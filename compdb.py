#!/usr/bin/env python3
"""Merge the build compile databases into one compile_commands.json for clangd.

It reads every compile_commands.json under app/build*/ and sim/build*/. A file built in more
than one image keeps its first entry: the SP, NS, the bootloaders, other images, then the sim,
and the newest build first within each. The script also links compile_commands.json and
.clangd into the west workspace, so files in external/ resolve too. Run it again after a
pristine build or after you add a source file.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
IMAGES = ["app/tfm", "app", "mcuboot", "mcuboot_s1_variant", "b0"]
LINKS = ["compile_commands.json", ".clangd"]


def rank(db):
    """Order key: the image (SP first, sim last), then the newest build first."""
    rel = db.parent.relative_to(REPO)
    if rel.parts[0] == "sim":
        r = len(IMAGES) + 1
    else:
        image = "/".join(rel.parts[2:])
        r = IMAGES.index(image) if image in IMAGES else len(IMAGES)
    return (r, -db.stat().st_mtime)


def find_dbs():
    dbs = []
    for db in [*REPO.glob("app/build*/**/compile_commands.json"),
               *REPO.glob("sim/build*/**/compile_commands.json")]:
        entries = json.loads(db.read_text())
        rel = db.parent.relative_to(REPO)
        if not entries or not Path(entries[0]["directory"]).is_dir():
            print(f"skip {rel} (empty, or built on another host)")
            continue
        dbs.append(db)
    return sorted(dbs, key=rank)


def merge():
    merged = {}
    for db in find_dbs():
        print(f"use {db.parent.relative_to(REPO)}")
        for e in json.loads(db.read_text()):
            merged.setdefault(str(Path(e["directory"], e["file"]).resolve()), e)
    return list(merged.values())


def link_into_workspace():
    for name in LINKS:
        link = REPO.parent / name
        if link.is_symlink():
            link.unlink()
        if link.exists():
            print(f"skip link {link} (a file is there)")
        else:
            link.symlink_to(Path(REPO.name, name))


def main():
    entries = merge()
    if not entries:
        sys.exit("nothing built yet: build the firmware or the sim first")
    out = REPO / "compile_commands.json"
    out.write_text(json.dumps(entries, indent=1))
    link_into_workspace()
    print(f"wrote {out} ({len(entries)} files)")


if __name__ == "__main__":
    main()
