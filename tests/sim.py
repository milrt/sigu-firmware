# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""One sigu-sim process, its paths, the key names and the opcodes."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# txlab.py is in sim/, because the fuzz seeds use it too.
# Import txlab after this module.
sys.path.append(str(ROOT / "sim"))
SIM = Path(os.environ.get("SIGU_SIM", ROOT / "sim/build/sigu-sim"))
WEB = os.environ.get("SIGU_SIM_WEB") == "1"

# The three keys, as the sim names them. Their role is what the screen shows above them.
LEFT, MIDDLE, RIGHT = "a", "s", "d"

# Opcodes (shared/bitcoin_service_defs.h), for the tests that call the SP as a malicious NS.
STATUS, GET_XPUB = 1001, 1002
TX_BEGIN, TX_OUTPUT, TX_INPUT, TX_CONFIRM, TX_POLL, TX_SIGN_INPUT = 1004, 1005, 1006, 1007, 1008, 1009
FILES_SET, FILES_POLL, FILES_RESULT = 1011, 1012, 1013
PROD_FIRST, PROD_LAST = STATUS, FILES_RESULT


class Sim:
    """One headless sigu-sim with a fresh wallet and its own card folder."""

    def __init__(self, card: Path, ps: Path | None = None, args: tuple[str, ...] = ()):
        # The log goes to a file. A full pipe would block the sim in the middle of a write.
        self.log = tempfile.TemporaryFile(mode="w+")
        if WEB:
            argv = ["node", str(ROOT / "sim/web/node_host.cjs"), str(ROOT / "sim/build-web")]
        else:
            # With `ps`, a second Sim on the same folder is the same device after a reboot.
            argv = [str(SIM), "--headless"] + (["--ps", str(ps)] if ps else ["--ephemeral"])
            argv += list(args)
        self.proc = subprocess.Popen(
            argv + ["--card", str(card)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.log,
            text=True,
        )

    def read_log(self) -> str:
        self.log.seek(0)
        return self.log.read()

    def cmd(self, line: str) -> str:
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        reply = self.proc.stdout.readline().strip()
        if not reply:
            raise RuntimeError(f"sim died on {line!r}: {self.read_log()}")
        return reply

    def ok(self, line: str) -> str:
        reply = self.cmd(line)
        if not reply.startswith("ok"):
            raise AssertionError(f"{line!r} -> {reply!r}")
        return reply[3:]

    def keys(self, *names: str) -> None:
        for name in names:
            self.ok(f"key {name}")

    def text(self) -> str:
        """The text on the panel, the drawn lines joined with ' | '."""
        return self.ok("text")

    def ipc(self, op: int, ins=(), outs=(), svc="p") -> tuple[int, list[bytes]]:
        """One psa_call from NS on TFM_BITCOIN (p) or TFM_BITCOIN_TEST (t).
        `ins` are bytes, `outs` are sizes. Returns the status and the outvecs."""
        vecs = ["i" + (v.hex() if v else "-") for v in ins] + [f"o{n}" for n in outs]
        reply = self.ok(f"ipc {svc} {op} " + " ".join(vecs)).split()
        return int(reply[0]), [b"" if h == "-" else bytes.fromhex(h) for h in reply[1:]]

    def close(self) -> str:
        self.proc.stdin.write("quit\n")
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        self.proc.stdout.close()
        log = self.read_log()
        self.log.close()
        return log
