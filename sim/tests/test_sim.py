# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""End-to-end tests for sigu-sim. They drive the panel with key presses.

Run them with the sim venv (sim/requirements.txt). They use txlab's test wallet and fixtures:

    sim/.venv/bin/python sim/tests/run.py

run.py runs them in parallel. `python -m unittest discover -s sim/tests -v` runs them one after
the other.

With SIGU_SIM_WEB=1 they run the WebAssembly build (sim/build-web) in node instead.
"""

import base64
import dataclasses
import hashlib
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIM = Path(os.environ.get("SIGU_SIM", ROOT / "sim/build/sigu-sim"))
WEB = os.environ.get("SIGU_SIM_WEB") == "1"
# nayuki's Python QR encoder, from the same west project as the C one the SP uses.
sys.path.append(str(ROOT.parent / "external/qrcodegen/python"))

import qrcodegen  # noqa: E402
import txlab  # noqa: E402
from btclib.psbt.psbt import Psbt  # noqa: E402
from btclib.tx.tx import Tx  # noqa: E402

# The three keys, as the sim names them. Their role is what the screen shows above them.
LEFT, MIDDLE, RIGHT = "a", "s", "d"

PSBT_IN_NON_WITNESS_UTXO = b"\x00"


def edit_prev_tx(b64: str, edit) -> str:
    """Return the PSBT with input 0's NON_WITNESS_UTXO replaced by edit(bytes), or removed if
    edit returns None. Every other record keeps its bytes and its place."""
    maps = txlab.split_maps(base64.b64decode(b64))
    records = []
    for key, value in maps[1]:
        if key == PSBT_IN_NON_WITNESS_UTXO:
            value = edit(value)
            if value is None:
                continue
        records.append((key, value))
    maps[1] = records
    return base64.b64encode(txlab.join_maps(maps)).decode()


def lower_prev_amount(b64: str, by: int) -> str:
    """The fee attack: the prev tx claims less for the output we spend. The txid stays."""
    vout = Psbt.b64decode(b64).tx.vin[0].prev_out.vout

    def edit(raw: bytes) -> bytes:
        tx = Tx.parse(raw)
        assert tx.serialize(include_witness=True, check_validity=False) == raw
        tx.vout[vout] = dataclasses.replace(tx.vout[vout], value=tx.vout[vout].value - by)
        return tx.serialize(include_witness=True, check_validity=False)

    return edit_prev_tx(b64, edit)

# The install images. The sim checks the headers and versions as the device does, but not the
# signatures, which are MCUboot's and b0's job.
S0_ADDR, S1_ADDR, NS_ADDR = 0x8000, 0x19000, 0x84000
SLOT1_SIZE = 624 * 1024
# The card files the Firmware screen reads: the build outputs, renamed.
APP_FILE, BOOT_S0_FILE, BOOT_S1_FILE = "sigu-app.bin", "sigu-mcuboot-s0.bin", "sigu-mcuboot-s1.bin"
IMAGE_F_ROM_FIXED = 0x100
FW_INFO_MAGIC = (0x281EE6DE, 0x8FCEBB4C, 0x00003602)
FW_INFO_VALID = 0x9102FFFF
# The TLV area: the info, then IMAGE_TLV_SHA256. The sim's MCUboot checks this hash where the
# device checks an ed25519 signature.
TLV_SIZE = 4 + 4 + 32
# MCUboot's magic for BOOT_MAX_ALIGN 16: the alignment, then 14 fixed bytes.
TRAILER_MAGIC = struct.pack("<H", 16) + bytes.fromhex("2de15d29410b8d77679c110f1f8a")

# What MCUboot (sim/mcuboot, the real loader) and our hooks log, as on the device console.
SWAP_TEST = "sigu: swap type 1 authorized"
SWAP_PERM = "sigu: swap type 2 authorized"
SWAP_BACK = "sigu: swap type 3 authorized"
DROPPED = "sigu: install dropped"
BACK_DROPPED = "sigu: swap back not to the app before the install, dropped"
CLOSED = "sigu: slot0 trailer not from an install, closing it"
NOT_VALID = "Image in the secondary slot is not valid!"
NSIB = "Starting swap using nsib algorithm."


def seal(img: bytearray, bad_hash=False) -> bytearray:
    """Writes the SHA-256 TLV over the header, the body and the protected TLVs, as imgtool does.
    With `bad_hash`, MCUboot refuses the image, as a bad signature on the device."""
    hashed = len(img) - TLV_SIZE
    digest = bytearray(hashlib.sha256(img[:hashed]).digest())
    if bad_hash:
        digest[0] ^= 0x01
    img[hashed:] = struct.pack("<HHBBH", 0x6907, TLV_SIZE, 0x10, 0, 32) + digest
    return img


def mcuboot_image(load_addr: int, version=(0, 0, 0), flags=IMAGE_F_ROM_FIXED, size=0x2000,
                  security: int | None = None, bad_hash=False) -> bytearray:
    """A signed image as imgtool lays it out: the header (struct image_header), a body that is
    not all 0xff, the protected TLVs and the TLVs, so the image ends with the file. sim/src/
    flash.c builds the running one the same way. NCS signs the app and both bootloaders with
    ROM_FIXED, so only the load address tells them apart."""
    img = bytearray(i % 251 for i in range(size))
    major, minor, rev = version
    # imgtool --security-counter: a protected TLV area (info, then SEC_CNT) after the body.
    prot = b"" if security is None else struct.pack("<HHBBHI", 0x6908, 12, 0x50, 0, 4, security)
    body = size - 0x800 - len(prot) - TLV_SIZE
    struct.pack_into("<IIHHIIBBHII", img, 0, 0x96F3B83D, load_addr, 0x800, len(prot), body, flags,
                     major, minor, rev, 0, 0)
    img[0x800 + body : 0x800 + body + len(prot)] = prot
    return seal(img, bad_hash)


def boot_image(load_addr: int, fw_version: int) -> bytes:
    """A bootloader image for one s0/s1 slot, with fw_info at 0xe00 as b0 reads it."""
    img = mcuboot_image(load_addr)
    struct.pack_into("<3I6I", img, 0xE00, *FW_INFO_MAGIC, 0x3C, len(img), fw_version, load_addr,
                     load_addr, FW_INFO_VALID)
    return bytes(seal(img))


PIN = "1234"
# BIP84's test vector wallet.
ABANDON = " ".join(["abandon"] * 11 + ["about"])
# Its master fingerprint and account key, m/84'/0'/0', as BIP84 publishes them (under the xpub
# version bytes).
ABANDON_FP = "73c5da0a"
ABANDON_XPUB = (
    "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZ"
    "XYVUhLv1VMrjPC7PW6V"
)

# BIP380's reference checksum, so the test does not trust the C code it checks.
DESC_INPUT_CHARSET = (
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"
    '"\\ '
)
DESC_CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def descsum_create(s: str) -> str:
    generator = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]

    def polymod(symbols):
        chk = 1
        for value in symbols:
            top = chk >> 35
            chk = (chk & 0x7FFFFFFFF) << 5 ^ value
            for i in range(5):
                chk ^= generator[i] if ((top >> i) & 1) else 0
        return chk

    symbols, groups = [], []
    for c in s:
        v = DESC_INPUT_CHARSET.index(c)
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    checksum = polymod(symbols + [0] * 8) ^ 1
    return s + "#" + "".join(DESC_CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))


def png_rgb(data: bytes) -> tuple[int, int, bytes]:
    """Width, height and the filtered RGB rows of a sim shot. The sim writes filter 0 only."""
    width, height = struct.unpack(">II", data[16:24])
    idat = b""
    pos = 8
    while pos < len(data):
        n, kind = struct.unpack(">I4s", data[pos : pos + 8])
        if kind == b"IDAT":
            idat += data[pos + 8 : pos + 8 + n]
        pos += 12 + n
    return width, height, zlib.decompress(idat)


# Opcodes (shared/bitcoin_service_defs.h), for the tests that call the SP as a malicious NS.
STATUS, GET_XPUB = 1001, 1002
TX_BEGIN, TX_OUTPUT, TX_INPUT, TX_CONFIRM, TX_POLL, TX_SIGN_INPUT = 1004, 1005, 1006, 1007, 1008, 1009
FILES_SET, FILES_POLL, FILES_RESULT = 1011, 1012, 1013
PROD_FIRST, PROD_LAST = STATUS, FILES_RESULT
CONFIG_UID = 0x10020010
FAILED_LINE = "firmware install failed"


def config_record(theme=0, seen=0, version=1) -> bytes:
    """The ITS config record: version, theme, fw_failed_seen."""
    return struct.pack("<BBB", version, theme, seen)


def config_path(ps: Path) -> Path:
    """The sim keeps each ITS UID as a file in the PS folder (sim/src/ps.c)."""
    return ps / f"{CONFIG_UID:016x}.its"


def read_config(ps: Path) -> bytes:
    return config_path(ps).read_bytes()[4:]  # after the u32 create flags


def write_config(ps: Path, record: bytes) -> None:
    ps.mkdir(parents=True, exist_ok=True)
    config_path(ps).write_bytes(struct.pack("<I", 0) + record)


def compact_size(n: int) -> bytes:
    return bytes([n]) if n < 0xFD else b"\xfd" + struct.pack("<H", n)


def prev_tx(amount: int, script: bytes) -> bytes:
    """A legacy-serialized tx with one made-up input that pays `amount` to `script`. The SP
    cannot see the chain, so any well-formed tx whose txid matches the outpoint counts."""
    tx = struct.pack("<IB", 2, 1) + b"\x11" * 32 + struct.pack("<IBI", 0, 0, 0xFFFFFFFF)
    tx += b"\x01" + struct.pack("<Q", amount) + compact_size(len(script)) + script
    return tx + struct.pack("<I", 0)


def stream_tx(sim: "Sim", dest: bytes, send=10000, fee=500, funds=50000, pause_ms=0) -> int:
    """BEGIN, a payment to `dest`, change, our input and CONFIRM, as NS sends them, with
    `pause_ms` after BEGIN. Returns the first status that is not 0, else 0."""
    w = txlab.wallet()
    ours = txlab.p2wpkh_script(txlab.pub_key(w, "m/84h/1h/0h/0/0"))
    change = txlab.p2wpkh_script(txlab.pub_key(w, "m/84h/1h/0h/1/0"))
    prev = prev_tx(funds, ours)
    txid = hashlib.sha256(hashlib.sha256(prev).digest()).digest()

    def out_rec(amount: int, script: bytes) -> bytes:
        return struct.pack("<QB", amount, len(script)) + script.ljust(34, b"\0")

    calls = [
        (TX_BEGIN, [struct.pack("<5I", 2, 0, 1, 2, 1)]),
        (TX_OUTPUT, [out_rec(send, dest), b""]),
        (TX_OUTPUT, [out_rec(funds - send - fee, change), b"m/84'/1'/0'/1/0\0"]),
        (TX_INPUT, [txid + struct.pack("<II", 0, 0xFFFFFFFD), b"m/84'/1'/0'/0/0\0", prev]),
        (TX_CONFIRM, []),
    ]
    for op, ins in calls:
        st, _ = sim.ipc(op, ins)
        if st:
            return st
        if op == TX_BEGIN and pause_ms:
            sim.ok(f"wait {pause_ms}")
    return 0


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
        """One psa_call from NS on TFM_BITCOIN (p) or TFM_BITCOIN_TEST (t). `ins` are bytes,
        `outs` are sizes. Returns the status and the outvecs."""
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


class SimTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.card = Path(self.tmp.name)
        self.sim = None

    def tearDown(self):
        if self.sim:
            self.sim.close()
        self.tmp.cleanup()

    def ps_dir(self) -> Path:
        """An empty PS folder, removed after the test."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return Path(tmp.name)

    def open_abandon(self, sim: Sim) -> Sim:
        """Stores and opens the BIP84 vector wallet, and waits for the status screen to poll it."""
        sim.ok(f"wallet setup {PIN} {ABANDON}")
        sim.ok(f"wallet open {PIN}")
        sim.ok("wait 1200")
        return sim

    def start(self) -> Sim:
        if self.sim:
            self.sim.close()
        self.sim = Sim(self.card)
        self.sim.ok("wait 200")
        return self.sim

    def open_test_wallet(self) -> Sim:
        sim = self.start()
        sim.ok(f"wallet setup {PIN} {txlab.MNEMONIC}")
        sim.ok(f"wallet open {PIN} {txlab.PASSPHRASE}")
        # The status screen polls the wallet once a second.
        sim.ok("wait 1200")
        return sim

    def review_card_psbt(self, b64: str) -> Sim:
        """Puts the PSBT on the card and opens it from the menu, up to the review."""
        (self.card / "test.psbt").write_text(b64 + "\n")
        sim = self.open_test_wallet()
        sim.keys(RIGHT, RIGHT, RIGHT)  # status -> menu -> Sign from card -> test.psbt
        sim.ok("wait 1000")  # NS polls for the job every 200 ms
        return sim

    def open_firmware(self) -> Sim:
        sim = self.open_test_wallet()
        sim.keys(RIGHT, *[MIDDLE] * 6, RIGHT)  # status -> menu -> Firmware
        return sim

    def stage(self, sim: Sim, *keys: str) -> None:
        """Presses `keys` (MIDDLE picks the next file), then install. NS writes slot1, and the
        panel shows it with OK armed."""
        sim.keys(*keys, RIGHT)
        sim.ok("wait 2000")  # the poll, the write to slot1, and 1 s before OK is armed

    def dump(self, sim: Sim, what: str) -> bytes:
        """Saves slot0 or slot1 and reads it. The card folder is the one host folder the web
        build can write. A new name each time: the web build's NODEFS keeps a deleted file."""
        self.dumps = getattr(self, "dumps", 0) + 1
        name = f"{what}-{self.dumps}.dump"
        sim.ok(f"{what} {'/sigu/card/' + name if WEB else self.card / name}")
        data = (self.card / name).read_bytes()
        (self.card / name).unlink()
        return data

    def slot1(self, sim: Sim) -> bytes:
        return self.dump(sim, "slot1")

    def install(self, sim: Sim, *keys: str) -> tuple[str, bytes]:
        """Stages the file, then OK on the confirm view. Returns the log and slot1 after NS is
        done."""
        self.stage(sim, *keys)
        sim.keys(RIGHT)
        sim.ok("wait 3000")  # the poll, the request, and the 2 s before the restart
        return sim.read_log(), self.slot1(sim)

    def assert_installed(self, log: str, slot1: bytes, image: bytes, what: str, permanent=False):
        """An app is a test (image_ok unset), so MCUboot swaps it back unless NS confirms it. A
        bootloader is permanent."""
        self.assertIn(f"install {what} written to slot1", log)
        self.assertIn("[SIM] install record: state 1", log)
        self.assertIn("install requested", log)
        self.assertIn("[SIM] reboot", log)
        self.assertEqual(slot1[: len(image)], image)
        self.assertEqual(slot1[-16:], TRAILER_MAGIC)
        self.assertEqual(slot1[-32], 0x01 if permanent else 0xFF)

    def assert_not_installed(self, log: str, slot1: bytes):
        self.assertNotIn("[SIM] install record", log)
        self.assertNotIn("[SIM] reboot", log)
        self.assertEqual(slot1[-16:], b"\xff" * 16)

    def mcuboot(self, sim: Sim) -> str:
        """What MCUboot does with the trailers and the install record on the next boot."""
        start = len(sim.read_log())
        sim.ok("mcuboot")
        return sim.read_log()[start:]

    def write_boot(self, version: int, s0=True, s1=True):
        if s0:
            (self.card / BOOT_S0_FILE).write_bytes(boot_image(S0_ADDR, version))
        if s1:
            (self.card / BOOT_S1_FILE).write_bytes(boot_image(S1_ADDR, version))

    def test_install_app_writes_slot1(self):
        # Any version installs. There is no downgrade check: the panel warns, and the user decides.
        for version in ((0, 2, 0), (0, 1, 0), (0, 0, 9)):
            with self.subTest(version=version):
                image = bytes(mcuboot_image(NS_ADDR, version))
                (self.card / APP_FILE).write_bytes(image)
                log, slot1 = self.install(self.open_firmware())
                self.assert_installed(log, slot1, image, "app " + ".".join(map(str, version)))

    def warn_band(self, sim: Sim) -> set:
        """The colors where the confirm view puts the downgrade warning."""
        width, _, raw = png_rgb(self.shot_bytes(sim, "confirm.png"))
        row = 1 + width * 3
        return {
            tuple(raw[y * row + 1 + x * 3 : y * row + 4 + x * 3])
            for y in range(150, 196)
            for x in range(12, 228)
        }

    def test_only_an_older_app_shows_a_warning(self):
        for version, warns in (((0, 0, 9), True), ((0, 2, 0), False)):
            with self.subTest(version=version):
                (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, version))
                sim = self.open_firmware()
                self.stage(sim)
                self.assertEqual(len(self.warn_band(sim)) > 1, warns)

    def test_mcuboot_swaps_what_the_panel_authorized(self):
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 2, 0)))
        sim = self.open_firmware()
        self.install(sim)
        self.assertIn(SWAP_TEST, self.mcuboot(sim))
        # Not confirmed: the next boot may swap the old app back, once.
        log = self.mcuboot(sim)
        self.assertIn(SWAP_BACK, log)
        self.assertIn("record 2 -> 0", log)
        self.assertNotIn("sigu:", self.mcuboot(sim))
        # The OK was used. The same bytes, requested again, need a new one.
        sim.ok("forge test")
        self.assertIn(DROPPED, self.mcuboot(sim))

    def test_cancel_on_the_confirm_view_installs_nothing(self):
        image = bytes(mcuboot_image(NS_ADDR, (0, 2, 0)))
        (self.card / APP_FILE).write_bytes(image)
        sim = self.open_firmware()
        self.stage(sim)
        sim.keys(LEFT)
        sim.ok("wait 1000")
        log, slot1 = sim.read_log(), self.slot1(sim)
        self.assertIn("install app 0.2.0 written to slot1", log)
        self.assertEqual(slot1[: len(image)], image)  # staged, but never requested
        self.assert_not_installed(log, slot1)

    def test_request_without_the_panel_is_dropped(self):
        # A broken NS writes a signed image to slot1 and requests it. No OK, no record.
        image = bytes(mcuboot_image(NS_ADDR, (0, 0, 9)))
        (self.card / APP_FILE).write_bytes(image)
        sim = self.open_firmware()
        self.stage(sim)
        sim.keys(LEFT)
        sim.ok("forge test")
        self.assertIn(DROPPED, self.mcuboot(sim))
        self.assertEqual(self.slot1(sim)[-16:], b"\x00" * 16)
        self.assertNotIn("sigu:", self.mcuboot(sim))

    def test_slot1_changed_after_ok_is_dropped(self):
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 2, 0)))
        sim = self.open_firmware()
        self.install(sim)
        sim.ok("forge byte 4096")  # in the body, after the panel hashed it
        self.assertIn(DROPPED, self.mcuboot(sim))

    def test_swap_back_to_another_image_is_dropped(self):
        # During the test boot, NS writes another signed image to slot1 and does not confirm.
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 2, 0)))
        sim = self.open_firmware()
        self.install(sim)
        self.assertIn(SWAP_TEST, self.mcuboot(sim))
        sim.ok("forge byte 4096")  # slot1 holds the old app now
        log = self.mcuboot(sim)
        self.assertIn(BACK_DROPPED, log)
        self.assertIn(CLOSED, log)
        self.assertNotIn("Starting swap", log)

    def test_forged_resume_during_the_test_is_closed(self):
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 2, 0)))
        sim = self.open_firmware()
        self.install(sim)
        self.assertIn("record 2 -> 3", self.mcuboot(sim))  # TESTING, before NS runs
        sim.ok("forge resume")
        log = self.mcuboot(sim)
        self.assertIn(CLOSED, log)
        self.assertNotIn("Starting swap", log)

    def test_unused_authorization_expires(self):
        # NS gets the OK but does not request on that boot. Later it may not use it.
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 2, 0)))
        sim = self.open_firmware()
        self.install(sim)
        sim.ok("forge clear")
        self.assertIn("record 1 -> 0", self.mcuboot(sim))
        sim.ok("forge test")
        self.assertIn(DROPPED, self.mcuboot(sim))

    def test_no_authorization_over_a_test(self):
        # The test app is confirmed, but MCUboot clears TESTING only on the next boot.
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 2, 0)))
        sim = self.open_firmware()
        self.install(sim)
        self.mcuboot(sim)
        sim.ok("boot confirm")
        sim.keys(LEFT)  # back to the list
        log, _ = self.install(sim)
        self.assertEqual(log.count("[SIM] install record: state 1"), 1)
        self.assertEqual(log.count("install requested"), 1)

    def reboot(self, ps: Path, first=False, args: tuple[str, ...] = ()) -> Sim:
        """Restarts the same device: PS and the flash stay, and MCUboot's checks run first. Opens
        the wallet and the Firmware screen."""
        if self.sim:
            self.sim.close()
        self.sim = Sim(self.card, ps, ("--reboot",) + args)
        sim = self.sim
        sim.ok("wait 200")
        if first:
            sim.ok(f"wallet setup {PIN} {txlab.MNEMONIC}")
        sim.ok(f"wallet open {PIN} {txlab.PASSPHRASE}")
        sim.ok("wait 1200")
        sim.keys(RIGHT, *[MIDDLE] * 6, RIGHT)  # status -> menu -> Firmware
        return sim

    def keep_app(self, ps: Path, security: int, first=False) -> str:
        """Installs an app with `security` and keeps it: the install, the test boot with the
        confirm, and the boot after. Returns the log of that last boot."""
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 2, 0), security=security))
        self.install(self.reboot(ps, first))
        sim = self.reboot(ps)
        self.assertIn(SWAP_TEST, sim.read_log())
        sim.ok("boot confirm")
        return self.reboot(ps).read_log()

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_floor_rises_when_the_app_is_kept(self):
        ps = self.ps_dir()
        self.assertIn("record 3 -> 0, min_security 2", self.keep_app(ps, 2, first=True))

    def test_floor_stays_on_a_swap_back(self):
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 2, 0), security=2))
        sim = self.open_firmware()
        self.install(sim)
        self.assertIn(SWAP_TEST, self.mcuboot(sim))
        log = self.mcuboot(sim)  # not confirmed
        self.assertIn(SWAP_BACK, log)
        self.assertIn("record 2 -> 0, min_security 0", log)

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_bad_signature_does_not_raise_the_floor(self):
        # The user says OK to an image whose signature MCUboot then refuses. Its counter was read
        # before the check, so it must not become the floor.
        ps = self.ps_dir()
        (self.card / APP_FILE).write_bytes(
            mcuboot_image(NS_ADDR, (0, 2, 0), security=0xFFFFFFFF, bad_hash=True))
        self.install(self.reboot(ps, first=True))
        log = self.reboot(ps).read_log()
        self.assertIn(NOT_VALID, log)
        self.assertIn("record 2 -> 0, min_security 0, pending 0", log)
        # Updates still work.
        self.assertIn("record 3 -> 0, min_security 1", self.keep_app(ps, 1))

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_torn_floor_write_keeps_the_copy_before(self):
        # Power fails while MCUboot writes the raised floor. The copy before it is TESTING, so
        # the next boot ends the test again and raises the floor again.
        ps = self.ps_dir()
        self.keep_app(ps, 2, first=True)
        self.sim.ok("forge tear")
        self.assertIn("record 3 -> 0, min_security 2", self.reboot(ps).read_log())

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_torn_approval_keeps_the_floor(self):
        # Power fails while the SP writes AUTHORIZED. The copy before it is IDLE with the floor.
        ps = self.ps_dir()
        self.keep_app(ps, 2, first=True)
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 3, 0), security=2))
        sim = self.reboot(ps)
        self.stage(sim)
        sim.keys(RIGHT)
        sim.ok("wait 3000")
        sim.ok("forge tear")
        log = self.reboot(ps).read_log()
        self.assertIn(DROPPED, log)
        self.assertNotIn("min_security 0", log)

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_floor_of_the_old_single_record_is_kept(self):
        ps = self.ps_dir()
        self.reboot(ps, first=True)
        self.sim.close()
        self.sim = None
        # The record before A/B copies, magic "SIGB", IDLE, floor 3, where copy A goes.
        flash = ps / "flash.bin"
        data = bytearray(flash.read_bytes())
        off = (628 + 624 + 68 + 68) * 1024  # after slot0, slot1, s0 and s1
        data[off : off + 16] = struct.pack("<IBBHII", 0x42474953, 0, 0xFF, 0xFFFF, 3, 0)
        flash.write_bytes(data)
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 3, 0), security=2))
        log, _ = self.install(self.reboot(ps))
        self.assertIn("install app 0.3.0 written to slot1", log)
        self.assertNotIn("[SIM] install record", log)  # below the old floor of 3

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_app_below_the_floor_is_blocked(self):
        ps = self.ps_dir()
        self.keep_app(ps, 2, first=True)
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 3, 0), security=1))
        log, slot1 = self.install(self.reboot(ps))
        self.assertIn("install app 0.3.0 written to slot1", log)  # NS staged it
        self.assertNotIn("[SIM] install record", log)  # the panel did not authorize it
        self.assertNotIn("install requested", log)

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_same_level_and_bootloaders_install_over_the_floor(self):
        ps = self.ps_dir()
        self.keep_app(ps, 2, first=True)
        # A reinstall, or another build of the same level.
        self.assertIn("record 3 -> 0, min_security 2", self.keep_app(ps, 2))
        # Bootloaders have no SEC_CNT: b0's counter covers them.
        self.write_boot(2)
        self.install(self.reboot(ps), MIDDLE)
        log = self.reboot(ps).read_log()
        self.assertIn(SWAP_PERM, log)
        self.assertIn(NSIB, log)

    def slot0(self, sim: Sim) -> bytes:
        return self.dump(sim, "slot0")

    def installed_app(self) -> tuple[Sim, bytes, bytes]:
        """An app with security counter 2 staged and authorized, and the boot not run yet.
        Returns the sim, the old app and the new one."""
        new = bytes(mcuboot_image(NS_ADDR, (0, 2, 0), security=2))
        (self.card / APP_FILE).write_bytes(new)
        sim = self.open_firmware()
        old = self.slot0(sim)[:0x2000]
        self.install(sim)
        # nonsecure/health acts once, 10 s after the start. Let that pass before slot0 holds a
        # test app, so it does not confirm one in the middle of a loop.
        sim.ok("wait 4000")
        return sim, old, new

    def cut_everywhere(self, sim: Sim, check, every=1) -> int:
        """Runs the next boot from the same flash, cut at each of its flash writes in turn
        (MCUboot's swap and status, our record), then boots again and calls check(log) on that
        boot. With `every`, only the first 50 writes and then every n-th one, plus the last.
        Returns how many writes the boot has."""
        sim.ok("snapshot")
        writes = int(re.search(r"mcuboot: (\d+) flash writes", self.mcuboot(sim)).group(1))
        cuts = sorted(set(range(1, min(50, writes) + 1)) | set(range(1, writes + 1, every)) |
                      {writes})
        for cut in cuts:
            with self.subTest(cut=cut):
                sim.ok("restore")
                self.assertIn(f"power cut at flash write {cut}", self.mcuboot_cut(sim, cut))
                log = self.mcuboot(sim)
                self.assertIn("Jumping to the first image slot", log)
                check(log)
        return writes

    def floor_after_keeping(self, sim: Sim, log: str) -> int:
        """Keeps whatever runs (confirm, boot), and returns the floor the logs show."""
        sim.ok("boot confirm")
        floors = re.findall(r"min_security (\d+)", log + self.mcuboot(sim))
        return int(floors[-1]) if floors else 0

    def test_power_cut_in_the_install_boot(self):
        # Every time the device boots an intact app, the old one or the new one, and the floor
        # matches it. A cut before the swap starts loses the install, safely.
        sim, old, new = self.installed_app()
        outcomes = set()

        def check(log):
            slot0 = self.slot0(sim)
            kept_new = slot0[: len(new)] == new
            self.assertTrue(kept_new or slot0[: len(old)] == old)
            self.assertEqual(self.floor_after_keeping(sim, log), 2 if kept_new else 0)
            outcomes.add(kept_new)

        self.assertGreater(self.cut_everywhere(sim, check), 100)
        self.assertEqual(outcomes, {True, False})

    def test_power_cut_in_the_swap_back(self):
        # The new app was not confirmed, so this boot swaps the old one back. It must end with
        # the old app, and the floor must not rise.
        sim, old, _ = self.installed_app()
        self.assertIn(SWAP_TEST, self.mcuboot(sim))

        def check(log):
            self.assertEqual(self.slot0(sim)[: len(old)], old)
            self.assertEqual(self.floor_after_keeping(sim, log), 0)

        self.assertGreater(self.cut_everywhere(sim, check), 100)

    def test_power_cut_in_the_floor_raise(self):
        # The new app was confirmed, so this boot raises the floor. A cut must not lose it.
        sim, _, new = self.installed_app()
        self.assertIn(SWAP_TEST, self.mcuboot(sim))
        sim.ok("boot confirm")

        def check(log):
            self.assertEqual(self.slot0(sim)[: len(new)], new)
            self.assertEqual(self.floor_after_keeping(sim, log), 2)

        self.cut_everywhere(sim, check)

    def test_power_cut_in_a_bootloader_install(self):
        # MCUboot copies the bootloader to the inactive s1. A cut anywhere must leave the app in
        # slot0 bootable and the floor alone: b0 checks s1 itself before it starts it.
        self.write_boot(2)
        sim = self.open_firmware()
        old = self.slot0(sim)[:0x2000]
        self.install(sim, MIDDLE)
        sim.ok("wait 4000")  # past nonsecure/health, as in installed_app()

        def check(log):
            self.assertEqual(self.slot0(sim)[: len(old)], old)
            self.assertEqual(self.floor_after_keeping(sim, log), 0)

        self.assertGreater(self.cut_everywhere(sim, check, every=40), 10)

    def mcuboot_cut(self, sim: Sim, cut: int) -> str:
        start = len(sim.read_log())
        sim.ok(f"mcuboot cut {cut}")
        return sim.read_log()[start:]

    def test_forged_revert_is_closed(self):
        # NS clears image_ok in slot0's trailer, so MCUboot would swap slot1 back in.
        sim = self.start()
        sim.ok("boot unconfirmed")
        log = self.mcuboot(sim)
        self.assertIn(CLOSED, log)
        self.assertNotIn("Starting swap", log)

    def test_install_bootloader_to_inactive_slot(self):
        self.write_boot(2)
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 2, 0)))
        # App is first, Boot second. s0 runs, so the s1 file is written.
        sim = self.open_firmware()
        log, slot1 = self.install(sim, MIDDLE)
        self.assert_installed(log, slot1, boot_image(S1_ADDR, 2), "boot v2", permanent=True)
        log = self.mcuboot(sim)
        self.assertIn(SWAP_PERM, log)
        self.assertIn(NSIB, log)

    def test_install_bootloader_not_above_running_is_blocked(self):
        self.write_boot(1)  # the sim runs v1
        log, slot1 = self.install(self.open_firmware())
        self.assert_not_installed(log, slot1)

    def test_install_bootloader_needs_both_files(self):
        self.write_boot(2, s0=False)
        log, slot1 = self.install(self.open_firmware())
        self.assert_not_installed(log, slot1)

    def test_install_bootloader_linked_for_wrong_slot_is_invalid(self):
        self.write_boot(2)
        (self.card / BOOT_S1_FILE).write_bytes(boot_image(S0_ADDR, 2))
        log, slot1 = self.install(self.open_firmware())
        self.assert_not_installed(log, slot1)

    def test_install_truncated_app_is_invalid(self):
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 2, 0))[:-100])
        log, slot1 = self.install(self.open_firmware())
        self.assert_not_installed(log, slot1)

    def test_install_size_that_wraps_is_invalid(self):
        # hdr_size + img_size wraps to 64, where this 104-byte file has its TLV info. Without
        # the check, NS, the SP and the hook all take it as a whole image.
        img = bytearray(104)
        struct.pack_into("<IIHHIIBBHII", img, 0, 0x96F3B83D, NS_ADDR, 0x8000, 0, 0xFFFF8040,
                         IMAGE_F_ROM_FIXED, 9, 9, 9, 0, 0)
        struct.pack_into("<HH", img, 64, 0x6907, 40)
        (self.card / APP_FILE).write_bytes(img)
        sim = self.open_firmware()
        self.assertIn("(invalid)", sim.text())
        log, slot1 = self.install(sim)
        self.assert_not_installed(log, slot1)

    def test_install_needs_the_wallet_open(self):
        image = bytes(mcuboot_image(NS_ADDR, (0, 2, 0)))
        (self.card / APP_FILE).write_bytes(image)
        sim = self.start()
        sim.ok(f"wallet setup {PIN} {ABANDON}")  # stored, never opened: locked
        sim.ok("wait 1200")
        sim.keys(MIDDLE, *[MIDDLE] * 6, RIGHT)  # locked status -> menu -> Firmware
        self.assertIn("unlock the wallet first", sim.text())
        log, slot1 = self.install(sim)
        self.assertNotIn("written to slot1", log)
        self.assert_not_installed(log, slot1)

    def test_install_refuses_a_changed_file(self):
        # The panel showed the hash of this file. Other bytes after the scan are not installed.
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 2, 0)))
        sim = self.open_firmware()
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 3, 0)))
        log, slot1 = self.install(sim)
        self.assertIn("the install file changed since the scan", log)
        self.assert_not_installed(log, slot1)

    def report_again(self, sim: Sim):
        """NS reads the firmware state when it reports, at start and on a card change."""
        sim.ok("card out")
        sim.ok("wait 1200")
        sim.ok("card in")
        sim.ok("wait 1200")

    def test_failed_install_is_reported(self):
        sim = self.start()
        sim.ok("boot failed")  # MCUboot swapped a failed app back
        self.report_again(sim)
        self.assertIn(FAILED_LINE, sim.text())

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_failed_install_is_shown_once(self):
        ps = self.ps_dir()

        # As on the device, the trailer state is there before NS starts.
        def boot(failed: bool) -> str:
            sim = Sim(self.card, ps, ("--boot-failed",) if failed else ())
            sim.ok("wait 2000")  # NS reports, then the 1 s status repaint
            text = sim.text()
            sim.close()
            return text

        self.assertIn(FAILED_LINE, boot(True))  # first boot after it
        self.assertEqual(read_config(ps), config_record(seen=1))
        self.assertNotIn(FAILED_LINE, boot(True))  # the reboot after
        self.assertNotIn(FAILED_LINE, boot(False))  # a good install since
        self.assertEqual(read_config(ps), config_record(seen=0))
        self.assertIn(FAILED_LINE, boot(True))  # the next rollback shows

    def settings_boot(self, ps: Path, row: int, *keys: str) -> str:
        """One boot on `ps` that opens Settings, goes down `row` rows and presses `keys`. Returns
        the screen text on that row."""
        sim = Sim(self.card, ps)
        sim.ok("wait 200")
        sim.keys(*[MIDDLE] * 6, RIGHT)  # status -> menu -> Settings
        sim.keys(*[MIDDLE] * row)
        text = sim.text()
        sim.keys(*keys)
        sim.ok("wait 200")
        sim.close()
        return text

    THEME_ROW = 0
    THEME_NEXT_SAVE = (RIGHT, RIGHT, LEFT, MIDDLE, RIGHT)  # edit, +, done, to Save, save

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_theme_is_kept_across_boots(self):
        ps = self.ps_dir()

        self.assertIn("Theme | 1", self.settings_boot(ps, self.THEME_ROW, *self.THEME_NEXT_SAVE))
        self.assertEqual(read_config(ps), config_record(theme=1))
        # The next boot starts from the record. + shows a theme, and DEL saves nothing.
        before = config_path(ps).stat().st_mtime_ns
        self.assertIn("Theme | 2", self.settings_boot(ps, self.THEME_ROW, RIGHT, RIGHT, LEFT, LEFT))
        self.assertEqual(config_path(ps).stat().st_mtime_ns, before)

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_theme_ok_without_a_change_writes_nothing(self):
        ps = self.ps_dir()
        self.settings_boot(ps, self.THEME_ROW, MIDDLE, RIGHT)  # Save with the theme in use
        self.assertFalse(config_path(ps).exists())

    def pixel(self, sim: Sim, x: int, y: int) -> tuple[int, int, int]:
        """One panel pixel from a shot."""
        width, _, raw = png_rgb(self.shot_bytes(sim, "shot.png"))
        off = y * (1 + width * 3) + 1 + x * 3
        return tuple(raw[off : off + 3])

    def bg_pixel(self, sim: Sim) -> tuple[int, int, int]:
        """The status screen's background, left of the center."""
        return self.pixel(sim, 2, 120)

    BLACK_BG = (0x00, 0x00, 0x00)  # the default theme's background 0x000000
    LIGHT_BG = (0xF7, 0xFB, 0xFF)  # theme 1's background 0xF6F8FA, after RGB565

    def first_frame(self, record: bytes) -> tuple[int, int, int]:
        """Boots on a PS folder with `record` as the config and returns the first background."""
        ps = self.ps_dir()
        write_config(ps, record)
        self.sim = Sim(self.card, ps)
        self.sim.ok("wait 100")  # less than the 1 s status repaint
        return self.bg_pixel(self.sim)

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_stored_theme_is_the_first_frame(self):
        self.assertEqual(self.first_frame(config_record(theme=1)), self.LIGHT_BG)

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_bad_config_record_gives_the_defaults(self):
        bad = [
            config_record(theme=1)[:-1],  # too short
            config_record(theme=1) + b"\0",  # too long
            config_record(theme=1, version=2),
            config_record(theme=99),
            config_record(theme=1, seen=2),  # a bad seen byte drops the good theme too
        ]
        for record in bad:
            with self.subTest(record=record.hex()):
                self.assertEqual(self.first_frame(record), self.BLACK_BG)
                self.sim.close()
                self.sim = None

    def test_no_failed_install_by_default(self):
        sim = self.start()
        self.report_again(sim)
        self.assertNotIn(FAILED_LINE, sim.text())

    def test_new_app_is_confirmed(self):
        sim = self.start()
        sim.ok("boot unconfirmed")  # as after MCUboot swapped a new app in
        sim.ok("wait 11500")  # 10 rounds of the health thread, one a second
        log = sim.read_log()
        self.assertIn("[SIM] watchdog fed", log)
        self.assertIn("install confirmed", log)
        self.assertIn("[SIM] confirmed", log)

    def test_install_confirming_is_shown(self):
        # A new app runs as a test until health.c confirms it. NS reports both changes.
        sim = self.start()
        sim.ok("boot unconfirmed")
        sim.ok("wait 2000")  # NS checks the firmware state once a second
        self.assertIn("install confirming", sim.read_log())
        sim.ok("wait 11000")
        log = sim.read_log()
        self.assertIn("install confirmed", log)
        self.assertLess(log.index("install confirming"), log.index("[SIM] confirmed"))

    def test_install_waits_for_the_confirm(self):
        # slot1 holds the app MCUboot would swap back to, so NS must not write it yet.
        (self.card / APP_FILE).write_bytes(mcuboot_image(NS_ADDR, (0, 2, 0)))
        sim = self.start()
        sim.ok("boot unconfirmed")
        sim.ok(f"wallet setup {PIN} {txlab.MNEMONIC}")
        sim.ok(f"wallet open {PIN} {txlab.PASSPHRASE}")
        sim.ok("wait 1200")
        sim.keys(RIGHT, *[MIDDLE] * 6, RIGHT)  # status -> menu -> Firmware
        log, slot1 = self.install(sim)
        self.assertIn("the running app is not confirmed yet", log)
        self.assertNotIn("install confirmed", log)
        self.assert_not_installed(log, slot1)

    def test_selftests_pass(self):
        sim = self.start()
        sim.ok("ns selftest")
        log = sim.close()
        self.sim = None
        self.assertIn("Tests Failed:    0", log)

    def export_wallet(self, *before: str) -> Sim:
        """Opens the BIP84 vector wallet, runs `before`, and saves it from the Export screen."""
        sim = self.open_abandon(self.start())
        for line in before:
            sim.ok(line)
        sim.keys(RIGHT, MIDDLE, MIDDLE, RIGHT)  # status -> menu -> Export wallet
        sim.keys(RIGHT)  # save
        sim.ok("wait 1000")  # NS polls for the job every 200 ms
        return sim

    def test_export_watch_only(self):
        sim = self.export_wallet()
        desc = descsum_create(f"wpkh([{ABANDON_FP}/84h/0h/0h]{ABANDON_XPUB}/<0;1>/*)")
        self.assertEqual((self.card / f"wallet-{ABANDON_FP}.txt").read_text(), desc + "\n")
        self.assertIn(f"wallet saved to /SD:/wallet-{ABANDON_FP}.txt", sim.read_log())

    def test_export_without_card(self):
        sim = self.export_wallet("card out", "wait 1200")
        self.assertFalse((self.card / f"wallet-{ABANDON_FP}.txt").exists())
        self.assertIn("wallet export failed: 1", sim.read_log())

    def shot_bytes(self, sim: Sim, name: str) -> bytes:
        shot = self.card / name
        sim.ok(f"shot {'/sigu/card/' + name if WEB else shot}")
        return shot.read_bytes()

    def test_export_qr(self):
        sim = self.open_abandon(self.start())
        sim.keys(RIGHT, MIDDLE, MIDDLE, RIGHT)  # status -> menu -> Export wallet
        sim.ok("wait 100")
        info = self.shot_bytes(sim, "export.png")
        sim.keys(MIDDLE)  # qr
        sim.ok("wait 100")
        desc = descsum_create(f"wpkh([{ABANDON_FP}/84h/0h/0h]{ABANDON_XPUB}/<0;1>/*)")
        want = qrcodegen.QrCode.encode_segments(
            [qrcodegen.QrSegment.make_bytes(desc.encode())], qrcodegen.QrCode.Ecc.LOW, 1, 7)
        self.assert_qr(self.shot_bytes(sim, "qr.png"), want, 45, 4)

        sim.keys(LEFT)  # any key goes back to the info, and does not leave
        sim.ok("wait 100")
        self.assertEqual(self.shot_bytes(sim, "export2.png"), info)

    # The panel shows `want` full screen, black on white, centered, with a light quiet zone.
    def assert_qr(self, png: bytes, want: "qrcodegen.QrCode", size: int, scale: int):
        width, height, raw = png_rgb(png)
        self.assertEqual((want.get_size(), width // (want.get_size() + 8)), (size, scale))
        x0 = (width - size * scale) // 2
        y0 = (height - size * scale) // 2

        def dark(x: int, y: int) -> bool:
            off = y * (1 + width * 3) + 1 + x * 3
            px = tuple(raw[off : off + 3])
            self.assertIn(px, ((0, 0, 0), (0xFF, 0xFF, 0xFF)))
            return px == (0, 0, 0)

        got = [[dark(x0 + c * scale + scale // 2, y0 + r * scale + scale // 2)
                for c in range(size)] for r in range(size)]
        self.assertEqual(got, [[want.get_module(c, r) for c in range(size)] for r in range(size)])
        # The quiet zone is light all around.
        self.assertFalse(any(dark(x, y) for y in range(height) for x in range(width)
                             if not (x0 <= x < x0 + size * scale and y0 <= y < y0 + size * scale)))

    def test_receive_screen(self):
        sim = self.open_abandon(self.start())
        sim.keys(RIGHT, MIDDLE, RIGHT)  # status -> menu -> Receive
        sim.ok("wait 100")
        first = self.shot_bytes(sim, "receive0.png")
        sim.keys(MIDDLE)  # next
        sim.ok("wait 100")
        # BIP84 publishes the second receive address too. The screen groups it in 4s.
        self.assertIn("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
                      sim.text().replace(" | ", "").replace(" ", ""))
        second = self.shot_bytes(sim, "receive1.png")
        self.assertNotEqual(first, second)
        sim.keys(LEFT)  # back to the menu
        sim.ok("wait 100")
        self.assertNotEqual(self.shot_bytes(sim, "menu.png"), second)

    def test_receive_qr(self):
        sim = self.open_abandon(self.start())
        sim.keys(RIGHT, MIDDLE, RIGHT)  # status -> menu -> Receive
        sim.keys(MIDDLE)  # next, index 1
        sim.ok("wait 100")
        info = self.shot_bytes(sim, "receive1.png")
        sim.keys(RIGHT)  # qr
        sim.ok("wait 100")
        # BIP84's second receive address, in uppercase for alphanumeric mode.
        want = qrcodegen.QrCode.encode_segments(
            [qrcodegen.QrSegment.make_alphanumeric("BC1QNJG0JD8228AQ7EGYZACY8CYS3KNF9XVRERKF9G")],
            qrcodegen.QrCode.Ecc.LOW, 1, 2)
        self.assert_qr(self.shot_bytes(sim, "receive-qr.png"), want, 25, 7)

        sim.keys(MIDDLE)  # any key goes back to the same address, and does not step
        sim.ok("wait 100")
        self.assertEqual(self.shot_bytes(sim, "receive1b.png"), info)

    def open_reset(self, sim: Sim, *keys: str) -> None:
        """From the status screen with a wallet open, presses `keys` on the Factory reset list."""
        sim.keys(RIGHT, *[MIDDLE] * 7, RIGHT)  # status -> menu -> Factory reset
        sim.keys(*keys)

    def enter_pin(self, sim: Sim, pin: str) -> None:
        """Types `pin` on the panel PIN entry. NEXT puts 0 in the slot and counts up, OK adds."""
        for d in pin:
            sim.keys(*[MIDDLE] * (int(d) + 1), RIGHT)
        sim.keys(RIGHT)  # done

    def wipe_config(self, *keys: str) -> tuple[Sim, Path]:
        """Opens the test wallet on a PS folder with theme 1 stored, then presses
        `keys` on the reset list. NS reports no failed install, so the seen bit stays 0."""
        ps = self.ps_dir()
        write_config(ps, config_record(theme=1))
        self.sim = Sim(self.card, ps)
        self.sim.ok("wait 200")
        self.open_abandon(self.sim)
        self.open_reset(self.sim, *keys)
        self.sim.ok("wait 200")
        return self.sim, ps

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_wipe_config_resets_the_theme(self):
        sim, ps = self.wipe_config(RIGHT, RIGHT)  # Wipe configuration -> wipe
        self.assertFalse(config_path(ps).exists())
        self.assertIn("configuration wiped", sim.text())
        sim.keys(RIGHT, LEFT)  # ok -> menu, back -> status
        sim.ok("wait 100")
        self.assertEqual(self.bg_pixel(sim), self.BLACK_BG)  # live, without a restart
        self.assertNotIn("[SIM] reboot", sim.read_log())
        self.assertIn("state=3", sim.ok("ns status"))  # the wallet is not touched

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_wipe_config_back_keeps_the_record(self):
        sim, ps = self.wipe_config(RIGHT, LEFT)  # Wipe configuration -> back
        self.assertEqual(read_config(ps), config_record(theme=1))

    def test_wipe_wallet(self):
        sim = self.open_abandon(self.start())
        self.open_reset(sim, MIDDLE, RIGHT, RIGHT)  # Wipe wallet -> wipe
        self.enter_pin(sim, PIN)
        sim.ok("wait 200")  # the wipe runs one tick after "wiping..."
        self.assertIn("state=0", sim.ok("ns status"))
        self.assertTrue(sim.cmd(f"wallet open {PIN}").startswith("err"))

    def test_wipe_wallet_without_stored_wallet(self):
        sim = self.start()
        sim.ok(f"wallet temp {ABANDON}")
        sim.ok("wait 1200")
        sim.keys(RIGHT, *[MIDDLE] * 7)  # status -> menu, on Factory reset
        sim.ok("wait 100")
        menu = self.shot_bytes(sim, "menu.png")
        sim.keys(RIGHT, MIDDLE, RIGHT)  # Factory reset -> Wipe wallet: "no stored wallet"
        sim.ok("wait 100")
        self.assertNotEqual(self.shot_bytes(sim, "msg.png"), menu)
        sim.keys(RIGHT)  # ok goes back to the menu. A PIN would be asked on the confirm page.
        sim.ok("wait 100")
        self.assertEqual(self.shot_bytes(sim, "back.png"), menu)
        self.assertIn("state=3", sim.ok("ns status"))  # the temporary wallet stays open

    def test_wipe_wallet_wrong_pin(self):
        sim = self.open_abandon(self.start())
        self.open_reset(sim, MIDDLE, RIGHT, RIGHT)
        self.enter_pin(sim, "9999")
        sim.ok("wait 200")
        self.assertIn("state=3", sim.ok("ns status"))  # still open
        # The screen asks again, and the record is still there for the right PIN.
        self.enter_pin(sim, PIN)
        sim.ok("wait 200")
        self.assertIn("state=0", sim.ok("ns status"))

    @unittest.skipIf(WEB, "the web build has one fixed PS folder")
    def test_unreadable_wallet_is_kept_until_wiped(self):
        ps = self.ps_dir()
        record = ps / "0000000010010010.ps"  # key_storage_uids_production
        blob = struct.pack("<I", 0) + struct.pack("<I", 2) + bytes(range(96))  # flags, format 2
        record.write_bytes(blob)
        sim = self.sim = Sim(self.card, ps)
        sim.ok("wait 1200")
        status = sim.ok("ns status")
        self.assertIn("state=4", status)
        self.assertTrue(sim.cmd(f"wallet setup {PIN} {ABANDON}").startswith("err"))
        self.assertEqual(record.read_bytes(), blob)

        # OK opens the menu, not setup. The wipe asks no PIN.
        self.open_reset(sim, MIDDLE, RIGHT, RIGHT)  # Wipe wallet -> wipe
        sim.ok("wait 200")  # the wipe runs one tick after "wiping..."
        self.assertFalse(record.exists())
        self.assertIn("state=0", sim.ok("ns status"))
        sim.ok(f"wallet setup {PIN} {ABANDON}")

    def test_wrong_pin_costs_a_try(self):
        sim = self.start()
        sim.ok(f"wallet setup {PIN} {ABANDON}")
        self.assertTrue(sim.cmd("wallet open 9999").startswith("err"))
        self.assertIn("attempts=9", sim.ok("ns status"))

    LOCK_TICKS = 15000  # 5 min of 20 ms ticks, display.c

    def test_idle_closes_wallet(self):
        sim = self.open_test_wallet()
        sim.ok(f"ticks {self.LOCK_TICKS + 2}")
        self.assertIn("state=1", sim.ok("ns status"))

    def test_key_restarts_idle_time(self):
        sim = self.open_test_wallet()
        sim.ok(f"ticks {self.LOCK_TICKS - 1000}")
        sim.keys(MIDDLE)  # status has no action on next while open
        sim.ok(f"ticks {self.LOCK_TICKS - 1000}")
        self.assertIn("state=3", sim.ok("ns status"))

    def test_idle_closes_temp_wallet(self):
        sim = self.start()
        sim.ok(f"wallet temp {ABANDON}")
        sim.ok("wait 1200")
        sim.ok(f"ticks {self.LOCK_TICKS + 2}")
        self.assertIn("state=0", sim.ok("ns status"))

    def test_menu_close_wallet(self):
        sim = self.open_test_wallet()
        sim.ok("wait 100")
        status = self.shot_bytes(sim, "open.png")
        sim.keys(RIGHT, *[MIDDLE] * 4, RIGHT)  # status -> menu -> Close wallet
        self.assertIn("state=1", sim.ok("ns status"))
        sim.ok("wait 1200")  # the status screen polls the state once a second
        self.assertNotEqual(self.shot_bytes(sim, "locked.png"), status)

    def test_busy_ns_does_not_stretch_idle_time(self):
        # Each call keeps the SP thread 200 ms (`ipc cost`), as a call that derives keys may on
        # the device. The idle time must follow the clock, not the ticks the SP got to handle.
        sim = self.open_test_wallet()
        sim.ok("ns freeze")  # the test is NS
        # Up to 10 s before the lock. The tick thread runs during a burst too (a slow build
        # adds hundreds of ticks), so the second burst fills up to what the SP counted. No key
        # was pressed, so every tick since the start is idle time.
        sim.ok(f"ticks {self.LOCK_TICKS - 2000}")
        sim.ok(f"ticks {self.LOCK_TICKS - 500 - int(sim.ok('tickcount'))}")
        self.assertIn("state=3", sim.ok("ns status"))
        sim.ok("ipc cost 200")
        end = time.monotonic() + 15
        while time.monotonic() < end:
            sim.ipc(GET_XPUB, [b"m/84'/0'/0'/0/0\0"], [113])
        sim.ok("ipc cost 0")
        self.assertIn("state=1", sim.ok("ns status"))

    def test_ns_cannot_close_the_wallet(self):
        # A temporary wallet is gone once closed. Only the panel closes the user's wallet.
        sim = self.start()
        sim.ok(f"wallet temp {ABANDON}")
        sim.ok("wait 1200")
        before = sim.ok("ns status")
        for op in range(PROD_FIRST, PROD_LAST + 1):  # every production opcode, without args
            sim.ipc(op)
        sim.ok("wait 1200")
        self.assertEqual(sim.ok("ns status"), before)

    MERCHANT_SCRIPT = b"\x00\x14" + bytes(range(101, 121))
    ATTACKER_SCRIPT = b"\x00\x14" + bytes(range(1, 21))

    def review_from_ns(self) -> Sim:
        """NS streams a payment to the merchant. The user reads it up to the total page and OK
        is armed."""
        sim = self.open_test_wallet()
        sim.ok("ns freeze")  # the test is NS
        self.assertEqual(stream_tx(sim, self.MERCHANT_SCRIPT), 0)
        sim.ok("wait 450")  # the status screen polls for a tx every 200 ms
        self.assertTrue(sim.text().startswith("Review"))
        sim.keys(MIDDLE)
        sim.ok("wait 1200")
        return sim

    def sign_first_input(self, sim: Sim) -> int:
        st, _ = sim.ipc(TX_SIGN_INPUT, [struct.pack("<I", 0), b"m/84'/1'/0'/0/0\0"], [72, 33])
        return st

    def test_swap_under_review_ends_it(self):
        # The same amounts to another address. A review that restarted on it would look the
        # same on the total page, and the same keys would sign it.
        # No tick between the calls, as from a fast NS. A slow one is the next test.
        sim = self.review_from_ns()
        sim.ok("tick hold")
        self.assertEqual(stream_tx(sim, self.ATTACKER_SCRIPT), 0)
        sim.ok("tick go")
        sim.ok("wait 450")
        self.assertFalse(sim.text().startswith("Review"))
        sim.keys(MIDDLE)
        sim.ok("wait 1200")
        sim.keys(RIGHT)
        self.assertNotEqual(self.sign_first_input(sim), 0)

    def test_slow_swap_under_review_ends_it(self):
        # A pause after BEGIN: the review sees no tx_id and must not come back for the next one.
        sim = self.review_from_ns()
        self.assertNotEqual(stream_tx(sim, self.ATTACKER_SCRIPT, pause_ms=450), 0)
        self.assertFalse(sim.text().startswith("Review"))
        sim.keys(RIGHT)
        self.assertNotEqual(self.sign_first_input(sim), 0)

    def test_idle_on_review_signs_nothing(self):
        sim = self.review_card_psbt(txlab.EXAMPLE_PSBT)
        sim.ok(f"ticks {self.LOCK_TICKS + 2}")
        self.assertIn("state=1", sim.ok("ns status"))
        sim.ok("wait 1500")
        self.assertFalse((self.card / "test-signed.psbt").exists())

    def test_card_sign_matches_device(self):
        sim = self.review_card_psbt(txlab.EXAMPLE_PSBT)
        sim.keys(MIDDLE)  # the total page, the only page where "sign" approves
        sim.ok("wait 1200")  # ARM_TICKS
        sim.keys(RIGHT)
        sim.ok("wait 1500")

        signed = (self.card / "test-signed.psbt").read_text()
        self.assertEqual(signed, txlab.EXAMPLE_SIGNED_PSBT)
        self.assertTrue(sim.text().startswith("SD card | signed |"))
        self.assertEqual(signed, txlab.sign_raw(txlab.wallet(), txlab.EXAMPLE_PSBT))

    def test_card_sign_pays_p2pkh(self):
        # A legacy destination renders as base58 and can be approved.
        w = txlab.wallet()
        b64 = txlab.build_psbt(
            w,
            inputs=[txlab.Input(txlab.PREV_TX, 1, "m/84h/1h/0h/0/0")],
            outputs=[
                txlab.Output("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", 5000),
                txlab.Output("m/84h/1h/0h/1/0", 13000),
            ],
        ).b64encode()
        sim = self.review_card_psbt(b64)
        sim.keys(MIDDLE)
        sim.ok("wait 1200")
        sim.keys(RIGHT)
        sim.ok("wait 1500")

        self.assertEqual((self.card / "test-signed.psbt").read_text(), txlab.sign_raw(w, b64))

    def test_reinsert_reads_new_files(self):
        # The card is read when it goes in. A file added later needs the card out and in.
        sim = self.open_test_wallet()
        (self.card / "test.psbt").write_text(txlab.EXAMPLE_PSBT + "\n")
        sim.ok("card out")
        sim.ok("wait 1200")  # NS checks the card once a second
        sim.ok("card in")
        sim.ok("wait 1200")
        sim.keys(RIGHT, RIGHT, RIGHT)  # status -> menu -> Sign from card -> test.psbt
        sim.ok("wait 1000")
        sim.keys(MIDDLE)
        sim.ok("wait 1200")
        sim.keys(RIGHT)
        sim.ok("wait 1500")
        self.assertEqual((self.card / "test-signed.psbt").read_text(), txlab.EXAMPLE_SIGNED_PSBT)

    def test_card_ok_without_a_signature_is_not_signed(self):
        # NS takes the sign job and ends it with OK at once: no tx, no review, no signature.
        sim = self.open_test_wallet()
        sim.ok("ns freeze")  # the test is NS
        sim.ipc(FILES_SET, [b"ok.psbt".ljust(32, b"\0"), struct.pack("<I", 1), struct.pack("<IB", 0, 0)])
        sim.keys(RIGHT, RIGHT, RIGHT)  # status -> menu -> Sign from card -> ok.psbt
        self.assertEqual(sim.ipc(FILES_POLL, [], [32, 4])[0], 0)
        self.assertEqual(sim.ipc(FILES_RESULT, [struct.pack("<I", 0)])[0], 0)  # BITCOIN_FILES_OK
        sim.ok("wait 300")
        self.assertTrue(sim.text().startswith("SD card | not signed |"))

    def test_ok_before_arm_does_not_sign(self):
        sim = self.review_card_psbt(txlab.EXAMPLE_PSBT)
        sim.keys(MIDDLE, RIGHT)
        sim.ok("wait 1500")
        self.assertFalse((self.card / "test-signed.psbt").exists())

    def test_reject_writes_nothing(self):
        sim = self.review_card_psbt(txlab.EXAMPLE_PSBT)
        sim.keys(LEFT)  # reject
        sim.ok("wait 1500")
        self.assertFalse((self.card / "test-signed.psbt").exists())
        self.assertEqual(sorted(p.name for p in self.card.iterdir()), ["test.psbt"])

    def assert_refused(self, b64: str, why: str):
        """The card job fails before any review, so the keys that would sign do nothing."""
        sim = self.review_card_psbt(b64)
        sim.keys(MIDDLE)
        sim.ok("wait 1200")
        sim.keys(RIGHT)
        sim.ok("wait 1500")
        log = sim.close()
        self.sim = None
        self.assertFalse((self.card / "test-signed.psbt").exists())
        self.assertIn(why, log)

    def test_lying_prev_tx_is_refused(self):
        self.assert_refused(
            lower_prev_amount(txlab.EXAMPLE_PSBT, 100), "rejected by secure partition"
        )

    def test_missing_non_witness_utxo_is_refused(self):
        self.assert_refused(
            edit_prev_tx(txlab.EXAMPLE_PSBT, lambda raw: None), "missing non-witness UTXO"
        )


if __name__ == "__main__":
    unittest.main()
