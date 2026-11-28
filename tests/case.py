# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""The base class of the wallet tests, with the steps most of them share."""

import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from sim import WEB, Sim
import txlab  # after sim, which puts sim/ on sys.path

PIN = "1234"
# BIP84's test vector wallet.
ABANDON = " ".join(["abandon"] * 11 + ["about"])

CONFIG_UID = 0x10020010


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


class WalletTest(unittest.TestCase):
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
        """Stores and opens the BIP84 vector wallet,
        and waits for the status screen to poll it."""
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

    def shot_bytes(self, sim: Sim, name: str) -> bytes:
        shot = self.card / name
        sim.ok(f"shot {'/sigu/card/' + name if WEB else shot}")
        return shot.read_bytes()

    def pixel(self, sim: Sim, x: int, y: int) -> tuple[int, int, int]:
        width, _, raw = png_rgb(self.shot_bytes(sim, "shot.png"))
        off = y * (1 + width * 3) + 1 + x * 3
        return tuple(raw[off : off + 3])

    def bg_pixel(self, sim: Sim) -> tuple[int, int, int]:
        """The status screen's background, left of the center."""
        return self.pixel(sim, 2, 120)

    BLACK_BG = (0x00, 0x00, 0x00)  # the default theme's background
    LOCK_TICKS = 15000  # 5 min of 20 ms ticks, display.c
