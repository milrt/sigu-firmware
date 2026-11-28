# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Install images as imgtool and NCS lay them out, and the steps of an install on the Firmware
screen."""

import hashlib
import struct

from case import WalletTest
from sim import MIDDLE, RIGHT, WEB, Sim

# The sim checks the headers and versions as the device does,
# but not the signatures, which are MCUboot's and b0's job.
S0_ADDR, S1_ADDR, NS_ADDR = 0x8000, 0x19000, 0x84000
SLOT1_SIZE = 624 * 1024
# The card files the Firmware screen reads: the build outputs, renamed.
APP_FILE, BOOT_S0_FILE, BOOT_S1_FILE = "sigu-app.bin", "sigu-mcuboot-s0.bin", "sigu-mcuboot-s1.bin"
IMAGE_F_ROM_FIXED = 0x100
FW_INFO_MAGIC = (0x281EE6DE, 0x8FCEBB4C, 0x00003602)
FW_INFO_VALID = 0x9102FFFF
# The TLV area: the info, then IMAGE_TLV_SHA256.
# The sim's MCUboot checks this hash where the device checks an ed25519 signature.
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
    """A signed image as imgtool lays it out: the header (struct image_header),
    a body that is not all 0xff, the protected TLVs and the TLVs, so the image ends with the file.
    sim/src/flash.c builds the running one the same way.
    NCS signs the app and both bootloaders with ROM_FIXED,
    so only the load address tells them apart."""
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


class InstallCase(WalletTest):
    def open_firmware(self) -> Sim:
        sim = self.open_test_wallet()
        sim.keys(RIGHT, *[MIDDLE] * 6, RIGHT)  # status -> menu -> Firmware
        return sim

    def stage(self, sim: Sim, *keys: str) -> None:
        """Presses `keys` (MIDDLE picks the next file), then install.
        NS writes slot1, and the panel shows it with OK armed."""
        sim.keys(*keys, RIGHT)
        sim.ok("wait 2000")  # the poll, the write to slot1, and 1 s before OK is armed

    def dump(self, sim: Sim, what: str) -> bytes:
        """Saves slot0 or slot1 and reads it.
        The card folder is the one host folder the web build can write.
        A new name each time: the web build's NODEFS keeps a deleted file."""
        self.dumps = getattr(self, "dumps", 0) + 1
        name = f"{what}-{self.dumps}.dump"
        sim.ok(f"{what} {'/sigu/card/' + name if WEB else self.card / name}")
        data = (self.card / name).read_bytes()
        (self.card / name).unlink()
        return data

    def slot1(self, sim: Sim) -> bytes:
        return self.dump(sim, "slot1")

    def install(self, sim: Sim, *keys: str) -> tuple[str, bytes]:
        """Stages the file, then OK on the confirm view.
        Returns the log and slot1 after NS is done."""
        self.stage(sim, *keys)
        sim.keys(RIGHT)
        sim.ok("wait 3000")  # the poll, the request, and the 2 s before the restart
        return sim.read_log(), self.slot1(sim)

    def assert_installed(self, log: str, slot1: bytes, image: bytes, what: str, permanent=False):
        """An app is a test (image_ok unset), so MCUboot swaps it back unless NS confirms it.
        A bootloader is permanent."""
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
