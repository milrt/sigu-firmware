# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""The security floor: no app below `min_security` installs, and when the floor rises."""

import struct
import unittest
from pathlib import Path

from case import PIN
from images import (APP_FILE, DROPPED, NOT_VALID, NS_ADDR, NSIB, SWAP_BACK, SWAP_PERM, SWAP_TEST,
                     InstallCase, mcuboot_image)
from sim import MIDDLE, RIGHT, WEB, Sim
import txlab  # after sim, which puts sim/ on sys.path


class SecurityFloorTest(InstallCase):
    def reboot(self, ps: Path, first=False, args: tuple[str, ...] = ()) -> Sim:
        """Restarts the same device: PS and the flash stay, and MCUboot's checks run first.
        Opens the wallet and the Firmware screen."""
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
        """Installs an app with `security` and keeps it:
        the install, the test boot with the confirm, and the boot after.
        Returns the log of that last boot."""
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
        # The user says OK to an image whose signature MCUboot then refuses.
        # Its counter was read before the check, so it must not become the floor.
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
        # Power fails while MCUboot writes the raised floor.
        # The copy before it is TESTING, so the next boot ends the test again and raises the
        # floor again.
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
