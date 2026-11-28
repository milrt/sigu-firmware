# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Firmware installs: the Firmware screen, the install record, and what MCUboot swaps."""

import struct


from case import ABANDON, PIN, png_rgb
from images import (APP_FILE, BACK_DROPPED, BOOT_S1_FILE, CLOSED, DROPPED, IMAGE_F_ROM_FIXED,
                     NS_ADDR, NSIB, S0_ADDR, S1_ADDR, SWAP_BACK, SWAP_PERM, SWAP_TEST,
                     InstallCase, boot_image, mcuboot_image)
from sim import LEFT, MIDDLE, RIGHT, Sim


class InstallTest(InstallCase):
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
        # hdr_size + img_size wraps to 64, where this 104-byte file has its TLV info.
        # Without the check, NS, the SP and the hook all take it as a whole image.
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
