# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Power cuts at every flash write of a boot that swaps."""

import re

from images import APP_FILE, NS_ADDR, SWAP_TEST, InstallCase, mcuboot_image
from sim import MIDDLE, Sim


class PowerCutTest(InstallCase):
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
        # nonsecure/health acts once, 10 s after the start.
        # Let that pass before slot0 holds a test app, so it does not confirm one in the middle
        # of a loop.
        sim.ok("wait 4000")
        return sim, old, new

    def cut_everywhere(self, sim: Sim, check, every=1) -> int:
        """Runs the next boot from the same flash,
        cut at each of its flash writes in turn (MCUboot's swap and status, our record),
        then boots again and calls check(log) on that boot.
        With `every`, only the first 50 writes and then every n-th one, plus the last.
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
        # Every time the device boots an intact app, the old one or the new one,
        # and the floor matches it. A cut before the swap starts loses the install, safely.
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
        # The new app was not confirmed, so this boot swaps the old one back.
        # It must end with the old app, and the floor must not rise.
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
        # MCUboot copies the bootloader to the inactive s1.
        # A cut anywhere must leave the app in slot0 bootable and the floor alone:
        # b0 checks s1 itself before it starts it.
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
