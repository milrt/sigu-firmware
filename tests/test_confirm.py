# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""After an install: health.c confirms the new app, and the status screen shows a failed one."""

import unittest

from case import PIN, config_record, read_config
from images import APP_FILE, NS_ADDR, InstallCase, mcuboot_image
from sim import MIDDLE, RIGHT, WEB, Sim
import txlab  # after sim, which puts sim/ on sys.path

FAILED_LINE = "firmware install failed"


class ConfirmTest(InstallCase):
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
