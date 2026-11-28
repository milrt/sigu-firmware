# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""The firmware's own self-tests, run from NS."""

from case import WalletTest


class SelftestTest(WalletTest):
    def test_selftests_pass(self):
        sim = self.start()
        sim.ok("ns selftest")
        log = sim.close()
        self.sim = None
        self.assertIn("Tests Failed:    0", log)
