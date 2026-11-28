# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""The firmware's own self-tests,
as `bitcoin test_secure` and `bitcoin test_nonsecure` run them in the shell of a dev build."""

from case import WalletTest


class SelftestTest(WalletTest):
    def test_secure_selftests_pass(self):
        sim = self.start()
        sim.ok("ns test_secure")
        log = sim.close()
        self.sim = None
        self.assertIn("Tests Failed:    0", log)

    def test_nonsecure_selftests_pass(self):
        sim = self.start()
        reply = sim.cmd("ns test_nonsecure")
        log = sim.close()
        self.sim = None
        # The failures are in the log.
        self.assertRegex(reply, r"^ok passed=[1-9]\d* failed=0$", log)
