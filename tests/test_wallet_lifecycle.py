# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""The wallet's life on the panel: PIN, lock, idle time and wipe."""

import struct
import time
import unittest
from pathlib import Path

from case import (ABANDON, PIN, WalletTest, config_path, config_record, read_config,
                   write_config)
from sim import GET_XPUB, LEFT, MIDDLE, PROD_FIRST, PROD_LAST, RIGHT, WEB, Sim


class WalletLifecycleTest(WalletTest):
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
        """Opens the test wallet on a PS folder with theme 1 stored,
        then presses `keys` on the reset list.
        NS reports no failed install, so the seen bit stays 0."""
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
        # Each call keeps the SP thread 200 ms (`ipc cost`),
        # as a call that derives keys may on the device.
        # The idle time must follow the clock, not the ticks the SP got to handle.
        sim = self.open_test_wallet()
        sim.ok("ns freeze")  # the test is NS
        # Up to 10 s before the lock.
        # The tick thread runs during a burst too (a slow build adds hundreds of ticks),
        # so the second burst fills up to what the SP counted.
        # No key was pressed, so every tick since the start is idle time.
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
