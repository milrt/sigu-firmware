# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Settings: the theme, kept in the SP's config record."""

import unittest
from pathlib import Path

from case import WalletTest, config_path, config_record, read_config, write_config
from sim import LEFT, MIDDLE, RIGHT, WEB, Sim


class SettingsTest(WalletTest):
    def settings_boot(self, ps: Path, row: int, *keys: str) -> str:
        """One boot on `ps` that opens Settings, goes down `row` rows and presses `keys`.
        Returns the screen text on that row."""
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
