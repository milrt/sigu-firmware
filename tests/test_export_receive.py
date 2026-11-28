# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Export wallet and Receive: the descriptor file, the addresses, and their QR codes."""

import sys

from case import WalletTest, png_rgb
from sim import LEFT, MIDDLE, RIGHT, ROOT, Sim

# nayuki's Python QR encoder, from the same west project as the C one the SP uses.
sys.path.append(str(ROOT.parent / "external/qrcodegen/python"))

import qrcodegen  # noqa: E402

# Its master fingerprint and account key, m/84'/0'/0', as BIP84 publishes them
# (under the xpub version bytes).
ABANDON_FP = "73c5da0a"
ABANDON_XPUB = (
    "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZ"
    "XYVUhLv1VMrjPC7PW6V"
)

# BIP380's reference checksum, so the test does not trust the C code it checks.
DESC_INPUT_CHARSET = (
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"
    '"\\ '
)
DESC_CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def descsum_create(s: str) -> str:
    generator = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]

    def polymod(symbols):
        chk = 1
        for value in symbols:
            top = chk >> 35
            chk = (chk & 0x7FFFFFFFF) << 5 ^ value
            for i in range(5):
                chk ^= generator[i] if ((top >> i) & 1) else 0
        return chk

    symbols, groups = [], []
    for c in s:
        v = DESC_INPUT_CHARSET.index(c)
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    checksum = polymod(symbols + [0] * 8) ^ 1
    return s + "#" + "".join(DESC_CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))


class ExportReceiveTest(WalletTest):
    def export_wallet(self, *before: str) -> Sim:
        """Opens the BIP84 vector wallet, runs `before`, and saves it from the Export screen."""
        sim = self.open_abandon(self.start())
        for line in before:
            sim.ok(line)
        sim.keys(RIGHT, MIDDLE, MIDDLE, RIGHT)  # status -> menu -> Export wallet
        sim.keys(RIGHT)  # save
        sim.ok("wait 1000")  # NS polls for the job every 200 ms
        return sim

    def test_export_watch_only(self):
        sim = self.export_wallet()
        desc = descsum_create(f"wpkh([{ABANDON_FP}/84h/0h/0h]{ABANDON_XPUB}/<0;1>/*)")
        self.assertEqual((self.card / f"wallet-{ABANDON_FP}.txt").read_text(), desc + "\n")
        self.assertIn(f"wallet saved to /SD:/wallet-{ABANDON_FP}.txt", sim.read_log())

    def test_export_without_card(self):
        sim = self.export_wallet("card out", "wait 1200")
        self.assertFalse((self.card / f"wallet-{ABANDON_FP}.txt").exists())
        self.assertIn("wallet export failed: 1", sim.read_log())

    def test_export_qr(self):
        sim = self.open_abandon(self.start())
        sim.keys(RIGHT, MIDDLE, MIDDLE, RIGHT)  # status -> menu -> Export wallet
        sim.ok("wait 100")
        info = self.shot_bytes(sim, "export.png")
        sim.keys(MIDDLE)  # qr
        sim.ok("wait 100")
        desc = descsum_create(f"wpkh([{ABANDON_FP}/84h/0h/0h]{ABANDON_XPUB}/<0;1>/*)")
        want = qrcodegen.QrCode.encode_segments(
            [qrcodegen.QrSegment.make_bytes(desc.encode())], qrcodegen.QrCode.Ecc.LOW, 1, 7)
        self.assert_qr(self.shot_bytes(sim, "qr.png"), want, 45, 4)

        sim.keys(LEFT)  # any key goes back to the info, and does not leave
        sim.ok("wait 100")
        self.assertEqual(self.shot_bytes(sim, "export2.png"), info)

    # The panel shows `want` full screen, black on white, centered, with a light quiet zone.
    def assert_qr(self, png: bytes, want: "qrcodegen.QrCode", size: int, scale: int):
        width, height, raw = png_rgb(png)
        self.assertEqual((want.get_size(), width // (want.get_size() + 8)), (size, scale))
        x0 = (width - size * scale) // 2
        y0 = (height - size * scale) // 2

        def dark(x: int, y: int) -> bool:
            off = y * (1 + width * 3) + 1 + x * 3
            px = tuple(raw[off : off + 3])
            self.assertIn(px, ((0, 0, 0), (0xFF, 0xFF, 0xFF)))
            return px == (0, 0, 0)

        got = [[dark(x0 + c * scale + scale // 2, y0 + r * scale + scale // 2)
                for c in range(size)] for r in range(size)]
        self.assertEqual(got, [[want.get_module(c, r) for c in range(size)] for r in range(size)])
        # The quiet zone is light all around.
        self.assertFalse(any(dark(x, y) for y in range(height) for x in range(width)
                             if not (x0 <= x < x0 + size * scale and y0 <= y < y0 + size * scale)))

    def test_receive_screen(self):
        sim = self.open_abandon(self.start())
        sim.keys(RIGHT, MIDDLE, RIGHT)  # status -> menu -> Receive
        sim.ok("wait 100")
        first = self.shot_bytes(sim, "receive0.png")
        sim.keys(MIDDLE)  # next
        sim.ok("wait 100")
        # BIP84 publishes the second receive address too. The screen groups it in 4s.
        self.assertIn("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
                      sim.text().replace(" | ", "").replace(" ", ""))
        second = self.shot_bytes(sim, "receive1.png")
        self.assertNotEqual(first, second)
        sim.keys(LEFT)  # back to the menu
        sim.ok("wait 100")
        self.assertNotEqual(self.shot_bytes(sim, "menu.png"), second)

    def test_receive_qr(self):
        sim = self.open_abandon(self.start())
        sim.keys(RIGHT, MIDDLE, RIGHT)  # status -> menu -> Receive
        sim.keys(MIDDLE)  # next, index 1
        sim.ok("wait 100")
        info = self.shot_bytes(sim, "receive1.png")
        sim.keys(RIGHT)  # qr
        sim.ok("wait 100")
        # BIP84's second receive address, in uppercase for alphanumeric mode.
        want = qrcodegen.QrCode.encode_segments(
            [qrcodegen.QrSegment.make_alphanumeric("BC1QNJG0JD8228AQ7EGYZACY8CYS3KNF9XVRERKF9G")],
            qrcodegen.QrCode.Ecc.LOW, 1, 2)
        self.assert_qr(self.shot_bytes(sim, "receive-qr.png"), want, 25, 7)

        sim.keys(MIDDLE)  # any key goes back to the same address, and does not step
        sim.ok("wait 100")
        self.assertEqual(self.shot_bytes(sim, "receive1b.png"), info)
