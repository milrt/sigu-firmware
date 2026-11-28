# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Host tests for txlab. They need no sim. run.py runs them with the wallet tests."""

import base64
import sys
import unittest
from pathlib import Path

from btclib.psbt.psbt import Psbt

sys.path.append(str(Path(__file__).resolve().parents[1] / "sim"))
import txlab  # noqa: E402


class TxlabTest(unittest.TestCase):
    def test_sign_raw_matches_device(self):
        self.assertEqual(txlab.sign_raw(txlab.wallet(), txlab.EXAMPLE_PSBT),
                         txlab.EXAMPLE_SIGNED_PSBT)

    def test_device_signature_checks(self):
        txlab.check_signed(txlab.wallet(), Psbt.b64decode(txlab.EXAMPLE_SIGNED_PSBT))

    def test_maps_round_trip(self):
        raw = base64.b64decode(txlab.EXAMPLE_PSBT)
        self.assertEqual(txlab.join_maps(txlab.split_maps(raw)), raw)

    def test_build_psbt_with_change(self):
        psbt = txlab.build_psbt(
            txlab.wallet(),
            inputs=[txlab.Input(txlab.PREV_TX, 1, "m/84h/1h/0h/0/0")],
            outputs=[
                txlab.Output("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", 5000),
                txlab.Output("m/84h/1h/0h/1/0", 13000),
            ],
        )
        self.assertFalse(psbt.outputs[0].hd_key_paths)
        self.assertTrue(psbt.outputs[1].hd_key_paths)


if __name__ == "__main__":
    unittest.main()
