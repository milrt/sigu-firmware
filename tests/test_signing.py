# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Signing: the review on the panel, card jobs, and an NS that lies about the tx."""

import base64
import dataclasses
import hashlib
import struct

from btclib.psbt.psbt import Psbt
from btclib.tx.tx import Tx

from case import WalletTest
from sim import (FILES_POLL, FILES_RESULT, FILES_SET, LEFT, MIDDLE, RIGHT, TX_BEGIN, TX_CONFIRM,
                  TX_INPUT, TX_OUTPUT, TX_SIGN_INPUT, Sim)
import txlab  # after sim, which puts sim/ on sys.path

PSBT_IN_NON_WITNESS_UTXO = b"\x00"


def edit_prev_tx(b64: str, edit) -> str:
    """Return the PSBT with input 0's NON_WITNESS_UTXO replaced by edit(bytes),
    or removed if edit returns None. Every other record keeps its bytes and its place."""
    maps = txlab.split_maps(base64.b64decode(b64))
    records = []
    for key, value in maps[1]:
        if key == PSBT_IN_NON_WITNESS_UTXO:
            value = edit(value)
            if value is None:
                continue
        records.append((key, value))
    maps[1] = records
    return base64.b64encode(txlab.join_maps(maps)).decode()


def lower_prev_amount(b64: str, by: int) -> str:
    """The fee attack: the prev tx claims less for the output we spend. The txid stays."""
    vout = Psbt.b64decode(b64).tx.vin[0].prev_out.vout

    def edit(raw: bytes) -> bytes:
        tx = Tx.parse(raw)
        assert tx.serialize(include_witness=True, check_validity=False) == raw
        tx.vout[vout] = dataclasses.replace(tx.vout[vout], value=tx.vout[vout].value - by)
        return tx.serialize(include_witness=True, check_validity=False)

    return edit_prev_tx(b64, edit)


def compact_size(n: int) -> bytes:
    return bytes([n]) if n < 0xFD else b"\xfd" + struct.pack("<H", n)


def prev_tx(amount: int, script: bytes) -> bytes:
    """A legacy-serialized tx with one made-up input that pays `amount` to `script`.
    The SP cannot see the chain, so any well-formed tx whose txid matches the outpoint counts."""
    tx = struct.pack("<IB", 2, 1) + b"\x11" * 32 + struct.pack("<IBI", 0, 0, 0xFFFFFFFF)
    tx += b"\x01" + struct.pack("<Q", amount) + compact_size(len(script)) + script
    return tx + struct.pack("<I", 0)


def stream_tx(sim: "Sim", dest: bytes, send=10000, fee=500, funds=50000, pause_ms=0) -> int:
    """BEGIN, a payment to `dest`, change, our input and CONFIRM, as NS sends them,
    with `pause_ms` after BEGIN. Returns the first status that is not 0, else 0."""
    w = txlab.wallet()
    ours = txlab.p2wpkh_script(txlab.pub_key(w, "m/84h/1h/0h/0/0"))
    change = txlab.p2wpkh_script(txlab.pub_key(w, "m/84h/1h/0h/1/0"))
    prev = prev_tx(funds, ours)
    txid = hashlib.sha256(hashlib.sha256(prev).digest()).digest()

    def out_rec(amount: int, script: bytes) -> bytes:
        return struct.pack("<QB", amount, len(script)) + script.ljust(34, b"\0")

    calls = [
        (TX_BEGIN, [struct.pack("<5I", 2, 0, 1, 2, 1)]),
        (TX_OUTPUT, [out_rec(send, dest), b""]),
        (TX_OUTPUT, [out_rec(funds - send - fee, change), b"m/84'/1'/0'/1/0\0"]),
        (TX_INPUT, [txid + struct.pack("<II", 0, 0xFFFFFFFD), b"m/84'/1'/0'/0/0\0", prev]),
        (TX_CONFIRM, []),
    ]
    for op, ins in calls:
        st, _ = sim.ipc(op, ins)
        if st:
            return st
        if op == TX_BEGIN and pause_ms:
            sim.ok(f"wait {pause_ms}")
    return 0


class SigningTest(WalletTest):
    def review_card_psbt(self, b64: str) -> Sim:
        """Puts the PSBT on the card and opens it from the menu, up to the review."""
        (self.card / "test.psbt").write_text(b64 + "\n")
        sim = self.open_test_wallet()
        sim.keys(RIGHT, RIGHT, RIGHT)  # status -> menu -> Sign from card -> test.psbt
        sim.ok("wait 1000")  # NS polls for the job every 200 ms
        return sim

    MERCHANT_SCRIPT = b"\x00\x14" + bytes(range(101, 121))
    ATTACKER_SCRIPT = b"\x00\x14" + bytes(range(1, 21))

    def review_from_ns(self) -> Sim:
        """NS streams a payment to the merchant.
        The user reads it up to the total page and OK is armed."""
        sim = self.open_test_wallet()
        sim.ok("ns freeze")  # the test is NS
        self.assertEqual(stream_tx(sim, self.MERCHANT_SCRIPT), 0)
        sim.ok("wait 450")  # the status screen polls for a tx every 200 ms
        self.assertTrue(sim.text().startswith("Review"))
        sim.keys(MIDDLE)
        sim.ok("wait 1200")
        return sim

    def sign_first_input(self, sim: Sim) -> int:
        st, _ = sim.ipc(TX_SIGN_INPUT, [struct.pack("<I", 0), b"m/84'/1'/0'/0/0\0"], [72, 33])
        return st

    def test_swap_under_review_ends_it(self):
        # The same amounts to another address.
        # A review that restarted on it would look the same on the total page,
        # and the same keys would sign it.
        # No tick between the calls, as from a fast NS. A slow one is the next test.
        sim = self.review_from_ns()
        sim.ok("tick hold")
        self.assertEqual(stream_tx(sim, self.ATTACKER_SCRIPT), 0)
        sim.ok("tick go")
        sim.ok("wait 450")
        self.assertFalse(sim.text().startswith("Review"))
        sim.keys(MIDDLE)
        sim.ok("wait 1200")
        sim.keys(RIGHT)
        self.assertNotEqual(self.sign_first_input(sim), 0)

    def test_slow_swap_under_review_ends_it(self):
        # A pause after BEGIN: the review sees no tx_id and must not come back for the next one.
        sim = self.review_from_ns()
        self.assertNotEqual(stream_tx(sim, self.ATTACKER_SCRIPT, pause_ms=450), 0)
        self.assertFalse(sim.text().startswith("Review"))
        sim.keys(RIGHT)
        self.assertNotEqual(self.sign_first_input(sim), 0)

    def test_idle_on_review_signs_nothing(self):
        sim = self.review_card_psbt(txlab.EXAMPLE_PSBT)
        sim.ok(f"ticks {self.LOCK_TICKS + 2}")
        self.assertIn("state=1", sim.ok("ns status"))
        sim.ok("wait 1500")
        self.assertFalse((self.card / "test-signed.psbt").exists())

    def test_card_sign_matches_device(self):
        sim = self.review_card_psbt(txlab.EXAMPLE_PSBT)
        sim.keys(MIDDLE)  # the total page, the only page where "sign" approves
        sim.ok("wait 1200")  # ARM_TICKS
        sim.keys(RIGHT)
        sim.ok("wait 1500")

        signed = (self.card / "test-signed.psbt").read_text()
        self.assertEqual(signed, txlab.EXAMPLE_SIGNED_PSBT)
        self.assertTrue(sim.text().startswith("SD card | signed |"))
        self.assertEqual(signed, txlab.sign_raw(txlab.wallet(), txlab.EXAMPLE_PSBT))

    def test_card_sign_pays_p2pkh(self):
        # A legacy destination renders as base58 and can be approved.
        w = txlab.wallet()
        b64 = txlab.build_psbt(
            w,
            inputs=[txlab.Input(txlab.PREV_TX, 1, "m/84h/1h/0h/0/0")],
            outputs=[
                txlab.Output("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", 5000),
                txlab.Output("m/84h/1h/0h/1/0", 13000),
            ],
        ).b64encode()
        sim = self.review_card_psbt(b64)
        sim.keys(MIDDLE)
        sim.ok("wait 1200")
        sim.keys(RIGHT)
        sim.ok("wait 1500")

        self.assertEqual((self.card / "test-signed.psbt").read_text(), txlab.sign_raw(w, b64))

    def test_reinsert_reads_new_files(self):
        # The card is read when it goes in. A file added later needs the card out and in.
        sim = self.open_test_wallet()
        (self.card / "test.psbt").write_text(txlab.EXAMPLE_PSBT + "\n")
        sim.ok("card out")
        sim.ok("wait 1200")  # NS checks the card once a second
        sim.ok("card in")
        sim.ok("wait 1200")
        sim.keys(RIGHT, RIGHT, RIGHT)  # status -> menu -> Sign from card -> test.psbt
        sim.ok("wait 1000")
        sim.keys(MIDDLE)
        sim.ok("wait 1200")
        sim.keys(RIGHT)
        sim.ok("wait 1500")
        self.assertEqual((self.card / "test-signed.psbt").read_text(), txlab.EXAMPLE_SIGNED_PSBT)

    def test_card_ok_without_a_signature_is_not_signed(self):
        # NS takes the sign job and ends it with OK at once: no tx, no review, no signature.
        sim = self.open_test_wallet()
        sim.ok("ns freeze")  # the test is NS
        sim.ipc(FILES_SET, [b"ok.psbt".ljust(32, b"\0"), struct.pack("<I", 1), struct.pack("<IB", 0, 0)])
        sim.keys(RIGHT, RIGHT, RIGHT)  # status -> menu -> Sign from card -> ok.psbt
        self.assertEqual(sim.ipc(FILES_POLL, [], [32, 4])[0], 0)
        self.assertEqual(sim.ipc(FILES_RESULT, [struct.pack("<I", 0)])[0], 0)  # BITCOIN_FILES_OK
        sim.ok("wait 300")
        self.assertTrue(sim.text().startswith("SD card | not signed |"))

    def test_ok_before_arm_does_not_sign(self):
        sim = self.review_card_psbt(txlab.EXAMPLE_PSBT)
        sim.keys(MIDDLE, RIGHT)
        sim.ok("wait 1500")
        self.assertFalse((self.card / "test-signed.psbt").exists())

    def test_reject_writes_nothing(self):
        sim = self.review_card_psbt(txlab.EXAMPLE_PSBT)
        sim.keys(LEFT)  # reject
        sim.ok("wait 1500")
        self.assertFalse((self.card / "test-signed.psbt").exists())
        self.assertEqual(sorted(p.name for p in self.card.iterdir()), ["test.psbt"])

    def assert_refused(self, b64: str, why: str):
        """The card job fails before any review, so the keys that would sign do nothing."""
        sim = self.review_card_psbt(b64)
        sim.keys(MIDDLE)
        sim.ok("wait 1200")
        sim.keys(RIGHT)
        sim.ok("wait 1500")
        log = sim.close()
        self.sim = None
        self.assertFalse((self.card / "test-signed.psbt").exists())
        self.assertIn(why, log)

    def test_lying_prev_tx_is_refused(self):
        self.assert_refused(
            lower_prev_amount(txlab.EXAMPLE_PSBT, 100), "rejected by secure partition"
        )

    def test_missing_non_witness_utxo_is_refused(self):
        self.assert_refused(
            edit_prev_tx(txlab.EXAMPLE_PSBT, lambda raw: None), "missing non-witness UTXO"
        )
