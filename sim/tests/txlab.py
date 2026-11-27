# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""The test wallet and a reference signer for the sim tests.

It builds a PSBT, signs one the way the partition signs, and checks a PSBT the
device gave back. sim/tests and sim/fuzz/make_corpus.py import it.
"""

import base64
import hashlib
import hmac
from typing import NamedTuple

from btclib.bip32 import bip32
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.curves.curve import secp256k1
from btclib.ecc import dsa
from btclib.hashes import hash160
from btclib.mnemonic import bip39
from btclib.network import NETWORKS
from btclib.psbt.psbt import Psbt, extract_tx, finalize
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.script import sig_hash
from btclib.script.engine import verify_transaction
from btclib.script.script_pub_key import ScriptPubKey
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut

# The wallet. These are the values psbt_test.c seeds its test wallet with, so
# the fixtures there and anything built here describe the same keys. Change
# both files together, or the BIP32 records stop naming the same master
# fingerprint and change detection on the device breaks.
MNEMONIC = "guess nuclear width pave clap crumble rain dance nurse bind parrot yellow"
PASSPHRASE = "sigzone"
NETWORK = "testnet"
ACCOUNT = "m/84h/1h/0h"

TX_VERSION = 2
SEQUENCE = 0xFFFFFFFD
SIGHASH_ALL = 1
PSBT_IN_PARTIAL_SIG = 0x02


class Input(NamedTuple):
    """One input: the funding transaction as hex, which output of it, our path."""

    prev_tx: str
    vout: int
    path: str


class Output(NamedTuple):
    """One output. The target is an address, or our own path for change."""

    target: str
    amount: int


def wallet(mnemonic: str = MNEMONIC, passphrase: str = PASSPHRASE) -> str:
    """Return the root xprv of the wallet, as the device derives it."""
    seed = bip39.seed_from_mnemonic(mnemonic, passphrase)
    return bip32.rootxprv_from_seed(seed, NETWORKS[NETWORK].bip32_prv)


def pub_key(root: str, path) -> bytes:
    xpub = bip32.xpub_from_xprv(bip32.derive(root, path))
    return bip32.BIP32KeyData.b58decode(xpub).key


def prv_key(root: str, path) -> bytes:
    return bip32.BIP32KeyData.b58decode(bip32.derive(root, path)).key[1:]


def fingerprint(root: str) -> bytes:
    return hash160(pub_key(root, "m/"))[:4]


def p2wpkh_script(pub: bytes) -> bytes:
    """OP_0 <hash160(pubkey)>, what chains_pubkey_to_script() builds."""
    return b"\x00\x14" + hash160(pub)


def prevouts(psbt: Psbt) -> list[TxOut]:
    """Return the output each input spends, in input order."""
    out = []
    for n, psbt_in in enumerate(psbt.inputs):
        if psbt_in.non_witness_utxo is not None:
            out.append(psbt_in.non_witness_utxo.vout[psbt.tx.vin[n].prev_out.vout])
        else:
            out.append(psbt_in.witness_utxo)
    return out


def build_psbt(root: str, inputs: list[Input], outputs: list[Output], lock_time: int = 0) -> Psbt:
    """Build an unsigned PSBT. An output target that starts with "m/" is ours.

    Ours means the output gets a BIP32 derivation record, which is what lets the
    partition re-derive it and treat it as change instead of showing it.
    """
    master = fingerprint(root)
    prev_txs = [Tx.parse(spec.prev_tx) for spec in inputs]

    vout, psbt_outs = [], []
    for spec in outputs:
        if spec.target.startswith("m/"):
            pub = pub_key(root, spec.target)
            script = p2wpkh_script(pub)
            psbt_outs.append(PsbtOut(hd_key_paths={pub: BIP32KeyOrigin(master, spec.target)}))
        else:
            script = ScriptPubKey.from_address(spec.target).script
            psbt_outs.append(PsbtOut())
        vout.append(TxOut(spec.amount, script))

    tx = Tx(
        version=TX_VERSION,
        lock_time=lock_time,
        vin=[
            TxIn(OutPoint(prev_tx.id, spec.vout), sequence=SEQUENCE)
            for prev_tx, spec in zip(prev_txs, inputs)
        ],
        vout=vout,
    )

    psbt_ins = [
        PsbtIn(
            non_witness_utxo=prev_tx,
            witness_utxo=prev_tx.vout[spec.vout],
            sig_hash_type=SIGHASH_ALL,
            hd_key_paths={pub_key(root, spec.path): BIP32KeyOrigin(master, spec.path)},
        )
        for prev_tx, spec in zip(prev_txs, inputs)
    ]

    psbt = Psbt.from_tx(tx, psbt_ins, psbt_outs)
    account = bip32.BIP32KeyData.b58decode(bip32.xpub_from_xprv(bip32.derive(root, ACCOUNT)))
    psbt.hd_key_paths = {account.serialize(): BIP32KeyOrigin(master, ACCOUNT)}
    psbt.assert_valid()
    return psbt


def rfc6979_nonce(prv: bytes, digest: bytes) -> int:
    """Return the nonce libsecp256k1 derives for this key and digest.

    secp256k1_ecdsa_sign() with a NULL nonce function is RFC6979 over
    key32 || msg32, with no algo16. We redo it here so a signature built in this
    file is the same bytes the partition produces. btclib's own signer uses a
    different RFC6979 convention and gives a valid but different signature, so
    it cannot be used to predict or pin device output.
    """
    order = secp256k1.n
    seed = prv + digest
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + seed, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + seed, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < order:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_digest(prv: bytes, digest: bytes, hash_type: int) -> bytes:
    """Return the DER signature plus the sighash byte, as the partition does."""
    nonce = rfc6979_nonce(prv, digest)
    # lower_s and no grinding is what secp256k1_ecdsa_sign() answers with
    return dsa.sign_(digest, prv, nonce, True, grind=False).serialize() + bytes([hash_type])


def sign(root: str, psbt: Psbt) -> Psbt:
    """Sign every input the wallet owns, in place, and return the PSBT."""
    master = fingerprint(root)
    spent = prevouts(psbt)

    for n, psbt_in in enumerate(psbt.inputs):
        hash_type = psbt_in.sig_hash_type or SIGHASH_ALL
        for pub, origin in psbt_in.hd_key_paths.items():
            if origin.master_fingerprint != master:
                continue
            # a PSBT saying "this key is at that path" is written by someone
            # else, so sign only when the path really derives to that key
            if pub_key(root, origin.der_path) != pub:
                raise ValueError(f"input {n}: {origin.description} is not that key")
            digest = sig_hash.from_tx(spent, psbt.tx, n, hash_type)
            psbt_in.partial_sigs[pub] = sign_digest(prv_key(root, origin.der_path), digest,
                                                    hash_type)
    return psbt


def split_maps(raw: bytes) -> list[list[tuple[bytes, bytes]]]:
    """Split PSBT bytes into its maps, keeping every record where it is."""

    def size(at: int) -> tuple[int, int]:
        first = raw[at]
        if first < 0xFD:
            return first, at + 1
        width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
        return int.from_bytes(raw[at + 1 : at + 1 + width], "little"), at + 1 + width

    at, maps = len(b"psbt\xff"), []
    while at < len(raw):
        records = []
        while raw[at] != 0:
            length, at = size(at)
            key, at = raw[at : at + length], at + length
            length, at = size(at)
            value, at = raw[at : at + length], at + length
            records.append((key, value))
        at += 1
        maps.append(records)
    return maps


def join_maps(maps: list[list[tuple[bytes, bytes]]]) -> bytes:
    """Return the PSBT bytes for maps, the inverse of split_maps()."""

    def size(length: int) -> bytes:
        if length < 0xFD:
            return bytes([length])
        if length <= 0xFFFF:
            return b"\xfd" + length.to_bytes(2, "little")
        return b"\xfe" + length.to_bytes(4, "little")

    raw = b"psbt\xff"
    for records in maps:
        for key, value in records:
            raw += size(len(key)) + key + size(len(value)) + value
        raw += b"\x00"
    return raw


def sign_raw(root: str, b64: str) -> str:
    """Sign and re-emit, leaving every record where it was.

    The partition appends the partial signature to the end of the input map, and
    psbt_test.c pins the base64 that comes out. btclib sorts records by key type
    when it serializes, so sign() gives the same PSBT in a different byte order.
    Use this one to regenerate that fixture.
    """
    maps = split_maps(base64.b64decode(b64))
    psbt = sign(root, Psbt.b64decode(b64))
    for n, psbt_in in enumerate(psbt.inputs):
        records = maps[1 + n]
        for pub, sig in psbt_in.partial_sigs.items():
            key = bytes([PSBT_IN_PARTIAL_SIG]) + pub
            if not any(existing == key for existing, _ in records):
                records.append((key, sig))
    return base64.b64encode(join_maps(maps)).decode()


def check_signed(root: str, psbt: Psbt) -> None:
    """Check a signed PSBT the way a reviewer would. Raise on the first problem."""
    master = fingerprint(root)
    spent = prevouts(psbt)

    for n, psbt_in in enumerate(psbt.inputs):
        if not psbt_in.partial_sigs:
            raise ValueError(f"input {n}: no signature")
        hash_type = psbt_in.sig_hash_type or SIGHASH_ALL
        digest = sig_hash.from_tx(spent, psbt.tx, n, hash_type)

        for pub, sig in psbt_in.partial_sigs.items():
            if sig[-1] != hash_type:
                raise ValueError(f"input {n}: signed for sighash {sig[-1]}, not {hash_type}")
            origin = psbt_in.hd_key_paths.get(pub)
            if origin is None or origin.master_fingerprint != master:
                raise ValueError(f"input {n}: signed by a key the PSBT does not place in us")
            if pub_key(root, origin.der_path) != pub:
                raise ValueError(f"input {n}: {origin.description} is not that key")
            if not dsa.verify_(digest, pub, sig[:-1]):
                raise ValueError(f"input {n}: signature does not verify")
            if sig != sign_digest(prv_key(root, origin.der_path), digest, hash_type):
                raise ValueError(f"input {n}: not the signature the partition would make")

    verify_transaction(spent, extract_tx(finalize(psbt)))


# The funding transaction of the fixtures below. Its output 1 pays
# m/84h/1h/0h/0/0 with 18922 sats.
PREV_TX = (
    "02000000019001cf937b7e7950a5c818138aa98ef74adc8fd1f336d877d348799a6e784c49"
    "0100000000fdffffff0288b7a6b8000000001600142f990de55716e76a9c3e6e9ef444ff42"
    "9d8298c4ea4900000000000016001463eabb1e882628a3d050f6ef2bba9030febe17dd402e"
    "3e00"
)

# The one output PSBT, the same fixture psbt_test.c reads.
EXAMPLE_PSBT = (
    "cHNidP8BAHECAAAAAQmRtjBtG4pseYo9aWA6Cjst0E5db1QhSAHBSovQGSk5AQAAAAD9////Apg6AAAAAAAAFgAU"
    "AhwwpCAd2VHnZbXafW/XWEH7pE9eDQAAAAAAABYAFGfHzVm5AeAEX4fdTMHZJTsp7hveVS4+AE8BBDWHzwMuRF/"
    "cgAAAAPxf6XMnS+a0/RiSUycEy0ViWsmgCXTApwTTC+jLPvCuA92ijp/z7HQvP2n4wSfUgxF8wHpvxvmq9vv6l7"
    "VFm6hPECSzBqZUAACAAQAAgAAAAIAAAQBxAgAAAAGQAc+Te355UKXIGBOKqY73StyP0fM22HfTSHmabnhMSQEAA"
    "AAA/f///wKIt6a4AAAAABYAFC+ZDeVXFudqnD5unvRE/0KdgpjE6kkAAAAAAAAWABRj6rseiCYoo9BQ9u8rupAw"
    "/r4X3UAuPgABAR/qSQAAAAAAABYAFGPqux6IJiij0FD27yu6kDD+vhfdAQMEAQAAACIGAi+NVo70FI76y2NOK7w"
    "qU1IAMfZ+fw9PPSwyaO248d6nGCSzBqZUAACAAQAAgAAAAIAAAAAAAAAAAAAAIgIDit7wwrlz/pHLR2CmBQkUgm"
    "tqorsaQxWTOnCrejidFiQYJLMGplQAAIABAACAAAAAgAEAAAAAAAAAAA=="
)

# The same PSBT after the device signed it, the expected_signed_psbt_b64 fixture.
EXAMPLE_SIGNED_PSBT = (
    "cHNidP8BAHECAAAAAQmRtjBtG4pseYo9aWA6Cjst0E5db1QhSAHBSovQGSk5AQAAAAD9////Apg6AAAAAAAAFgAU"
    "AhwwpCAd2VHnZbXafW/XWEH7pE9eDQAAAAAAABYAFGfHzVm5AeAEX4fdTMHZJTsp7hveVS4+AE8BBDWHzwMuRF/c"
    "gAAAAPxf6XMnS+a0/RiSUycEy0ViWsmgCXTApwTTC+jLPvCuA92ijp/z7HQvP2n4wSfUgxF8wHpvxvmq9vv6l7VF"
    "m6hPECSzBqZUAACAAQAAgAAAAIAAAQBxAgAAAAGQAc+Te355UKXIGBOKqY73StyP0fM22HfTSHmabnhMSQEAAAAA"
    "/f///wKIt6a4AAAAABYAFC+ZDeVXFudqnD5unvRE/0KdgpjE6kkAAAAAAAAWABRj6rseiCYoo9BQ9u8rupAw/r4X"
    "3UAuPgABAR/qSQAAAAAAABYAFGPqux6IJiij0FD27yu6kDD+vhfdAQMEAQAAACIGAi+NVo70FI76y2NOK7wqU1IA"
    "MfZ+fw9PPSwyaO248d6nGCSzBqZUAACAAQAAgAAAAIAAAAAAAAAAACICAi+NVo70FI76y2NOK7wqU1IAMfZ+fw9P"
    "PSwyaO248d6nRzBEAiAjhEP70ON9ZRRut/X3650qfBIswfkTatUb8rBRfkfSaAIgcpr42du1SEXd3Ug/FipiUD0W"
    "BDIYgzR/iQnqh/9cm4gBAAAiAgOK3vDCuXP+kctHYKYFCRSCa2qiuxpDFZM6cKt6OJ0WJBgkswamVAAAgAEAAIAA"
    "AACAAQAAAAAAAAAA"
)

