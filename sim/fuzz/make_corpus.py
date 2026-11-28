# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write the seed corpus for the fuzz targets, from txlab's test wallet fixtures.

    sim/.venv/bin/python sim/fuzz/make_corpus.py sim/build-fuzz/corpus

Each target gets <out>/<target>/. The seeds are valid inputs, so the fuzzer starts deep in the
parser instead of at the magic bytes.
"""

import base64
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sim"))

import txlab  # noqa: E402
from btclib.psbt.psbt import Psbt  # noqa: E402
from btclib.tx.tx import Tx  # noqa: E402

FILE_NAME_MAX = 32  # BITCOIN_FILE_NAME_MAX_SIZE
SCRIPT_MAX = 34  # BITCOIN_TX_SCRIPT_MAX_SIZE


def psbts() -> list[bytes]:
    w = txlab.wallet()
    built = txlab.build_psbt(
        w,
        inputs=[txlab.Input(txlab.PREV_TX, 1, "m/84h/1h/0h/0/0")],
        outputs=[
            txlab.Output("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", 5000),
            txlab.Output("m/84h/1h/0h/1/0", 6422),
        ],
        lock_time=4075093,
    )
    return [
        base64.b64decode(txlab.EXAMPLE_PSBT),
        base64.b64decode(txlab.EXAMPLE_SIGNED_PSBT),
        base64.b64decode(built.b64encode()),
    ]


def prev_txs() -> list[tuple[int, bytes]]:
    """(vout, tx) for every NON_WITNESS_UTXO in the PSBTs, with and without the witness."""
    out = []
    for raw in psbts():
        psbt = Psbt.b64decode(base64.b64encode(raw).decode())
        for n, psbt_in in enumerate(psbt.inputs):
            tx = psbt_in.non_witness_utxo
            if tx is None:
                continue
            vout = psbt.tx.vin[n].prev_out.vout
            out.append((vout, tx.serialize(include_witness=False, check_validity=False)))
            if tx.is_segwit:
                out.append((vout, tx.serialize(include_witness=True, check_validity=False)))
    prev = Tx.parse(txlab.PREV_TX)
    out.append((1, prev.serialize(include_witness=True, check_validity=False)))
    return out


def records() -> list[bytes]:
    script = txlab.p2wpkh_script(txlab.pub_key(txlab.wallet(), "m/84h/1h/0h/1/0"))
    return [
        b"\x00" + struct.pack("<5I", 2, 4075093, 1, 2, 1),
        b"\x01" + struct.pack("<QB", 6422, len(script)) + script.ljust(SCRIPT_MAX, b"\0"),
        b"\x02" + bytes(range(32)) + struct.pack("<II", 1, 0xFFFFFFFD),
    ]


def files_set() -> list[bytes]:
    def msg(names, card, fw=struct.pack("<IB", 0, 0), installs=b""):
        in0 = b"".join(n.ljust(FILE_NAME_MAX, b"\0") for n in names)
        in1 = struct.pack("<I", card)
        vecs = [in0, in1, fw, installs]
        return struct.pack("<4H", *(len(v) for v in vecs)) + b"".join(vecs)

    app = struct.pack("<BBBBHI", 2, 0, 1, 2, 3, 0) + bytes(range(32))
    boot = struct.pack("<BBBBHI", 1, 0, 0, 0, 0, 5) + bytes(32)
    return [
        msg([], 0),
        msg([b"pay.psbt", b"b.PSBT"], 1),
        msg([b"x.psbt"], 1, struct.pack("<IB", 4, 2), app + boot),
        msg([], 2, struct.pack("<IB", 3, 1)),
    ]


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "corpus")
    seeds = {
        "fuzz_psbt": psbts(),
        "fuzz_prev_tx": [struct.pack("<I", vout) + tx for vout, tx in prev_txs()],
        "fuzz_records": records(),
        "fuzz_files_set": files_set(),
    }
    for target, items in seeds.items():
        d = out / target
        d.mkdir(parents=True, exist_ok=True)
        for i, data in enumerate(items):
            (d / f"seed-{i}").write_bytes(data)
        print(f"{d}: {len(items)} seeds")


if __name__ == "__main__":
    main()
