// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "sighash.h"
#include "script.h"
#include "shared/hash.h"
#include "shared/mem_util.h"
#include "shared/wire.h"

// nVersion | hashPrevouts | hashSequence | outpoint | scriptCode with its compactsize |
// amount | nSequence | hashOutputs | nLockTime | nHashType
#define PREIMAGE_SIZE (4 + 32 + 32 + 36 + 1 + SCRIPT_CODE_P2WPKH_SIZE + 8 + 4 + 32 + 4 + 4)

psa_status_t sighash_bip143(const sighash_bip143_params_t *p, uint8_t out32[32])
{
    if (!p || !out32 || !p->hash_prevouts || !p->hash_sequence || !p->txid || !p->script_code ||
        !p->hash_outputs) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    // P2WPKH is the only input the partition signs.
    // The three commitment hashes are the SIGHASH_ALL forms,
    // so no other type may go into the preimage.
    if (p->script_code_len != SCRIPT_CODE_P2WPKH_SIZE || p->sighash_type != BITCOIN_SIGHASH_ALL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t preimage[PREIMAGE_SIZE];
    wire_w w = wire_writer(preimage, sizeof(preimage));

    wire_put_le32(&w, p->version);
    wire_put_field(&w, p->hash_prevouts, 32, 32);
    wire_put_field(&w, p->hash_sequence, 32, 32);
    wire_put_field(&w, p->txid, 32, 32);
    wire_put_le32(&w, p->vout);
    wire_put_u8(&w, SCRIPT_CODE_P2WPKH_SIZE);
    wire_put_field(&w, p->script_code, SCRIPT_CODE_P2WPKH_SIZE, SCRIPT_CODE_P2WPKH_SIZE);
    wire_put_le64(&w, p->amount);
    wire_put_le32(&w, p->sequence);
    wire_put_field(&w, p->hash_outputs, 32, 32);
    wire_put_le32(&w, p->locktime);
    wire_put_le32(&w, p->sighash_type);

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    if (w.ok && w.pos == sizeof(preimage)) {
        status = hash_double_sha256(preimage, sizeof(preimage), out32, 32);
    }
    mem_zeroize(preimage, sizeof(preimage));
    return status;
}
