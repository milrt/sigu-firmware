// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The BIP143 (segwit v0) signature hash.
// The partition builds it itself, so an approval means something:
// with a digest from NS, nothing the partition checks or shows would be tied to the signature.
//
// BIP143 also commits to the amount of the input.
// A wrong amount gives a signature that is not valid against the real UTXO,
// so either the fee on the panel is right or the tx cannot be broadcast.
// Legacy inputs have no such commitment, so the partition does not sign them.

#pragma once

#include "shared/tx_records.h"
#include <psa/crypto.h>
#include <stdint.h>

typedef struct {
    uint32_t version;
    const uint8_t *hash_prevouts; // 32
    const uint8_t *hash_sequence; // 32
    const uint8_t *txid;          // 32, the outpoint of this input
    uint32_t vout;
    const uint8_t *script_code;
    size_t script_code_len;
    uint64_t amount;
    uint32_t sequence;
    const uint8_t *hash_outputs; // 32
    uint32_t locktime;
    uint32_t sighash_type;
} sighash_bip143_params_t;

// The sighash of a P2WPKH input with SIGHASH_ALL.
// Any other scriptCode or type is PSA_ERROR_INVALID_ARGUMENT.
psa_status_t sighash_bip143(const sighash_bip143_params_t *params, uint8_t out32[32]);
