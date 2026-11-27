// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The output scripts the partition builds, names and shows.

#pragma once

#include "shared/bitcoin_service_defs.h"
#include <psa/crypto.h>
#include <stdbool.h>
#include <stdint.h>

#define SCRIPT_P2WPKH_SIZE 22
#define SCRIPT_P2WSH_SIZE 34
#define SCRIPT_P2TR_SIZE 34
#define SCRIPT_P2PKH_SIZE 25
#define SCRIPT_P2SH_SIZE 23
#define SCRIPT_CODE_P2WPKH_SIZE 25

typedef enum {
    SCRIPT_KIND_UNKNOWN = 0,
    SCRIPT_KIND_P2WPKH,
    SCRIPT_KIND_P2WSH,
    SCRIPT_KIND_P2TR,
    SCRIPT_KIND_P2PKH,
    SCRIPT_KIND_P2SH,
} script_kind_t;

// The P2WPKH scriptPubKey of a compressed pubkey: OP_0 <hash160(pubkey)>.
// The partition builds it from a key it derived and compares bytes,
// so a change output is checked, not believed.
psa_status_t script_p2wpkh_from_pubkey(const uint8_t pubkey[BITCOIN_PUBKEY_SIZE],
                                       uint8_t out[SCRIPT_P2WPKH_SIZE]);

// The BIP143 scriptCode of a P2WPKH input:
// OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG.
psa_status_t script_code_p2wpkh_from_pubkey(const uint8_t pubkey[BITCOIN_PUBKEY_SIZE],
                                            uint8_t out[SCRIPT_CODE_P2WPKH_SIZE]);

script_kind_t script_classify(const uint8_t *script, size_t script_len);

// The address of a scriptPubKey: base58 for P2PKH and P2SH, bech32 or bech32m for segwit.
// `coin_type` is the BIP44 value of a path the partition parsed (0 mainnet, else testnet),
// so the network is never a setting NS sends.
// Any other script is PSA_ERROR_NOT_SUPPORTED, because the user could not check it.
// `out_size` must be at least BITCOIN_ADDRESS_MAX_SIZE.
psa_status_t script_to_address(const uint8_t *script, size_t script_len, uint32_t coin_type,
                               char *out, size_t out_size);
