// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "script.h"
#include "base58.h"
#include "shared/hash.h"
#include "shared/segwit_addr.h"
#include <string.h>

// An uncompressed key of the same private key hashes to a different address.
// A script built from one could not be spent, so only compressed keys hash.
static psa_status_t pubkey_hash(const uint8_t *pubkey, uint8_t hash[20])
{
    if (!pubkey || (pubkey[0] != 0x02 && pubkey[0] != 0x03)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return hash_hash160(pubkey, BITCOIN_PUBKEY_SIZE, hash, 20);
}

psa_status_t script_p2wpkh_from_pubkey(const uint8_t pubkey[BITCOIN_PUBKEY_SIZE],
                                       uint8_t out[SCRIPT_P2WPKH_SIZE])
{
    if (!out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    out[0] = 0x00; // OP_0, witness version 0
    out[1] = 0x14; // push 20 bytes
    return pubkey_hash(pubkey, &out[2]);
}

psa_status_t script_code_p2wpkh_from_pubkey(const uint8_t pubkey[BITCOIN_PUBKEY_SIZE],
                                            uint8_t out[SCRIPT_CODE_P2WPKH_SIZE])
{
    if (!out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    out[0] = 0x76;  // OP_DUP
    out[1] = 0xa9;  // OP_HASH160
    out[2] = 0x14;  // push 20 bytes
    out[23] = 0x88; // OP_EQUALVERIFY
    out[24] = 0xac; // OP_CHECKSIG
    return pubkey_hash(pubkey, &out[3]);
}

script_kind_t script_classify(const uint8_t *script, size_t script_len)
{
    if (!script) {
        return SCRIPT_KIND_UNKNOWN;
    }
    if (script_len == SCRIPT_P2PKH_SIZE && script[0] == 0x76 && script[1] == 0xa9 &&
        script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac) {
        return SCRIPT_KIND_P2PKH;
    }
    if (script_len == SCRIPT_P2SH_SIZE && script[0] == 0xa9 && script[1] == 0x14 &&
        script[22] == 0x87) {
        return SCRIPT_KIND_P2SH;
    }
    if (script_len == SCRIPT_P2WPKH_SIZE && script[0] == 0x00 && script[1] == 0x14) {
        return SCRIPT_KIND_P2WPKH;
    }
    if (script_len == SCRIPT_P2WSH_SIZE && script[0] == 0x00 && script[1] == 0x20) {
        return SCRIPT_KIND_P2WSH;
    }
    // OP_1 and a 32-byte push.
    // The partition cannot sign taproot inputs, but a tx can pay to one,
    // and the user must see where the money goes.
    if (script_len == SCRIPT_P2TR_SIZE && script[0] == 0x51 && script[1] == 0x20) {
        return SCRIPT_KIND_P2TR;
    }
    return SCRIPT_KIND_UNKNOWN;
}

// Base58Check of a version byte and the 20-byte hash at script[hash_at].
static psa_status_t base58_address(const uint8_t *script, size_t hash_at, uint8_t version,
                                   char *out, size_t out_size)
{
    uint8_t payload[21];

    payload[0] = version;
    memcpy(&payload[1], script + hash_at, 20);
    return base58_check_encode(payload, sizeof(payload), out, out_size);
}

psa_status_t script_to_address(const uint8_t *script, size_t script_len, uint32_t coin_type,
                               char *out, size_t out_size)
{
    if (!script || !out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // The session allows only coin types 0 and 1,
    // so testnet for any other value is a fallback, not a way to pick a network.
    bool mainnet = coin_type == 0;
    script_kind_t kind = script_classify(script, script_len);

    // tx_session_confirm() then refuses the tx.
    if (kind == SCRIPT_KIND_UNKNOWN) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    // BIP173 limits a bech32 string to 90 characters, and segwit_addr_encode() checks that.
    // A base58 address is shorter. So one size covers every kind and network.
    if (out_size < BITCOIN_ADDRESS_MAX_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (kind == SCRIPT_KIND_P2PKH) {
        return base58_address(script, 3, mainnet ? 0x00 : 0x6f, out, out_size);
    }
    if (kind == SCRIPT_KIND_P2SH) {
        return base58_address(script, 2, mainnet ? 0x05 : 0xc4, out, out_size);
    }
    // script[0] is the version opcode and script[1] the push length.
    int version = kind == SCRIPT_KIND_P2TR ? 1 : 0;
    if (!segwit_addr_encode(out, mainnet ? "bc" : "tb", version, script + 2, script_len - 2)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return PSA_SUCCESS;
}
