// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// BIP32 in the partition:
// the master key from a seed, private derivation along a path, and the xpub.
// The partition has no xprv encoding and decodes no extended key.
//
// Every path goes through one parser: "m", or "m" and up to BIP32_MAX_DEPTH components,
// each "/" then decimal digits below 2^31 and one optional ', h or H for hardened.
// Anything else is PSA_ERROR_INVALID_ARGUMENT.
// So a path that names a network or an account is exactly a path that could derive a key.

#pragma once

#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

#define BIP32_MAX_SERIALIZED_SIZE 113 // room for a base58 xpub and its NUL
#define BIP32_FINGERPRINT_SIZE 4
#define BIP32_MAX_PATH_LENGTH 256
#define BIP32_MAX_DEPTH 10
#define BIP32_HARDENED 0x80000000

// BIP32's own version bytes, not SLIP-132: the partition signs P2WPKH only,
// and the descriptor around the xpub gives the script type.
#define BIP32_MAINNET_PUB_VERSION 0x0488B21E
#define BIP32_TESTNET_PUB_VERSION 0x043587CF

typedef struct {
    uint8_t private_key[32];
    uint8_t chain_code[32];
    uint8_t depth;
    uint32_t child_number;
    uint8_t parent_fingerprint[BIP32_FINGERPRINT_SIZE];
} bip32_extended_privkey_t;

typedef struct {
    uint8_t pubkey[33];
    uint8_t chain_code[32];
    uint8_t depth;
    uint32_t child_number;
    uint8_t parent_fingerprint[BIP32_FINGERPRINT_SIZE];
} bip32_extended_pubkey_t;

typedef struct {
    uint32_t coin_type;
    uint32_t account;
    uint32_t chain;
    uint32_t index;
} bip32_bip84_path_t;

// The master key of a seed of 16 to 64 bytes.
psa_status_t bip32_seed_to_master_privkey(const uint8_t *seed, size_t seed_size,
                                          bip32_extended_privkey_t *master_key);

// Derives `path_str` from `parent_key`, so "m" gives a copy of it.
// `derived_key` may be `parent_key`.
// On a failure `derived_key` is zeroed, except when it is `parent_key`: then it stays as it was.
psa_status_t bip32_extended_privkey_derive_from_path(const bip32_extended_privkey_t *parent_key,
                                                     const char *path_str,
                                                     bip32_extended_privkey_t *derived_key);

// The public half of `privkey`,
// with the same chain code, depth, child number and parent fingerprint.
psa_status_t bip32_extended_pubkey_from_privkey(const bip32_extended_privkey_t *privkey,
                                                bip32_extended_pubkey_t *out_pubkey);

// The base58check xpub of `key` with `version`.
// `*output_size` is the buffer size in (at least BIP32_MAX_SERIALIZED_SIZE),
// and the string size with its NUL out.
psa_status_t bip32_extended_pubkey_serialize(const bip32_extended_pubkey_t *key, uint32_t version,
                                             char *output, size_t *output_size);

// The fingerprint of `key` itself: the first 4 bytes of hash160(pubkey).
psa_status_t bip32_extended_pubkey_get_fingerprint(const bip32_extended_pubkey_t *key,
                                                   uint8_t *fingerprint);

// The BIP44 coin type: the second component, with the hardened bit cleared.
// PSA_ERROR_DOES_NOT_EXIST for a shorter path,
// and PSA_ERROR_NOT_SUPPORTED if the component is not hardened.
// The purpose is not checked.
psa_status_t bip32_path_coin_type(const char *path_str, uint32_t *out);

// The BIP44 purpose: the first component, with the hardened bit kept, so 84 never passes as 84'.
// PSA_ERROR_DOES_NOT_EXIST for "m".
psa_status_t bip32_path_purpose(const char *path_str, uint32_t *out);

// m/84'/c'/a'/chain/index, with c and a hardened and chain and index not.
// The values have no hardened bit. PSA_ERROR_NOT_SUPPORTED for any other path.
psa_status_t bip32_path_bip84(const char *path_str, bip32_bip84_path_t *out);
