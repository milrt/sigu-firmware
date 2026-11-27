// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bip32.h"
#include "base58.h"
#include "secp256k1_context.h"
#include "shared/hash.h"
#include "shared/mem_util.h"
#include <secp256k1.h>
#include <secp256k1_preallocated.h>
#include <stdbool.h>
#include <string.h>

#define BIP32_SERIALIZED_SIZE 78

static psa_status_t privkey_to_pubkey(const uint8_t *privkey, uint8_t *out_pubkey33)
{
    uint8_t ctx_mem[secp256k1_get_context_size()];
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    secp256k1_context *ctx = secp256k1_create_randomized_context(ctx_mem);
    if (!ctx) {
        goto cleanup;
    }

    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, privkey)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    size_t pub_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, out_pubkey33, &pub_len, &pub,
                                       SECP256K1_EC_COMPRESSED)) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto cleanup;
    }

    status = PSA_SUCCESS;

cleanup:
    if (ctx) {
        secp256k1_context_preallocated_destroy(ctx);
    }
    mem_zeroize(ctx_mem, sizeof(ctx_mem));
    return status;
}

static psa_status_t get_fingerprint(const uint8_t *pubkey, uint8_t fingerprint[4])
{
    if (!pubkey || !fingerprint) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t hash160[20] = {0};

    psa_status_t status = hash_hash160(pubkey, 33, hash160, sizeof(hash160));
    if (status == PSA_SUCCESS) {
        memcpy(fingerprint, hash160, 4);
    }

    mem_zeroize(hash160, sizeof(hash160));
    return status;
}

psa_status_t bip32_seed_to_master_privkey(const uint8_t *seed, size_t seed_size,
                                          bip32_extended_privkey_t *master_key)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    uint8_t hmac[64] = {0};

    if (!seed || seed_size < 16 || seed_size > 64 || !master_key) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // 1) HMAC-SHA512("Bitcoin seed", seed)
    const char *key = "Bitcoin seed";
    status =
        hash_hmac_sha512((const uint8_t *)key, strlen(key), seed, seed_size, hmac, sizeof(hmac));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    // 2) Rejects k == 0 and k >= n.
    //    The static context is enough: no multiply by the generator, so no blinding.
    if (!secp256k1_ec_seckey_verify(secp256k1_context_static, hmac)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    // 3) Fill out the structure
    memcpy(master_key->private_key, hmac, 32);
    memcpy(master_key->chain_code, hmac + 32, 32);
    master_key->depth = 0;
    master_key->child_number = 0;
    memset(master_key->parent_fingerprint, 0, BIP32_FINGERPRINT_SIZE);

    status = PSA_SUCCESS;

cleanup:
    if (status != PSA_SUCCESS) {
        mem_zeroize(master_key, sizeof(*master_key));
    }
    mem_zeroize(hmac, sizeof(hmac));
    return status;
}

static psa_status_t derive_child_privkey(const bip32_extended_privkey_t *parent_key,
                                         uint32_t child_index, bip32_extended_privkey_t *child_key)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    bool hardened = (child_index & BIP32_HARDENED) != 0;

    uint8_t data[37] = {0};
    uint8_t hmac[64] = {0};
    uint8_t parent_pubkey[33] = {0};
    uint8_t fingerprint[BIP32_FINGERPRINT_SIZE] = {0};
    uint8_t tweak[32] = {0};
    uint8_t child_privkey[32] = {0};
    uint8_t parent_depth;

    if (!parent_key || !child_key) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (parent_key->depth == 255) {
        // Depth is one byte. A child of 255 would wrap to 0 and serialize as a master key.
        // Only a deserialized depth-255 key can get here.
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    parent_depth = parent_key->depth;

    // 1) We need the parent pubkey for the fingerprint in both cases,
    //    and as the HMAC data when the child is not hardened.
    status = privkey_to_pubkey(parent_key->private_key, parent_pubkey);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = get_fingerprint(parent_pubkey, fingerprint);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    // 2) HMAC data: [0x00 + parent_privkey] when hardened, [parent_pubkey] when not,
    //    plus child_index in big-endian.
    if (hardened) {
        data[0] = 0x00;
        memcpy(&data[1], parent_key->private_key, 32);
    } else {
        memcpy(data, parent_pubkey, 33);
    }
    data[33] = (child_index >> 24) & 0xFF;
    data[34] = (child_index >> 16) & 0xFF;
    data[35] = (child_index >> 8) & 0xFF;
    data[36] = (child_index) & 0xFF;

    // 3) HMAC-SHA512(chain_code, data)
    status = hash_hmac_sha512(parent_key->chain_code, 32, data, sizeof(data), hmac, sizeof(hmac));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    memcpy(tweak, hmac, 32);
    memcpy(child_privkey, parent_key->private_key, 32);

    // 4) ki = k + IL mod n.
    //    Returns 0 for both invalid-child cases in BIP-32: IL >= n (scalar overflow) and ki == 0.
    //    IL == 0 is allowed. We report the error instead of skipping to the next index.
    if (!secp256k1_ec_seckey_tweak_add(secp256k1_context_static, child_privkey, tweak)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }
    if (!secp256k1_ec_seckey_verify(secp256k1_context_static, child_privkey)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    // 5) First write to the child.
    //    child_key may alias parent_key, so every read of the parent comes before this.
    memcpy(child_key->private_key, child_privkey, 32);
    memcpy(child_key->chain_code, hmac + 32, 32);
    memcpy(child_key->parent_fingerprint, fingerprint, sizeof(fingerprint));
    child_key->depth = parent_depth + 1;
    child_key->child_number = child_index;

    status = PSA_SUCCESS;

cleanup:
    mem_zeroize(data, sizeof(data));
    mem_zeroize(hmac, sizeof(hmac));
    mem_zeroize(parent_pubkey, sizeof(parent_pubkey));
    mem_zeroize(fingerprint, sizeof(fingerprint));
    mem_zeroize(tweak, sizeof(tweak));
    mem_zeroize(child_privkey, sizeof(child_privkey));
    return status;
}

// "m" or "m/c1/.../cN".
// A component is one or more decimal digits, then one optional ' h or H for hardened,
// and must end at '/' or NUL.
// We reject anything else ("m/0h1", "m/0'foo", "m/") instead of guessing.
static psa_status_t parse_path(const char *path_str, uint32_t *indices, size_t *out_depth)
{
    const char *p = path_str;
    size_t depth = 0;

    if (strlen(path_str) >= BIP32_MAX_PATH_LENGTH) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (*p++ != 'm') {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    while (*p) {
        // This also checks the end of the previous component.
        if (*p++ != '/') {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (depth == BIP32_MAX_DEPTH) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (*p < '0' || *p > '9') {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        uint32_t index = 0;
        do {
            uint32_t digit = (uint32_t)(*p - '0');
            // Check before multiplying: index * 10 can wrap past 0x7FFFFFFF.
            if (index > (0x7FFFFFFFu - digit) / 10u) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            index = index * 10u + digit;
            p++;
        } while (*p >= '0' && *p <= '9');

        if (*p == '\'' || *p == 'h' || *p == 'H') {
            index |= BIP32_HARDENED;
            p++;
        }

        indices[depth++] = index;
    }

    *out_depth = depth;
    return PSA_SUCCESS;
}

static psa_status_t derive_path_privkey(const bip32_extended_privkey_t *parent_key,
                                        const uint32_t *path, size_t path_length,
                                        bip32_extended_privkey_t *derived_key)
{
    // Copy first: derived_key may alias parent_key.
    bip32_extended_privkey_t current = *parent_key;
    psa_status_t status = PSA_SUCCESS;

    for (size_t i = 0; i < path_length; i++) {
        status = derive_child_privkey(&current, path[i], &current);
        if (status != PSA_SUCCESS) {
            break;
        }
    }

    if (status == PSA_SUCCESS) {
        // Intermediate keys never reach the output,
        // so a failure in the middle of the path leaves nothing half-written there.
        *derived_key = current;
    }

    mem_zeroize(&current, sizeof(current));
    return status;
}

psa_status_t bip32_extended_privkey_derive_from_path(const bip32_extended_privkey_t *parent_key,
                                                     const char *path_str,
                                                     bip32_extended_privkey_t *derived_key)
{
    if (!parent_key || !path_str || !derived_key) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint32_t indices[BIP32_MAX_DEPTH];
    size_t depth = 0;

    psa_status_t status = parse_path(path_str, indices, &depth);
    if (status == PSA_SUCCESS) {
        status = derive_path_privkey(parent_key, indices, depth, derived_key);
    }

    // A failure must not leave an old key in the caller's output.
    // But when in and out are the same struct, that output is the caller's parent key.
    if (status != PSA_SUCCESS && derived_key != parent_key) {
        mem_zeroize(derived_key, sizeof(*derived_key));
    }

    mem_zeroize(indices, sizeof(indices));
    return status;
}

psa_status_t bip32_path_coin_type(const char *path_str, uint32_t *out)
{
    if (!path_str || !out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint32_t indices[BIP32_MAX_DEPTH];
    size_t depth = 0;

    psa_status_t status = parse_path(path_str, indices, &depth);
    if (status == PSA_SUCCESS) {
        if (depth < 2) {
            status = PSA_ERROR_DOES_NOT_EXIST;
        } else if (!(indices[1] & BIP32_HARDENED)) {
            status = PSA_ERROR_NOT_SUPPORTED;
        } else {
            *out = indices[1] & ~BIP32_HARDENED;
        }
    }

    mem_zeroize(indices, sizeof(indices));
    return status;
}

psa_status_t bip32_path_purpose(const char *path_str, uint32_t *out)
{
    if (!path_str || !out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint32_t indices[BIP32_MAX_DEPTH];
    size_t depth = 0;

    psa_status_t status = parse_path(path_str, indices, &depth);
    if (status == PSA_SUCCESS) {
        if (depth < 1) {
            status = PSA_ERROR_DOES_NOT_EXIST;
        } else {
            *out = indices[0];
        }
    }

    mem_zeroize(indices, sizeof(indices));
    return status;
}

psa_status_t bip32_path_bip84(const char *path_str, bip32_bip84_path_t *out)
{
    if (!path_str || !out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint32_t indices[BIP32_MAX_DEPTH];
    size_t depth = 0;

    psa_status_t status = parse_path(path_str, indices, &depth);
    if (status == PSA_SUCCESS) {
        if (depth != 5 || indices[0] != (84u | BIP32_HARDENED) || !(indices[1] & BIP32_HARDENED) ||
            !(indices[2] & BIP32_HARDENED) || (indices[3] & BIP32_HARDENED) ||
            (indices[4] & BIP32_HARDENED)) {
            status = PSA_ERROR_NOT_SUPPORTED;
        } else {
            out->coin_type = indices[1] & ~BIP32_HARDENED;
            out->account = indices[2] & ~BIP32_HARDENED;
            out->chain = indices[3];
            out->index = indices[4];
        }
    }

    mem_zeroize(indices, sizeof(indices));
    return status;
}

psa_status_t bip32_extended_pubkey_from_privkey(const bip32_extended_privkey_t *privkey,
                                                bip32_extended_pubkey_t *out_pubkey)
{
    if (!privkey || !out_pubkey) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = privkey_to_pubkey(privkey->private_key, out_pubkey->pubkey);
    if (status != PSA_SUCCESS) {
        return status;
    }

    memcpy(out_pubkey->chain_code, privkey->chain_code, 32);
    out_pubkey->depth = privkey->depth;
    out_pubkey->child_number = privkey->child_number;
    memcpy(out_pubkey->parent_fingerprint, privkey->parent_fingerprint, BIP32_FINGERPRINT_SIZE);

    return PSA_SUCCESS;
}

psa_status_t bip32_extended_pubkey_serialize(const bip32_extended_pubkey_t *key, uint32_t version,
                                             char *output, size_t *output_size)
{
    if (!key || !output || !output_size || *output_size < BIP32_MAX_SERIALIZED_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    uint8_t data[BIP32_SERIALIZED_SIZE + 4] = {0};

    data[0] = (version >> 24) & 0xFF;
    data[1] = (version >> 16) & 0xFF;
    data[2] = (version >> 8) & 0xFF;
    data[3] = (version) & 0xFF;

    data[4] = key->depth;

    memcpy(&data[5], key->parent_fingerprint, 4);

    data[9] = (key->child_number >> 24) & 0xFF;
    data[10] = (key->child_number >> 16) & 0xFF;
    data[11] = (key->child_number >> 8) & 0xFF;
    data[12] = (key->child_number) & 0xFF;

    memcpy(&data[13], key->chain_code, 32);

    memcpy(&data[45], key->pubkey, 33);

    status = base58_check_encode(data, BIP32_SERIALIZED_SIZE, output, *output_size);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    *output_size = strlen(output) + 1;
    status = PSA_SUCCESS;

cleanup:
    mem_zeroize(data, sizeof(data));
    return status;
}

psa_status_t bip32_extended_pubkey_get_fingerprint(const bip32_extended_pubkey_t *key,
                                                   uint8_t *fingerprint)
{
    if (!key || !fingerprint) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = get_fingerprint(key->pubkey, fingerprint);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return PSA_SUCCESS;
}
