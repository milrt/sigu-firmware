// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "key_storage.h"
#include "shared/hash.h"
#include "shared/mem_util.h"
#include "shared/tx_records.h"
#include <psa/protected_storage.h>
#include <string.h>

#define MAX_FAILS 10
#define FORMAT_VERSION 1

#define SALT_SIZE 16
#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16

// PBKDF2-HMAC-SHA512 iterations for the PIN key.
// About 500 ms on the nRF54L15 (CRACEN), which is one unlock. Tune it against a measured time.
#define PIN_KDF_ITERATIONS 10000

// The AAD binds the ciphertext to the format and the UID,
// so a blob cannot move to the other record or be read under a later layout.
// It is built byte by byte, because a struct would feed its padding to the AEAD.
#define AAD_SIZE 12

typedef struct {
    uint32_t format;
    uint32_t fail_count;
    uint8_t salt[SALT_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t tag[TAG_SIZE];
    uint8_t ciphertext[sizeof(magic_internet_key_t)];
} key_storage_data_t;

const key_storage_uids_t key_storage_uids_production = {
    .data = 0x10010010UL,
};

// Must never equal production: the tests store a known blob under a known PIN and wipe it.
// On the production UID, `bitcoin test_secure` would destroy a real wallet.
const key_storage_uids_t key_storage_uids_test = {
    .data = 0x10010020UL,
};

static void make_aad(const key_storage_uids_t *uids, uint8_t aad[AAD_SIZE])
{
    tx_put_le32(&aad[0], FORMAT_VERSION);
    tx_put_le64(&aad[4], (uint64_t)uids->data);
}

// A volatile AES-256-GCM key from the PIN and the record's salt.
static psa_status_t pin_key(const char *pin, const uint8_t salt[SALT_SIZE], psa_key_usage_t usage,
                            psa_key_id_t *key)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t material[64]; // hash_pbkdf2_hmac_sha512() gives at least one block

    psa_status_t status =
        hash_pbkdf2_hmac_sha512((const uint8_t *)pin, strlen(pin), salt, SALT_SIZE,
                                PIN_KDF_ITERATIONS, material, sizeof(material));
    if (status == PSA_SUCCESS) {
        psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&attributes, KEY_SIZE * 8);
        psa_set_key_usage_flags(&attributes, usage);
        psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
        status = psa_import_key(&attributes, material, KEY_SIZE, key);
    }
    mem_zeroize(material, sizeof(material));
    return status;
}

// GCM puts the tag after the ciphertext. The record keeps the two apart.
static psa_status_t seal(const key_storage_uids_t *uids, psa_key_id_t key,
                         const magic_internet_key_t *keys, key_storage_data_t *data)
{
    uint8_t aad[AAD_SIZE];
    uint8_t out[sizeof(data->ciphertext) + TAG_SIZE];
    size_t len = 0;

    make_aad(uids, aad);
    psa_status_t status =
        psa_aead_encrypt(key, PSA_ALG_GCM, data->iv, IV_SIZE, aad, AAD_SIZE, (const uint8_t *)keys,
                         sizeof(*keys), out, sizeof(out), &len);
    if (status == PSA_SUCCESS && len != sizeof(out)) {
        status = PSA_ERROR_GENERIC_ERROR;
    }
    if (status == PSA_SUCCESS) {
        memcpy(data->ciphertext, out, sizeof(data->ciphertext));
        memcpy(data->tag, out + sizeof(data->ciphertext), TAG_SIZE);
    }
    mem_zeroize(out, sizeof(out));
    return status;
}

// On a failure `keys` is zeroed, so a wrong PIN leaves no plaintext.
static psa_status_t unseal(const key_storage_uids_t *uids, psa_key_id_t key,
                           const key_storage_data_t *data, magic_internet_key_t *keys)
{
    uint8_t aad[AAD_SIZE];
    uint8_t in[sizeof(data->ciphertext) + TAG_SIZE];
    size_t len = 0;

    make_aad(uids, aad);
    memcpy(in, data->ciphertext, sizeof(data->ciphertext));
    memcpy(in + sizeof(data->ciphertext), data->tag, TAG_SIZE);
    psa_status_t status = psa_aead_decrypt(key, PSA_ALG_GCM, data->iv, IV_SIZE, aad, AAD_SIZE, in,
                                           sizeof(in), (uint8_t *)keys, sizeof(*keys), &len);
    if (status == PSA_SUCCESS && len != sizeof(*keys)) {
        status = PSA_ERROR_DATA_INVALID;
    }
    if (status != PSA_SUCCESS) {
        mem_zeroize(keys, sizeof(*keys));
    }
    mem_zeroize(in, sizeof(in));
    return status;
}

// A record of the wrong size or format is not this app's wallet.
// It is PSA_ERROR_DATA_INVALID, never "no wallet here".
static psa_status_t load_ps_data(const key_storage_uids_t *uids, key_storage_data_t *data)
{
    // psa_ps_get() clamps to the object size, so a larger record still returns a full struct.
    // Only get_info() can refuse one.
    struct psa_storage_info_t info;
    psa_status_t status = psa_ps_get_info(uids->data, &info);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (info.size != sizeof(*data)) {
        return PSA_ERROR_DATA_INVALID;
    }

    size_t bytes_read = 0;
    status = psa_ps_get(uids->data, 0, sizeof(*data), data, &bytes_read);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (bytes_read != sizeof(*data) || data->format != FORMAT_VERSION) {
        return PSA_ERROR_DATA_INVALID;
    }
    return PSA_SUCCESS;
}

static psa_status_t store_ps_data(const key_storage_uids_t *uids, const key_storage_data_t *data)
{
    return psa_ps_set(uids->data, sizeof(*data), data, PSA_STORAGE_FLAG_NONE);
}

// PSA_SUCCESS only when PS holds `fail_count`, and it is still within the limit.
static psa_status_t counted(const key_storage_uids_t *uids, uint32_t fail_count)
{
    key_storage_data_t again;
    psa_status_t status = load_ps_data(uids, &again);

    if (status == PSA_SUCCESS && (again.fail_count != fail_count || again.fail_count > MAX_FAILS)) {
        status = PSA_ERROR_STORAGE_FAILURE;
    }
    mem_zeroize(&again, sizeof(again));
    return status;
}

// Only key_storage_store() writes it, but a corrupt or foreign one shows up here first,
// and entropy_size goes to bip39 as a length.
static bool keys_are_sane(const magic_internet_key_t *keys)
{
    return keys->version == 1 && keys->entropy_size >= BITCOIN_ENTROPY_MIN_SIZE &&
           keys->entropy_size <= BITCOIN_ENTROPY_MAX_SIZE && (keys->entropy_size % 4) == 0;
}

psa_status_t key_storage_store(const key_storage_uids_t *uids, const magic_internet_key_t *keys,
                               const char *pin)
{
    if (!uids || !keys || !pin || pin[0] == '\0') {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    bool exists = false;
    psa_status_t status = key_storage_exists(uids, &exists);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (exists) {
        return PSA_ERROR_ALREADY_EXISTS;
    }

    key_storage_data_t data = {.format = FORMAT_VERSION, .fail_count = 0};
    psa_key_id_t key;

    status = psa_generate_random(data.salt, SALT_SIZE);
    if (status == PSA_SUCCESS) {
        status = psa_generate_random(data.iv, IV_SIZE);
    }
    if (status == PSA_SUCCESS) {
        status = pin_key(pin, data.salt, PSA_KEY_USAGE_ENCRYPT, &key);
    }
    if (status == PSA_SUCCESS) {
        status = seal(uids, key, keys, &data);
        psa_destroy_key(key);
    }
    // One write, so the wallet and the count that guards it cannot disagree.
    if (status == PSA_SUCCESS) {
        status = store_ps_data(uids, &data);
    }
    mem_zeroize(&data, sizeof(data));
    return status;
}

psa_status_t key_storage_load(const key_storage_uids_t *uids, const char *pin,
                              magic_internet_key_t *keys)
{
    if (!uids || !pin || !keys || pin[0] == '\0') {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_storage_data_t data;
    psa_key_id_t key;
    psa_status_t status = load_ps_data(uids, &data);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    // A record left at the limit by a power cut during a wipe still gets wiped.
    if (data.fail_count >= MAX_FAILS) {
        psa_ps_remove(uids->data);
        status = PSA_ERROR_NOT_PERMITTED;
        goto cleanup;
    }

    // Count first, check the PIN second.
    // With the count after the check,
    // a power cut between the two would drop the attempt and give unlimited guesses.
    data.fail_count++;
    // The limit again, so one skipped branch above gives no extra guess.
    // Volatile, or the compiler drops this check as always false.
    volatile uint32_t count = data.fail_count;
    if (count > MAX_FAILS || count == 0) {
        status = PSA_ERROR_NOT_PERMITTED;
        goto cleanup;
    }
    status = store_ps_data(uids, &data);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    // Read the count back, so a glitch on the store or on its status gives no free guess.
    // Volatile, so a skipped call cannot leave the PSA_SUCCESS of the store.
    volatile psa_status_t count_ok = PSA_ERROR_GENERIC_ERROR;
    count_ok = counted(uids, data.fail_count);
    if (count_ok != PSA_SUCCESS) {
        status = PSA_ERROR_STORAGE_FAILURE;
        goto cleanup;
    }

    status = pin_key(pin, data.salt, PSA_KEY_USAGE_DECRYPT, &key);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    status = unseal(uids, key, &data, keys);
    psa_destroy_key(key);

    if (status == PSA_SUCCESS) {
        if (!keys_are_sane(keys)) {
            mem_zeroize(keys, sizeof(*keys));
            status = PSA_ERROR_DATA_INVALID;
            goto cleanup;
        }
        // Not checked on purpose: a failure only leaves the attempt counted, the safe direction.
        // The PIN was right.
        data.fail_count = 0;
        (void)store_ps_data(uids, &data);
    } else if (status == PSA_ERROR_INVALID_SIGNATURE && data.fail_count >= MAX_FAILS) {
        psa_ps_remove(uids->data);
    }

cleanup:
    mem_zeroize(&data, sizeof(data));
    return status;
}

psa_status_t key_storage_get_attempts_remaining(const key_storage_uids_t *uids, uint32_t *out)
{
    if (!uids || !out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_storage_data_t data;
    psa_status_t status = load_ps_data(uids, &data);
    if (status == PSA_SUCCESS) {
        // A count past the limit is an interrupted wipe, not a negative number of tries.
        *out = data.fail_count < MAX_FAILS ? MAX_FAILS - data.fail_count : 0;
    }
    mem_zeroize(&data, sizeof(data));
    return status;
}

psa_status_t key_storage_exists(const key_storage_uids_t *uids, bool *exists)
{
    if (!uids || !exists) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_storage_data_t data;
    psa_status_t status = load_ps_data(uids, &data);
    mem_zeroize(&data, sizeof(data));

    if (status == PSA_ERROR_DOES_NOT_EXIST) {
        *exists = false;
        return PSA_SUCCESS;
    }
    if (status == PSA_SUCCESS) {
        *exists = true;
    }
    return status;
}

psa_status_t key_storage_wipe(const key_storage_uids_t *uids)
{
    if (!uids) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return psa_ps_remove(uids->data);
}

psa_status_t key_storage_wipe_unreadable(const key_storage_uids_t *uids)
{
    if (!uids) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // The format check is here, so no caller can skip it.
    key_storage_data_t data;
    psa_status_t status = load_ps_data(uids, &data);
    mem_zeroize(&data, sizeof(data));

    if (status == PSA_SUCCESS) {
        return PSA_ERROR_BAD_STATE;
    }
    if (status != PSA_ERROR_DATA_INVALID) {
        return status;
    }
    return psa_ps_remove(uids->data);
}
