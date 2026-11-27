// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The wallet record in Protected Storage. What keeps the seed secret:
//
// - PS. PSA_STORAGE_FLAG_NONE asks it for confidentiality and replay protection.
//   PS encrypts every object under a key it derives from the HUK.
//   All device binding comes from there, because this partition cannot reach the HUK.
// - The PIN, which wraps the seed inside that object with AES-256-GCM.
//   It is the only secret input to the wrapping key, so each guess costs one PBKDF2-HMAC-SHA512.
//   Against an attacker who has both the flash and the PS key,
//   the fail count is the real limit, not the KDF.
//
// So the fail count is outside the AEAD: it must change on a wrong PIN, when no key can be derived.
// Only PS authenticates it.
// PS rollback protection uses NV counters in the tfm_otp_partition RRAM region, not fuses.
// An attacker who can write that region directly can restore an older count.
// An application RoT cannot reach any OTP counter.

#pragma once

#include <psa/crypto.h>
#include <psa/storage_common.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// BIP39 entropy: 12 to 24 words.
#define BITCOIN_ENTROPY_MIN_SIZE 16
#define BITCOIN_ENTROPY_MAX_SIZE 32

// The plaintext of the record. It is stored as it is, so a change to it is a format change.
typedef struct {
    uint32_t version;
    size_t entropy_size;
    uint8_t entropy[32];
    uint8_t reserved[128];
} magic_internet_key_t;

// Which PS record a call works on,
// so the self-tests use the real store without touching the user's wallet.
// One member only, because the fail count is in the record it guards.
typedef struct {
    psa_storage_uid_t data;
} key_storage_uids_t;

extern const key_storage_uids_t key_storage_uids_production;
extern const key_storage_uids_t key_storage_uids_test;

// Stores `keys` under `pin` in a new record. PSA_ERROR_ALREADY_EXISTS if there is one,
// and the error of key_storage_exists() if it cannot tell, so no store replaces a record.
psa_status_t key_storage_store(const key_storage_uids_t *uids, const magic_internet_key_t *keys,
                               const char *pin);

// Counts an attempt before it checks `pin`, and a right PIN resets the count.
// PSA_ERROR_INVALID_SIGNATURE for a wrong PIN, and the last one removes the record.
// PSA_ERROR_NOT_PERMITTED for a record already at the limit, which it removes too.
psa_status_t key_storage_load(const key_storage_uids_t *uids, const char *pin,
                              magic_internet_key_t *keys);

// Wrong PINs left before the record is removed. Only a right PIN resets it.
// There is no reset call, on purpose.
psa_status_t key_storage_get_attempts_remaining(const key_storage_uids_t *uids, uint32_t *out);

// `*exists` is false only for no record.
// PSA_ERROR_DATA_INVALID for a record this app cannot read (wrong size or format):
// it may be a real wallet in a newer format.
psa_status_t key_storage_exists(const key_storage_uids_t *uids, bool *exists);

psa_status_t key_storage_wipe(const key_storage_uids_t *uids);

// Removes the record only if it is unreadable.
// PSA_ERROR_BAD_STATE for a readable one,
// so no caller can remove a readable wallet without its PIN.
psa_status_t key_storage_wipe_unreadable(const key_storage_uids_t *uids);
