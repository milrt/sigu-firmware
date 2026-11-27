// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "key_storage.h"
#include "psa/crypto_types.h"
#include "psa/protected_storage.h"
#include "shared/test_util.h"
#include <psa/storage_common.h>
#include <string.h>

// These tests store a known blob under a known PIN and wipe it again,
// so they must never point at the production namespace.
#define TEST_UIDS (&key_storage_uids_test)

#define TEST_MAX_FAILS (10)

static magic_internet_key_t make_sample_keys(uint32_t version, const uint8_t *entropy,
                                             size_t entropy_len)
{
    magic_internet_key_t keys;
    memset(&keys, 0, sizeof(keys));
    keys.version = version;
    keys.entropy_size = entropy_len;
    if (entropy_len > sizeof(keys.entropy)) {
        entropy_len = sizeof(keys.entropy);
    }
    memcpy(keys.entropy, entropy, entropy_len);
    return keys;
}

// The blob must survive a real load,
// so it has to pass the checks after decryption: version 1 and a BIP39 entropy size.
static magic_internet_key_t make_valid_keys(uint8_t fill)
{
    uint8_t entropy[32];
    memset(entropy, fill, sizeof(entropy));
    return make_sample_keys(1, entropy, sizeof(entropy));
}

static void store_fresh(const magic_internet_key_t *keys, const char *pin)
{
    key_storage_wipe(TEST_UIDS);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, key_storage_store(TEST_UIDS, keys, pin));
}

// Counted as wrong PINs spent, not as tries left,
// because that is what each test below has just done.
static void assert_fails_used(uint32_t used)
{
    uint32_t attempts = 999;
    TEST_ASSERT_EQUAL(PSA_SUCCESS, key_storage_get_attempts_remaining(TEST_UIDS, &attempts));
    TEST_ASSERT_EQUAL(TEST_MAX_FAILS - used, attempts);
}

static void test_store_load_correct_pin(void)
{
    magic_internet_key_t keys_out = make_valid_keys(0xDE);
    const char *pin = "123456";
    store_fresh(&keys_out, pin);

    magic_internet_key_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    psa_status_t st = key_storage_load(TEST_UIDS, pin, &loaded);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, st);
    TEST_ASSERT_EQUAL(1, loaded.version);
    TEST_ASSERT_EQUAL(32, loaded.entropy_size);
    TEST_ASSERT_ARRAY_EQUAL(keys_out.entropy, loaded.entropy, 32);

    assert_fails_used(0);
}

static void test_load_wrong_pin(void)
{
    const char *correct_pin = "123456";
    const char *wrong_pin = "000000";
    magic_internet_key_t loaded;

    memset(&loaded, 0, sizeof(loaded));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_SIGNATURE, key_storage_load(TEST_UIDS, wrong_pin, &loaded));

    assert_fails_used(1);

    memset(&loaded, 0, sizeof(loaded));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, key_storage_load(TEST_UIDS, correct_pin, &loaded));

    assert_fails_used(0);
}

// The count must reach the disk before we know the result.
// Losing power on a wrong PIN must not give the attempt back.
static void test_fail_count_survives_interrupted_attempt(void)
{
    magic_internet_key_t keys_out = make_valid_keys(0x11);
    store_fresh(&keys_out, "123456");

    magic_internet_key_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_SIGNATURE, key_storage_load(TEST_UIDS, "wrong", &loaded));

    assert_fails_used(1);
}

static void test_correct_pin_is_the_only_reset(void)
{
    const char *pin = "asdfgh";
    magic_internet_key_t keys_out = make_valid_keys(0x99);
    store_fresh(&keys_out, pin);

    magic_internet_key_t loaded;
    for (int i = 0; i < 2; i++) {
        memset(&loaded, 0, sizeof(loaded));
        TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_SIGNATURE,
                          key_storage_load(TEST_UIDS, "nonsense", &loaded));
    }

    assert_fails_used(2);

    memset(&loaded, 0, sizeof(loaded));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, key_storage_load(TEST_UIDS, pin, &loaded));

    assert_fails_used(0);
}

// Passing the limit wipes the record.
// The slot must stay re-usable, or a device is bricked after one lockout.
static void test_lockout_wipes_and_frees_slot(void)
{
    const char *pin = "mypin";
    magic_internet_key_t keys_out = make_valid_keys(0xAA);
    store_fresh(&keys_out, pin);

    magic_internet_key_t loaded;
    for (uint32_t i = 0; i < TEST_MAX_FAILS; i++) {
        memset(&loaded, 0, sizeof(loaded));
        TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_SIGNATURE,
                          key_storage_load(TEST_UIDS, "wrong", &loaded));
        // The last attempt takes the record with it, so nothing is left to count down from.
        // A UI showing 0 would show a wallet that is already gone.
        if (i + 1 < TEST_MAX_FAILS) {
            assert_fails_used(i + 1);
        }
    }

    uint32_t attempts = 999;
    TEST_ASSERT_EQUAL(PSA_ERROR_DOES_NOT_EXIST,
                      key_storage_get_attempts_remaining(TEST_UIDS, &attempts));

    memset(&loaded, 0, sizeof(loaded));
    TEST_ASSERT_EQUAL(PSA_ERROR_DOES_NOT_EXIST, key_storage_load(TEST_UIDS, pin, &loaded));

    bool exists = true;
    TEST_ASSERT_EQUAL(PSA_SUCCESS, key_storage_exists(TEST_UIDS, &exists));
    TEST_ASSERT_FALSE(exists);

    magic_internet_key_t again = make_valid_keys(0xBB);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, key_storage_store(TEST_UIDS, &again, "newpin"));
}

static void test_store_rejects_existing(void)
{
    const char *pin = "123456";
    magic_internet_key_t keys_out = make_valid_keys(0xC1);
    store_fresh(&keys_out, pin);

    magic_internet_key_t other = make_valid_keys(0xC2);
    TEST_ASSERT_EQUAL(PSA_ERROR_ALREADY_EXISTS, key_storage_store(TEST_UIDS, &other, "different"));

    // The rejected store must not have changed the record or its lockout.
    magic_internet_key_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, key_storage_load(TEST_UIDS, pin, &loaded));
    TEST_ASSERT_ARRAY_EQUAL(keys_out.entropy, loaded.entropy, 32);

    assert_fails_used(0);
}

static void test_store_rejects_empty_pin(void)
{
    key_storage_wipe(TEST_UIDS);

    magic_internet_key_t keys_out = make_valid_keys(0xE0);
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, key_storage_store(TEST_UIDS, &keys_out, ""));

    bool exists = true;
    TEST_ASSERT_EQUAL(PSA_SUCCESS, key_storage_exists(TEST_UIDS, &exists));
    TEST_ASSERT_FALSE(exists);
}

// A rejected argument is not an attempt, so it must not cost a try.
static void test_load_rejects_empty_pin(void)
{
    magic_internet_key_t keys_out = make_valid_keys(0xE1);
    store_fresh(&keys_out, "123456");

    magic_internet_key_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, key_storage_load(TEST_UIDS, "", &loaded));

    assert_fails_used(0);
}

// A record this app cannot read may be a wallet in a newer format.
// It must not unlock, it must not cost a try, and nothing may store over it.
static void assert_unreadable_kept(const uint8_t *blob, size_t size)
{
    uint8_t now[256];
    size_t now_len = 0;
    struct psa_storage_info_t info;
    bool exists = false;
    uint32_t attempts = 0;
    magic_internet_key_t loaded;
    magic_internet_key_t other = make_valid_keys(0x0F);

    memset(&loaded, 0, sizeof(loaded));
    TEST_ASSERT_EQUAL(PSA_ERROR_DATA_INVALID, key_storage_exists(TEST_UIDS, &exists));
    TEST_ASSERT_EQUAL(PSA_ERROR_DATA_INVALID, key_storage_store(TEST_UIDS, &other, "654321"));
    TEST_ASSERT_EQUAL(PSA_ERROR_DATA_INVALID, key_storage_load(TEST_UIDS, "123456", &loaded));
    TEST_ASSERT_EQUAL(PSA_ERROR_DATA_INVALID,
                      key_storage_get_attempts_remaining(TEST_UIDS, &attempts));

    TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ps_get_info(TEST_UIDS->data, &info));
    TEST_ASSERT_EQUAL(size, info.size);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ps_get(TEST_UIDS->data, 0, size, now, &now_len));
    TEST_ASSERT_EQUAL(size, now_len);
    TEST_ASSERT(memcmp(now, blob, size) == 0, "unreadable record changed");
}

static void put_record(const uint8_t *blob, size_t size)
{
    TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ps_set(TEST_UIDS->data, size, blob, PSA_STORAGE_FLAG_NONE));
}

// One store only. Each PBKDF2 costs ~500 ms on the device,
// and the whole self-test is one partition call that must end before WDT31 fires.
// The readable case puts the stored bytes back.
static void test_unreadable_record(void)
{
    magic_internet_key_t keys_out = make_valid_keys(0xF0);
    struct psa_storage_info_t info;
    uint8_t real[256];
    uint8_t blob[256];
    size_t size = 0;
    bool exists = false;

    store_fresh(&keys_out, "123456");
    TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ps_get_info(TEST_UIDS->data, &info));
    TEST_ASSERT(info.size + 4 <= sizeof(real), "record larger than scratch");
    TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ps_get(TEST_UIDS->data, 0, info.size, real, &size));
    TEST_ASSERT_EQUAL(info.size, size);

    // The right size, a foreign format.
    const uint32_t bad_format = 0xDEADBEEFUL;
    memset(blob, 0, size);
    memcpy(blob, &bad_format, sizeof(bad_format));
    put_record(blob, size);
    assert_unreadable_kept(blob, size);

    // Our record with 4 more bytes. psa_ps_get() would still return a full struct.
    memcpy(blob, real, size);
    memset(blob + size, 0xA5, 4);
    put_record(blob, size + 4);
    assert_unreadable_kept(blob, size + 4);

    // A readable record is never removed without the PIN.
    put_record(real, size);
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, key_storage_wipe_unreadable(TEST_UIDS));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, key_storage_exists(TEST_UIDS, &exists));
    TEST_ASSERT_TRUE(exists);

    put_record(blob, size + 4);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, key_storage_wipe_unreadable(TEST_UIDS));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, key_storage_exists(TEST_UIDS, &exists));
    TEST_ASSERT_FALSE(exists);
    TEST_ASSERT_EQUAL(PSA_ERROR_DOES_NOT_EXIST, key_storage_wipe_unreadable(TEST_UIDS));
}

void key_storage_test_run_all(void)
{
    test_store_load_correct_pin();
    test_load_wrong_pin();
    test_fail_count_survives_interrupted_attempt();
    test_correct_pin_is_the_only_reset();
    test_lockout_wipes_and_frees_slot();
    test_store_rejects_existing();
    test_store_rejects_empty_pin();
    test_load_rejects_empty_pin();
    test_unreadable_record();
    key_storage_wipe(TEST_UIDS);
}
