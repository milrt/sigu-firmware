// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bip32.h"
#include "bip32_test_vectors.h"
#include "psa/crypto_types.h"
#include "shared/test_util.h"
#include <stdbool.h>
#include <string.h>
#include "tfm_log.h"

// Vector 1 master.
#define VEC_MASTER (&bip32_test_vectors[0])

static void make_master(bip32_extended_privkey_t *key)
{
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      bip32_seed_to_master_privkey(VEC_MASTER->seed, VEC_MASTER->seed_size, key));
}

static bool key_equal(const bip32_extended_privkey_t *a, const bip32_extended_privkey_t *b)
{
    return memcmp(a->private_key, b->private_key, 32) == 0 &&
           memcmp(a->chain_code, b->chain_code, 32) == 0 && a->depth == b->depth &&
           a->child_number == b->child_number &&
           memcmp(a->parent_fingerprint, b->parent_fingerprint, BIP32_FINGERPRINT_SIZE) == 0;
}

static bool all_zero(const void *buf, size_t len)
{
    const uint8_t *p = buf;
    for (size_t i = 0; i < len; i++) {
        if (p[i] != 0) {
            return false;
        }
    }
    return true;
}

static void test_valid_vectors(void)
{
    for (size_t i = 0; i < BIP32_TEST_VECTOR_COUNT; i++) {
        const bip32_test_vector_t *vec = &bip32_test_vectors[i];

        bip32_extended_privkey_t key;
        TEST_ASSERT_EQUAL(PSA_SUCCESS,
                          bip32_seed_to_master_privkey(vec->seed, vec->seed_size, &key));

        TEST_ASSERT_EQUAL(PSA_SUCCESS,
                          bip32_extended_privkey_derive_from_path(&key, vec->path, &key));

        bip32_extended_pubkey_t pubkey;
        TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_extended_pubkey_from_privkey(&key, &pubkey));

        char serialized[BIP32_MAX_SERIALIZED_SIZE];
        size_t serialized_size = sizeof(serialized);
        TEST_ASSERT_EQUAL(PSA_SUCCESS,
                          bip32_extended_pubkey_serialize(&pubkey, BIP32_MAINNET_PUB_VERSION,
                                                          serialized, &serialized_size));
        TEST_ASSERT_STR_EQUAL(serialized, vec->xpub);
    }
}

static void test_path_parsing(void)
{
    static const struct {
        const char *path;
        bool valid;
    } cases[] = {
        {"m", true},
        {"m/0", true},
        {"m/0'", true},
        {"m/0h", true},
        {"m/0H", true},
        {"m/0/1", true},
        {"m/2147483647", true},
        {"m/2147483647'", true},
        // Leading zeros are the only accepted alias. "m/00" is index 0.
        {"m/00", true},
        {"m/0/1/2/3/4/5/6/7/8/9", true}, // BIP32_MAX_DEPTH

        {"m/", false},
        {"m/0/", false},
        {"m/0//1", false},
        {"", false},
        {"0/1", false},
        {"m/2147483648", false},
        {"m/99999999999999999999", false},
        {"m/h", false},
        {"m/'", false},
        {"m/-0", false},
        {"m/+0", false},
        {"m/ 0", false},
        {"m/0x1", false},
        {"M/0", false},
        {"m/0/1/2/3/4/5/6/7/8/9/10", false}, // one past BIP32_MAX_DEPTH

        // A component must end at '/' or NUL.
        {"m/0'foo", false},
        {"m/0h1", false},
        {"m/0'1", false},
        {"m/0''", false},
        {"m/0X", false},
        {"m/0 ", false},
        {"m0", false},
        {"mm/0", false},
    };

    bip32_extended_privkey_t master;
    make_master(&master);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bip32_extended_privkey_t out;
        psa_status_t status = bip32_extended_privkey_derive_from_path(&master, cases[i].path, &out);
        if ((status == PSA_SUCCESS) != cases[i].valid) {
            ERROR("path \"%s\": unexpected status %d\n", cases[i].path, status);
        }
        TEST_ASSERT_EQUAL(cases[i].valid, status == PSA_SUCCESS);
    }

    // "m" gives a copy of the key it is applied to.
    bip32_extended_privkey_t copy;
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_extended_privkey_derive_from_path(&master, "m", &copy));
    TEST_ASSERT_TRUE(key_equal(&master, &copy));

    // ' h and H all mean hardened.
    bip32_extended_privkey_t tick, lower, upper;
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_extended_privkey_derive_from_path(&master, "m/0'", &tick));
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      bip32_extended_privkey_derive_from_path(&master, "m/0h", &lower));
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      bip32_extended_privkey_derive_from_path(&master, "m/0H", &upper));
    TEST_ASSERT_TRUE(key_equal(&tick, &lower));
    TEST_ASSERT_TRUE(key_equal(&tick, &upper));

    // "m/00" is index 0, not a second component.
    bip32_extended_privkey_t zero_index, padded_index;
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      bip32_extended_privkey_derive_from_path(&master, "m/0", &zero_index));
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      bip32_extended_privkey_derive_from_path(&master, "m/00", &padded_index));
    TEST_ASSERT_TRUE(key_equal(&zero_index, &padded_index));
}

static void test_output_zeroized_on_failure(void)
{
    bip32_extended_privkey_t master;
    make_master(&master);

    bip32_extended_privkey_t out;

    // Parse failure.
    memset(&out, 0xAA, sizeof(out));
    TEST_ASSERT_NOT_EQUAL(PSA_SUCCESS,
                          bip32_extended_privkey_derive_from_path(&master, "m/0/", &out));
    TEST_ASSERT_TRUE(all_zero(&out, sizeof(out)));

    // Derive failure, the parent is at the depth limit.
    bip32_extended_privkey_t deep = master;
    deep.depth = 255;
    memset(&out, 0xAA, sizeof(out));
    TEST_ASSERT_NOT_EQUAL(PSA_SUCCESS, bip32_extended_privkey_derive_from_path(&deep, "m/0", &out));
    TEST_ASSERT_TRUE(all_zero(&out, sizeof(out)));
}

// The other half of test_output_zeroized_on_failure.
// When in and out are the same struct, the "output" we would wipe is the caller's own key.
static void test_aliased_failure_preserves_input(void)
{
    bip32_extended_privkey_t key, copy;
    make_master(&key);
    make_master(&copy);

    TEST_ASSERT_NOT_EQUAL(PSA_SUCCESS, bip32_extended_privkey_derive_from_path(&key, "m/0/", &key));
    TEST_ASSERT_TRUE(key_equal(&key, &copy));

    TEST_ASSERT_NOT_EQUAL(PSA_SUCCESS,
                          bip32_extended_privkey_derive_from_path(&key, "m/0'foo", &key));
    TEST_ASSERT_TRUE(key_equal(&key, &copy));

    // Derive failure, not just a parse failure.
    key.depth = 255;
    copy.depth = 255;
    TEST_ASSERT_NOT_EQUAL(PSA_SUCCESS, bip32_extended_privkey_derive_from_path(&key, "m/0", &key));
    TEST_ASSERT_TRUE(key_equal(&key, &copy));
}

static void test_relative_derivation(void)
{
    bip32_extended_privkey_t master, absolute, step, relative;
    make_master(&master);

    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      bip32_extended_privkey_derive_from_path(&master, "m/0'/1", &absolute));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_extended_privkey_derive_from_path(&master, "m/0'", &step));
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      bip32_extended_privkey_derive_from_path(&step, "m/1", &relative));
    TEST_ASSERT_TRUE(key_equal(&absolute, &relative));
}

static void test_depth_overflow(void)
{
    bip32_extended_privkey_t master, out;
    make_master(&master);

    bip32_extended_privkey_t deep = master;
    deep.depth = 255;

    TEST_ASSERT_NOT_EQUAL(PSA_SUCCESS, bip32_extended_privkey_derive_from_path(&deep, "m/0", &out));

    // "m" derives nothing, so it still works.
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_extended_privkey_derive_from_path(&deep, "m", &out));
    TEST_ASSERT_EQUAL(255, out.depth);
}

static void test_master_fingerprint_and_index(void)
{
    bip32_extended_privkey_t master;
    make_master(&master);

    uint8_t zero_fpr[BIP32_FINGERPRINT_SIZE] = {0};
    TEST_ASSERT_EQUAL(0, master.depth);
    TEST_ASSERT_EQUAL(0, master.child_number);
    TEST_ASSERT_ARRAY_EQUAL(master.parent_fingerprint, zero_fpr, BIP32_FINGERPRINT_SIZE);

    bip32_extended_privkey_t child;
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      bip32_extended_privkey_derive_from_path(&master, "m/0'", &child));
    TEST_ASSERT_EQUAL(1, child.depth);
    TEST_ASSERT_EQUAL(0x80000000u, child.child_number);

    // The child's parent fingerprint is HASH160(compressed master pubkey)[0..4].
    bip32_extended_pubkey_t master_pub;
    uint8_t fingerprint[BIP32_FINGERPRINT_SIZE];
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_extended_pubkey_from_privkey(&master, &master_pub));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_extended_pubkey_get_fingerprint(&master_pub, fingerprint));
    TEST_ASSERT_ARRAY_EQUAL(child.parent_fingerprint, fingerprint, BIP32_FINGERPRINT_SIZE);
}

static void test_seed_bounds(void)
{
    uint8_t seed[65] = {0};
    bip32_extended_privkey_t key;

    TEST_ASSERT_NOT_EQUAL(PSA_SUCCESS, bip32_seed_to_master_privkey(seed, 15, &key));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_seed_to_master_privkey(seed, 16, &key));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_seed_to_master_privkey(seed, 64, &key));
    TEST_ASSERT_NOT_EQUAL(PSA_SUCCESS, bip32_seed_to_master_privkey(seed, 65, &key));
    TEST_ASSERT_NOT_EQUAL(PSA_SUCCESS, bip32_seed_to_master_privkey(seed, 0, &key));
    TEST_ASSERT_NOT_EQUAL(PSA_SUCCESS, bip32_seed_to_master_privkey(NULL, 32, &key));
}

// The tx session decides what counts as change from this shape alone.
static void test_bip84_path_shape(void)
{
    static const struct {
        const char *path;
        psa_status_t status;
    } cases[] = {
        {"m/84'/1'/2'/1/7", PSA_SUCCESS},
        {"m/84h/0h/0h/0/0", PSA_SUCCESS},
        {"m/84'/1'/2'/1", PSA_ERROR_NOT_SUPPORTED},
        {"m/84'/1'/2'/1/7/0", PSA_ERROR_NOT_SUPPORTED},
        {"m/84/1'/2'/1/7", PSA_ERROR_NOT_SUPPORTED},
        {"m/44'/1'/2'/1/7", PSA_ERROR_NOT_SUPPORTED},
        {"m/84'/1/2'/1/7", PSA_ERROR_NOT_SUPPORTED},
        {"m/84'/1'/2/1/7", PSA_ERROR_NOT_SUPPORTED},
        {"m/84'/1'/2'/1'/7", PSA_ERROR_NOT_SUPPORTED},
        {"m/84'/1'/2'/1/7'", PSA_ERROR_NOT_SUPPORTED},
        {"m/84'/1'/2'/1/x", PSA_ERROR_INVALID_ARGUMENT},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bip32_bip84_path_t p;
        psa_status_t status = bip32_path_bip84(cases[i].path, &p);
        if (status != cases[i].status) {
            ERROR("bip84 path \"%s\": unexpected status %d\n", cases[i].path, status);
        }
        TEST_ASSERT_EQUAL(cases[i].status, status);
    }

    bip32_bip84_path_t p;
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_path_bip84("m/84'/1'/2'/1/7", &p));
    TEST_ASSERT_EQUAL(1, p.coin_type);
    TEST_ASSERT_EQUAL(2, p.account);
    TEST_ASSERT_EQUAL(1, p.chain);
    TEST_ASSERT_EQUAL(7, p.index);
}

void bip32_test_run_all(void)
{
    test_bip84_path_shape();
    test_valid_vectors();
    test_path_parsing();
    test_output_zeroized_on_failure();
    test_aliased_failure_preserves_input();
    test_relative_derivation();
    test_depth_overflow();
    test_master_fingerprint_and_index();
    test_seed_bounds();
}
