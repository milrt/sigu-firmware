// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bip39.h"
#include "bip39_test_vectors.h"
#include "shared/test_util.h"
#include <psa/crypto.h>
#include <string.h>

static const uint8_t entropy_128[] = {0x0c, 0x1e, 0x24, 0xe5, 0x91, 0x77, 0x79, 0xd2,
                                      0x97, 0xe1, 0x4d, 0x45, 0xf1, 0x4e, 0x1a, 0x1a};
static const char mnemonic_128[] =
    "army van defense carry jealous true garbage claim echo media make crunch";

static void test_bip39_entropy_to_mnemonic(void)
{
    char mnemonic_out[256] = {0};

    psa_status_t status = bip39_entropy_to_mnemonic(entropy_128, sizeof(entropy_128), mnemonic_out,
                                                    sizeof(mnemonic_out));
    TEST_ASSERT_EQUAL(status, PSA_SUCCESS);
    TEST_ASSERT_STR_EQUAL(mnemonic_out, mnemonic_128);

    uint8_t invalid_entropy[10] = {0};
    status = bip39_entropy_to_mnemonic(invalid_entropy, sizeof(invalid_entropy), mnemonic_out,
                                       sizeof(mnemonic_out));
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);
}

static void test_bip39_validate_mnemonic(void)
{
    psa_status_t status = bip39_validate_mnemonic(mnemonic_128);
    TEST_ASSERT_EQUAL(status, PSA_SUCCESS);

    // A word that is not in the wordlist.
    const char *invalid_mnemonic =
        "army van defense carry jealous true garbage claim echo media make invalidword";
    status = bip39_validate_mnemonic(invalid_mnemonic);
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);

    // A wrong checksum.
    const char *invalid_checksum_mnemonic =
        "army van defense carry jealous true garbage claim echo media make crunches";
    status = bip39_validate_mnemonic(invalid_checksum_mnemonic);
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);
}

static void test_bip39_test_vectors(void)
{
    char mnemonic_out[256] = {0};
    uint8_t seed[BIP39_SEED_SIZE];
    uint8_t entropy_out[32];
    size_t entropy_out_size;

    for (size_t i = 0; i < BIP39_TEST_VECTOR_COUNT; i++) {
        const bip39_test_vector_t *vector = &bip39_test_vectors[i];

        psa_status_t status = bip39_entropy_to_mnemonic(vector->entropy, vector->entropy_size,
                                                        mnemonic_out, sizeof(mnemonic_out));
        TEST_ASSERT_EQUAL(status, PSA_SUCCESS);
        TEST_ASSERT_STR_EQUAL(mnemonic_out, vector->mnemonic);

        status = bip39_validate_mnemonic(vector->mnemonic);
        TEST_ASSERT_EQUAL(status, PSA_SUCCESS);

        // Round-trip back.
        // The table has 16, 24 and 32 byte entropy,
        // so this covers every size the wordlist packing must handle.
        entropy_out_size = sizeof(entropy_out);
        status = bip39_mnemonic_to_entropy(mnemonic_out, entropy_out, &entropy_out_size);
        TEST_ASSERT_EQUAL(status, PSA_SUCCESS);
        TEST_ASSERT_EQUAL(entropy_out_size, vector->entropy_size);
        TEST_ASSERT_ARRAY_EQUAL(entropy_out, vector->entropy, vector->entropy_size);

        status = bip39_mnemonic_to_seed(vector->mnemonic, "TREZOR", seed);
        TEST_ASSERT_EQUAL(status, PSA_SUCCESS);
        TEST_ASSERT_EQUAL(BIP39_SEED_SIZE, vector->seed_size);
        TEST_ASSERT_ARRAY_EQUAL(seed, vector->seed, vector->seed_size);
    }
}

// These differ from mnemonic_128 only in whitespace, so we assert the lengths below.
// An editor that trims them turns them back into the valid mnemonic.
static const char mnemonic_leading_space[] =
    " army van defense carry jealous true garbage claim echo media make crunch";
static const char mnemonic_trailing_space[] =
    "army van defense carry jealous true garbage claim echo media make crunch ";
static const char mnemonic_double_space[] =
    "army  van defense carry jealous true garbage claim echo media make crunch";

static void test_bip39_reject_malformed(void)
{
    // Before "abandon" and after "zoo".
    // The wordlist search must miss, and must not walk off either end.
    TEST_ASSERT_EQUAL(
        PSA_ERROR_INVALID_ARGUMENT,
        bip39_validate_mnemonic(
            "aardvark van defense carry jealous true garbage claim echo media make crunch"));
    TEST_ASSERT_EQUAL(
        PSA_ERROR_INVALID_ARGUMENT,
        bip39_validate_mnemonic(
            "zzzzz van defense carry jealous true garbage claim echo media make crunch"));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, bip39_validate_mnemonic(""));

    TEST_ASSERT_EQUAL(strlen(mnemonic_leading_space), strlen(mnemonic_128) + 1);
    TEST_ASSERT_EQUAL(strlen(mnemonic_trailing_space), strlen(mnemonic_128) + 1);
    TEST_ASSERT_EQUAL(strlen(mnemonic_double_space), strlen(mnemonic_128) + 1);
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, bip39_validate_mnemonic(mnemonic_leading_space));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, bip39_validate_mnemonic(mnemonic_trailing_space));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, bip39_validate_mnemonic(mnemonic_double_space));

    // 11, 13 and 25 words.
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      bip39_validate_mnemonic(
                          "army van defense carry jealous true garbage claim echo media make"));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      bip39_validate_mnemonic("army van defense carry jealous true garbage claim "
                                              "echo media make crunch abandon"));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      bip39_validate_mnemonic("abandon abandon abandon abandon abandon abandon "
                                              "abandon abandon abandon abandon abandon abandon "
                                              "abandon abandon abandon abandon abandon abandon "
                                              "abandon abandon abandon abandon abandon art "
                                              "abandon"));

    TEST_ASSERT_EQUAL(
        PSA_ERROR_INVALID_ARGUMENT,
        bip39_validate_mnemonic(
            "Army van defense carry jealous true garbage claim echo media make crunch"));

    // A mnemonic that parses but fails the checksum must not reach PBKDF2.
    uint8_t seed[BIP39_SEED_SIZE];
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      bip39_mnemonic_to_seed("army van defense carry jealous true garbage claim "
                                             "echo media make crunches",
                                             "", seed));
}

static void test_bip39_buffer_bounds(void)
{
    const size_t exact = strlen(mnemonic_128) + 1;
    char mnemonic_out[256] = {0};

    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip39_entropy_to_mnemonic(entropy_128, sizeof(entropy_128),
                                                             mnemonic_out, exact));
    TEST_ASSERT_STR_EQUAL(mnemonic_out, mnemonic_128);

    TEST_ASSERT_EQUAL(
        PSA_ERROR_BUFFER_TOO_SMALL,
        bip39_entropy_to_mnemonic(entropy_128, sizeof(entropy_128), mnemonic_out, exact - 1));
    TEST_ASSERT_EQUAL(
        PSA_ERROR_BUFFER_TOO_SMALL,
        bip39_entropy_to_mnemonic(entropy_128, sizeof(entropy_128), mnemonic_out, 10));

    uint8_t entropy_out[32];
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      bip39_mnemonic_to_entropy(mnemonic_128, entropy_out, NULL));

    // NULL and "" are the same empty passphrase, so they give the same seed.
    uint8_t seed_null[BIP39_SEED_SIZE];
    uint8_t seed_empty[BIP39_SEED_SIZE];
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip39_mnemonic_to_seed(mnemonic_128, NULL, seed_null));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip39_mnemonic_to_seed(mnemonic_128, "", seed_empty));
    TEST_ASSERT_ARRAY_EQUAL(seed_null, seed_empty, sizeof(seed_null));
}

void bip39_test_run_all(void)
{
    test_bip39_entropy_to_mnemonic();
    test_bip39_validate_mnemonic();
    test_bip39_test_vectors();
    test_bip39_reject_malformed();
    test_bip39_buffer_bounds();
}
