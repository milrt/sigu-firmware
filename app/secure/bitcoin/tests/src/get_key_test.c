// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// get_xpub and get_address on the test wallet, which is the BIP84 test vector mnemonic.
// So the keys and addresses below are the ones that spec publishes,
// not ones this code agreed with itself about.

#include "bitcoin/bitcoin_core.h"
#include "shared/test_util.h"
#include "test_wallet.h"
#include <string.h>

// That spec publishes the account key as a zpub.
// The strings below are the same payload under BIP32's version bytes,
// so they are still the published key.
#define ACCOUNT_XPUB                                                                               \
    "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZ" \
    "XYVUhLv1VMrjPC7PW6V"
#define ACCOUNT_TPUB                                                                               \
    "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQg" \
    "ewGiYZqrA9DsP4zbQ1M"

static void assert_xpub(wallet_session_t *w, const char *path, const char *expected)
{
    char xpub[BITCOIN_XPUB_MAX_SIZE];

    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_get_xpub(w, path, xpub, sizeof(xpub)));
    TEST_ASSERT_STR_EQUAL(expected, xpub);
}

static void rejects_xpub(wallet_session_t *w, const char *path, psa_status_t expected)
{
    char xpub[BITCOIN_XPUB_MAX_SIZE];

    TEST_ASSERT_EQUAL(expected, bitcoin_core_get_xpub(w, path, xpub, sizeof(xpub)));
}

static void assert_address(wallet_session_t *w, const char *path, const char *expected)
{
    char address[BITCOIN_ADDRESS_MAX_SIZE];

    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_get_address(w, path, address, sizeof(address)));
    TEST_ASSERT_STR_EQUAL(expected, address);
}

static void rejects_address(wallet_session_t *w, const char *path, psa_status_t expected)
{
    char address[BITCOIN_ADDRESS_MAX_SIZE];

    TEST_ASSERT_EQUAL(expected, bitcoin_core_get_address(w, path, address, sizeof(address)));
}

// The version bytes follow the path's coin type, so a caller cannot choose them,
// and an account key never comes back labeled for a network it was not derived under.
static void test_coin_type_selects_version(void)
{
    wallet_session_t *w = open_test_wallet();

    assert_xpub(w, "m/84'/0'/0'", ACCOUNT_XPUB);
    assert_xpub(w, "m/84'/1'/0'", ACCOUNT_TPUB);

    bitcoin_core_close(w);
}

static void test_bip84_vectors(void)
{
    wallet_session_t *w = open_test_wallet();

    assert_address(w, "m/84'/0'/0'/0/0", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert_address(w, "m/84'/0'/0'/0/1", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
    assert_address(w, "m/84'/0'/0'/1/0", "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");

    bitcoin_core_close(w);
}

// The HRP follows the path, not a network the caller gives us.
// script_test.c pins that mapping exactly. Here it only has to arrive.
static void test_coin_type_selects_hrp(void)
{
    wallet_session_t *w = open_test_wallet();
    char address[BITCOIN_ADDRESS_MAX_SIZE];

    psa_status_t status = bitcoin_core_get_address(w, "m/84'/1'/0'/0/0", address, sizeof(address));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, strncmp(address, "tb1q", 4));

    bitcoin_core_close(w);
}

// P2WPKH is the only script this partition spends from.
// A key or address under another purpose would end up in a descriptor this wallet cannot sign,
// or be one a user sends money to.
static void test_rejects_non_bip84_purpose(void)
{
    static const char *const purposes[] = {"m/44'", "m/49'", "m/86'",
                                           // Unhardened 84 is a different key.
                                           "m/84"};
    wallet_session_t *w = open_test_wallet();
    char path[32];

    for (size_t i = 0; i < sizeof(purposes) / sizeof(purposes[0]); i++) {
        strcpy(path, purposes[i]);
        strcat(path, "/0'/0'");
        rejects_xpub(w, path, PSA_ERROR_NOT_SUPPORTED);
        strcat(path, "/0/0");
        rejects_address(w, path, PSA_ERROR_NOT_SUPPORTED);
    }

    bitcoin_core_close(w);
}

// Only the two coin types we have version bytes and an HRP for.
static void test_rejects_unknown_coin_type(void)
{
    wallet_session_t *w = open_test_wallet();

    rejects_xpub(w, "m/84'/2'/0'", PSA_ERROR_NOT_SUPPORTED);
    rejects_address(w, "m/84'/2'/0'/0/0", PSA_ERROR_NOT_SUPPORTED);

    bitcoin_core_close(w);
}

// First no purpose, then no coin type. A key needs both before it names a network.
static void test_rejects_incomplete_path(void)
{
    static const struct {
        const char *path;
        psa_status_t status;
    } cases[] = {
        {"m", PSA_ERROR_DOES_NOT_EXIST},
        {"m/84'", PSA_ERROR_DOES_NOT_EXIST},
        {"not a path", PSA_ERROR_INVALID_ARGUMENT},
        {"m/84'/0'/", PSA_ERROR_INVALID_ARGUMENT},
    };
    wallet_session_t *w = open_test_wallet();

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rejects_xpub(w, cases[i].path, cases[i].status);
        rejects_address(w, cases[i].path, cases[i].status);
    }

    bitcoin_core_close(w);
}

static void test_requires_open_wallet(void)
{
    wallet_session_t *w = open_test_wallet();
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_close(w));

    rejects_xpub(w, "m/84'/0'/0'", PSA_ERROR_BAD_STATE);
    rejects_address(w, "m/84'/0'/0'/0/0", PSA_ERROR_BAD_STATE);
}

// Half an address is not an address, so a short buffer is an error, never a truncation.
static void test_rejects_short_buffer(void)
{
    wallet_session_t *w = open_test_wallet();
    char address[BITCOIN_ADDRESS_MAX_SIZE];

    TEST_ASSERT_EQUAL(PSA_ERROR_BUFFER_TOO_SMALL,
                      bitcoin_core_get_address(w, "m/84'/0'/0'/0/0", address, 20));

    bitcoin_core_close(w);
}

// The test session may only be seeded by open_ephemeral(),
// so a mnemonic from the test service cannot become a wallet that a key press approves.
static void test_temporary_refuses_test_session(void)
{
    wallet_session_t *w = bitcoin_core_session_test();

    bitcoin_core_close(w); // result ignored, it may not be open
    TEST_ASSERT_EQUAL(PSA_ERROR_NOT_PERMITTED, bitcoin_core_open_temporary(w, TEST_MNEMONIC, ""));
    TEST_ASSERT_FALSE(bitcoin_core_is_temporary(w));
}

void get_key_test_run_all(void)
{
    test_coin_type_selects_version();
    test_bip84_vectors();
    test_coin_type_selects_hrp();
    test_rejects_non_bip84_purpose();
    test_rejects_unknown_coin_type();
    test_rejects_incomplete_path();
    test_requires_open_wallet();
    test_rejects_short_buffer();
    test_temporary_refuses_test_session();
}
