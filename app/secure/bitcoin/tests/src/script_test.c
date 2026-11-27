// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "script.h"
#include "shared/test_util.h"
#include "sighash.h"
#include <string.h>

// The P2WPKH input from the BIP143 "Native P2WPKH" example.
static const uint8_t bip143_pubkey[BITCOIN_PUBKEY_SIZE] = {
    0x02, 0x54, 0x76, 0xc2, 0xe8, 0x31, 0x88, 0x36, 0x8d, 0xa1, 0xff,
    0x3e, 0x29, 0x2e, 0x7a, 0xca, 0xfc, 0xdb, 0x35, 0x66, 0xbb, 0x0a,
    0xd2, 0x53, 0xf6, 0x2f, 0xc7, 0x0f, 0x07, 0xae, 0xee, 0x63, 0x57,
};

static void test_p2wpkh_script_vector(void)
{
    static const uint8_t expected[SCRIPT_P2WPKH_SIZE] = {
        0x00, 0x14, 0x1d, 0x0f, 0x17, 0x2a, 0x0e, 0xcb, 0x48, 0xae, 0xe1,
        0xbe, 0x1f, 0x26, 0x87, 0xd2, 0x96, 0x3a, 0xe3, 0x3f, 0x71, 0xa1,
    };
    uint8_t script[SCRIPT_P2WPKH_SIZE];

    TEST_ASSERT_EQUAL(PSA_SUCCESS, script_p2wpkh_from_pubkey(bip143_pubkey, script));
    TEST_ASSERT_ARRAY_EQUAL(expected, script, sizeof(expected));
}

static void test_p2wpkh_script_code_vector(void)
{
    static const uint8_t expected[SCRIPT_CODE_P2WPKH_SIZE] = {
        0x76, 0xa9, 0x14, 0x1d, 0x0f, 0x17, 0x2a, 0x0e, 0xcb, 0x48, 0xae, 0xe1, 0xbe,
        0x1f, 0x26, 0x87, 0xd2, 0x96, 0x3a, 0xe3, 0x3f, 0x71, 0xa1, 0x88, 0xac,
    };
    uint8_t script_code[SCRIPT_CODE_P2WPKH_SIZE];

    TEST_ASSERT_EQUAL(PSA_SUCCESS, script_code_p2wpkh_from_pubkey(bip143_pubkey, script_code));
    TEST_ASSERT_ARRAY_EQUAL(expected, script_code, sizeof(expected));
}

static void test_script_builders_reject_bad_args(void)
{
    uint8_t script[SCRIPT_CODE_P2WPKH_SIZE];

    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, script_p2wpkh_from_pubkey(NULL, script));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, script_p2wpkh_from_pubkey(bip143_pubkey, NULL));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, script_code_p2wpkh_from_pubkey(NULL, script));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      script_code_p2wpkh_from_pubkey(bip143_pubkey, NULL));
}

// An uncompressed key hashes differently,
// so a script built from one cannot be spent with the key we hold.
static void test_uncompressed_pubkey_rejected(void)
{
    uint8_t uncompressed[BITCOIN_PUBKEY_SIZE];
    uint8_t script[SCRIPT_CODE_P2WPKH_SIZE];

    memcpy(uncompressed, bip143_pubkey, sizeof(uncompressed));
    uncompressed[0] = 0x04;

    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, script_p2wpkh_from_pubkey(uncompressed, script));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      script_code_p2wpkh_from_pubkey(uncompressed, script));
}

static void test_classify_kinds(void)
{
    static const uint8_t p2wpkh[SCRIPT_P2WPKH_SIZE] = {0x00, 0x14};
    static const uint8_t p2wsh[SCRIPT_P2WSH_SIZE] = {0x00, 0x20};
    static const uint8_t p2tr[SCRIPT_P2TR_SIZE] = {0x51, 0x20};

    TEST_ASSERT_EQUAL(SCRIPT_KIND_P2WPKH, script_classify(p2wpkh, sizeof(p2wpkh)));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_P2WSH, script_classify(p2wsh, sizeof(p2wsh)));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_P2TR, script_classify(p2tr, sizeof(p2tr)));

    // Right opcodes but wrong length,
    // and the two 34-byte forms must not be mixed up with each other.
    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(p2wpkh, SCRIPT_P2WPKH_SIZE - 1));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(p2wpkh, SCRIPT_P2WPKH_SIZE + 1));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(p2wsh, SCRIPT_P2WSH_SIZE - 1));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(p2wsh, SCRIPT_P2WSH_SIZE + 1));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(p2wsh, SCRIPT_P2WPKH_SIZE));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(p2tr, SCRIPT_P2WPKH_SIZE));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(p2wpkh, 0));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(NULL, sizeof(p2wpkh)));
}

static void test_classify_base58_kinds(void)
{
    uint8_t p2pkh[SCRIPT_P2PKH_SIZE + 1] = {0x76, 0xa9, 0x14};
    uint8_t p2sh[SCRIPT_P2SH_SIZE + 1] = {0xa9, 0x14};

    p2pkh[23] = 0x88;
    p2pkh[24] = 0xac;
    p2sh[22] = 0x87;

    TEST_ASSERT_EQUAL(SCRIPT_KIND_P2PKH, script_classify(p2pkh, SCRIPT_P2PKH_SIZE));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_P2SH, script_classify(p2sh, SCRIPT_P2SH_SIZE));

    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(p2pkh, SCRIPT_P2PKH_SIZE - 1));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(p2pkh, SCRIPT_P2PKH_SIZE + 1));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(p2sh, SCRIPT_P2SH_SIZE - 1));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(p2sh, SCRIPT_P2SH_SIZE + 1));

    // The last opcode is what makes it P2PKH or P2SH.
    p2pkh[24] = 0x87;
    p2sh[22] = 0x88;
    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(p2pkh, SCRIPT_P2PKH_SIZE));
    TEST_ASSERT_EQUAL(SCRIPT_KIND_UNKNOWN, script_classify(p2sh, SCRIPT_P2SH_SIZE));
}

// BIP173 test vectors
static void test_address_bip173_vectors(void)
{
    static const uint8_t p2wpkh[SCRIPT_P2WPKH_SIZE] = {
        0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
        0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
    };
    static const uint8_t p2wsh[SCRIPT_P2WSH_SIZE] = {
        0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04, 0xbd,
        0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d,
        0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62,
    };
    char address[BITCOIN_ADDRESS_MAX_SIZE];

    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      script_to_address(p2wpkh, sizeof(p2wpkh), 0, address, sizeof(address)));
    TEST_ASSERT_STR_EQUAL("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", address);

    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      script_to_address(p2wpkh, sizeof(p2wpkh), 1, address, sizeof(address)));
    TEST_ASSERT_STR_EQUAL("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", address);

    // Witness v0 stays bech32 even at 32 bytes.
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      script_to_address(p2wsh, sizeof(p2wsh), 1, address, sizeof(address)));
    TEST_ASSERT_STR_EQUAL("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
                          address);
}

// BIP350: witness v1 must use the bech32m constant.
static void test_address_p2tr_is_bech32m(void)
{
    static const uint8_t p2tr[SCRIPT_P2TR_SIZE] = {
        0x51, 0x20, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
        0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce,
        0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    };
    char address[BITCOIN_ADDRESS_MAX_SIZE];

    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      script_to_address(p2tr, sizeof(p2tr), 0, address, sizeof(address)));
    TEST_ASSERT_STR_EQUAL("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                          address);
}

// btclib gives these strings for the hash160 of the BIP173 vector key.
static void test_address_base58_vectors(void)
{
    static const uint8_t hash[20] = {
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
        0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
    };
    uint8_t p2pkh[SCRIPT_P2PKH_SIZE] = {0x76, 0xa9, 0x14};
    uint8_t p2sh[SCRIPT_P2SH_SIZE] = {0xa9, 0x14};
    char address[BITCOIN_ADDRESS_MAX_SIZE];

    memcpy(&p2pkh[3], hash, sizeof(hash));
    p2pkh[23] = 0x88;
    p2pkh[24] = 0xac;
    memcpy(&p2sh[2], hash, sizeof(hash));
    p2sh[22] = 0x87;

    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      script_to_address(p2pkh, sizeof(p2pkh), 0, address, sizeof(address)));
    TEST_ASSERT_STR_EQUAL("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", address);
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      script_to_address(p2pkh, sizeof(p2pkh), 1, address, sizeof(address)));
    TEST_ASSERT_STR_EQUAL("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", address);
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      script_to_address(p2sh, sizeof(p2sh), 0, address, sizeof(address)));
    TEST_ASSERT_STR_EQUAL("3CNHUhP3uyB9EUtRLsmvFUmvGdjGdkTxJw", address);
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      script_to_address(p2sh, sizeof(p2sh), 1, address, sizeof(address)));
    TEST_ASSERT_STR_EQUAL("2N3vVYSK5XRgVSGWy21PnsRmBUywSQNdCsf", address);
}

static void test_address_unknown_refused(void)
{
    static const uint8_t op_return[] = {0x6a, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f};
    char address[BITCOIN_ADDRESS_MAX_SIZE];

    TEST_ASSERT_EQUAL(PSA_ERROR_NOT_SUPPORTED,
                      script_to_address(op_return, sizeof(op_return), 0, address, sizeof(address)));
}

static void test_address_small_buffer(void)
{
    static const uint8_t p2wpkh[SCRIPT_P2WPKH_SIZE] = {0x00, 0x14};
    static const uint8_t p2sh[SCRIPT_P2SH_SIZE] = {[0] = 0xa9, [1] = 0x14, [22] = 0x87};

    // A script we can classify needs room for the longest bech32 string.
    char address[BITCOIN_ADDRESS_MAX_SIZE];
    TEST_ASSERT_EQUAL(PSA_ERROR_BUFFER_TOO_SMALL,
                      script_to_address(p2wpkh, sizeof(p2wpkh), 0, address, 20));
    TEST_ASSERT_EQUAL(
        PSA_ERROR_BUFFER_TOO_SMALL,
        script_to_address(p2wpkh, sizeof(p2wpkh), 0, address, BITCOIN_ADDRESS_MAX_SIZE - 1));
    TEST_ASSERT_EQUAL(PSA_ERROR_BUFFER_TOO_SMALL,
                      script_to_address(p2sh, sizeof(p2sh), 0, address, 20));
}

static void fill_bip143_params(sighash_bip143_params_t *p, const uint8_t *hash32,
                               const uint8_t *script_code)
{
    p->version = 1;
    p->hash_prevouts = hash32;
    p->hash_sequence = hash32;
    p->txid = hash32;
    p->vout = 0;
    p->script_code = script_code;
    p->script_code_len = SCRIPT_CODE_P2WPKH_SIZE;
    p->amount = 1;
    p->sequence = 0xffffffff;
    p->hash_outputs = hash32;
    p->locktime = 0;
    p->sighash_type = BITCOIN_SIGHASH_ALL;
}

// Anything but a 25-byte P2WPKH scriptCode is a script type we do not sign.
// We must refuse it before building the preimage, not run out of room later.
static void test_sighash_rejects_bad_script_code_len(void)
{
    static const uint8_t hash32[32] = {0};
    static const uint8_t script_code[252] = {0};
    static const size_t bad_len[] = {0, 24, 26, 74, 252};
    sighash_bip143_params_t params;
    uint8_t digest[32];

    for (size_t i = 0; i < sizeof(bad_len) / sizeof(bad_len[0]); i++) {
        fill_bip143_params(&params, hash32, script_code);
        params.script_code_len = bad_len[i];
        TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, sighash_bip143(&params, digest));
    }

    fill_bip143_params(&params, hash32, script_code);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, sighash_bip143(&params, digest));
}

// The commitment hashes are the SIGHASH_ALL forms, so no other type may be signed.
static void test_sighash_rejects_other_types(void)
{
    static const uint8_t hash32[32] = {0};
    static const uint8_t script_code[SCRIPT_CODE_P2WPKH_SIZE] = {0};
    static const uint32_t bad_type[] = {0x00, 0x02, 0x03, 0x81, 0x101};
    sighash_bip143_params_t params;
    uint8_t digest[32];

    for (size_t i = 0; i < sizeof(bad_type) / sizeof(bad_type[0]); i++) {
        fill_bip143_params(&params, hash32, script_code);
        params.sighash_type = bad_type[i];
        TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, sighash_bip143(&params, digest));
    }
}

static void test_sighash_rejects_null_params(void)
{
    static const uint8_t hash32[32] = {0};
    static const uint8_t script_code[SCRIPT_CODE_P2WPKH_SIZE] = {0};
    sighash_bip143_params_t params;
    uint8_t digest[32];

    fill_bip143_params(&params, hash32, script_code);
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, sighash_bip143(NULL, digest));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, sighash_bip143(&params, NULL));

    const uint8_t **fields[] = {&params.hash_prevouts, &params.hash_sequence, &params.txid,
                                &params.script_code, &params.hash_outputs};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        fill_bip143_params(&params, hash32, script_code);
        *fields[i] = NULL;
        TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, sighash_bip143(&params, digest));
    }
}

void script_test_run_all(void)
{
    test_p2wpkh_script_vector();
    test_p2wpkh_script_code_vector();
    test_script_builders_reject_bad_args();
    test_uncompressed_pubkey_rejected();
    test_classify_kinds();
    test_classify_base58_kinds();
    test_address_bip173_vectors();
    test_address_p2tr_is_bech32m();
    test_address_base58_vectors();
    test_address_unknown_refused();
    test_address_small_buffer();
    test_sighash_rejects_bad_script_code_len();
    test_sighash_rejects_other_types();
    test_sighash_rejects_null_params();
}
