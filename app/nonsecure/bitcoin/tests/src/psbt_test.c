// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../src/psbt_heap.h"
#include "bitcoin/bitcoin_client.h"
#include "bitcoin/psbt.h"
#include "bitcoin/psbt_result.h"
#include "bitcoin/psbt_signer.h"
#include "bitcoin/psbt_tx.h"
#include "shared/test_util.h"
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/base64.h>
#include <zephyr/sys/util.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(psbt_test);

static const char *psbt_base64 =
    "cHNidP8BAHECAAAAAQmRtjBtG4pseYo9aWA6Cjst0E5db1QhSAHBSovQGSk5AQAAAAD9////"
    "Apg6AAAAAAAAFgAUAhwwpCAd2VHnZbXafW/"
    "XWEH7pE9eDQAAAAAAABYAFGfHzVm5AeAEX4fdTMHZJTsp7hveVS4+AE8BBDWHzwMuRF/cgAAAAPxf6XMnS+a0/"
    "RiSUycEy0ViWsmgCXTApwTTC+jLPvCuA92ijp/"
    "z7HQvP2n4wSfUgxF8wHpvxvmq9vv6l7VFm6hPECSzBqZUAACAAQAAgAAAAIAAAQBxAgAAAAGQAc+"
    "Te355UKXIGBOKqY73StyP0fM22HfTSHmabnhMSQEAAAAA/f///wKIt6a4AAAAABYAFC+ZDeVXFudqnD5unvRE/"
    "0KdgpjE6kkAAAAAAAAWABRj6rseiCYoo9BQ9u8rupAw/r4X3UAuPgABAR/"
    "qSQAAAAAAABYAFGPqux6IJiij0FD27yu6kDD+vhfdAQMEAQAAACIGAi+NVo70FI76y2NOK7wqU1IAMfZ+"
    "fw9PPSwyaO248d6nGCSzBqZUAACAAQAAgAAAAIAAAAAAAAAAAAAAIgIDit7wwrlz/"
    "pHLR2CmBQkUgmtqorsaQxWTOnCrejidFiQYJLMGplQAAIABAACAAAAAgAEAAAAAAAAAAA==";

static const char expected_signed_psbt_b64[] =
    "cHNidP8BAHECAAAAAQmRtjBtG4pseYo9aWA6Cjst0E5db1QhSAHBSovQGSk5AQAAAAD9////"
    "Apg6AAAAAAAAFgAUAhwwpCAd2VHnZbXafW/XWEH7pE9eDQAAAAAAABYAFGfHzVm5AeAEX4fd"
    "TMHZJTsp7hveVS4+AE8BBDWHzwMuRF/cgAAAAPxf6XMnS+a0/RiSUycEy0ViWsmgCXTApwTT"
    "C+jLPvCuA92ijp/z7HQvP2n4wSfUgxF8wHpvxvmq9vv6l7VFm6hPECSzBqZUAACAAQAAgAAA"
    "AIAAAQBxAgAAAAGQAc+Te355UKXIGBOKqY73StyP0fM22HfTSHmabnhMSQEAAAAA/f///wKI"
    "t6a4AAAAABYAFC+ZDeVXFudqnD5unvRE/0KdgpjE6kkAAAAAAAAWABRj6rseiCYoo9BQ9u8r"
    "upAw/r4X3UAuPgABAR/qSQAAAAAAABYAFGPqux6IJiij0FD27yu6kDD+vhfdAQMEAQAAACIG"
    "Ai+NVo70FI76y2NOK7wqU1IAMfZ+fw9PPSwyaO248d6nGCSzBqZUAACAAQAAgAAAAIAAAAAA"
    "AAAAACICAi+NVo70FI76y2NOK7wqU1IAMfZ+fw9PPSwyaO248d6nRzBEAiAjhEP70ON9ZRRu"
    "t/X3650qfBIswfkTatUb8rBRfkfSaAIgcpr42du1SEXd3Ug/FipiUD0WBDIYgzR/iQnqh/9c"
    "m4gBAAAiAgOK3vDCuXP+kctHYKYFCRSCa2qiuxpDFZM6cKt6OJ0WJBgkswamVAAAgAEAAIAA"
    "AACAAQAAAAAAAAAA";

static uint8_t psbt_raw[4096];
static size_t psbt_raw_size = 0;

// The wallet the fixture PSBT was built for.
// Its BIP32 derivation records name this master fingerprint,
// so change detection and the expected addresses need exactly this mnemonic and passphrase.
#define TEST_MNEMONIC "guess nuclear width pave clap crumble rain dance nurse bind parrot yellow"
#define TEST_PASSPHRASE "sigzone"

// The one input that belongs to this wallet.
// Testnet coin type, so the partition renders "tb1" addresses in its summary.
#define TEST_INPUT_PATH "m/84'/1'/0'/0/0"

// Seeds the test wallet in RAM from the mnemonic above, in place of any open one.
// No UID is read, written or wiped, so no wallet on the device is touched.
static void open_wallet(void)
{
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      bitcoin_client_test_open_ephemeral(TEST_MNEMONIC, TEST_PASSPHRASE));
}

static void test_serialize_deserialize()
{
    psbt_t psbt = {0};
    psbt_result_t result = psbt_create_from_bin(&psbt, psbt_raw, psbt_raw_size);
    TEST_ASSERT_EQUAL(PSBT_OK, result);

    uint8_t psbt_raw_deserialized[4096];
    size_t psbt_raw__deserialized_size = sizeof(psbt_raw_deserialized);
    result = psbt_to_bin(&psbt, psbt_raw_deserialized, &psbt_raw__deserialized_size);
    TEST_ASSERT_EQUAL(PSBT_OK, result);

    char psbt_base64_deserialized[4096 * 2];
    size_t psbt_base64_len_deserialized;
    int res = base64_encode((uint8_t *)psbt_base64_deserialized, sizeof(psbt_base64_deserialized),
                            &psbt_base64_len_deserialized, psbt_raw_deserialized,
                            psbt_raw__deserialized_size);
    TEST_ASSERT_EQUAL(0, res);

    TEST_ASSERT_STR_EQUAL(psbt_base64, psbt_base64_deserialized);
    psbt_free(&psbt);
}

// psbt_sign() calls this once, while the session waits for the user.
// That is where the test service's programmatic approval replaces the button press.
static void approve_on_wait(void)
{
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_client_test_approve());
}

// Drives psbt_sign() end to end against the test wallet.
//
// The approve key itself cannot be covered here. That stays a manual check:
// run `bitcoin psbt_sign`, page to the total on the panel, press approve.
static void test_signer(void)
{
    open_wallet();

    psbt_t psbt = {0};
    TEST_ASSERT_EQUAL(PSBT_OK, psbt_create_from_bin(&psbt, psbt_raw, psbt_raw_size));

    TEST_ASSERT_EQUAL(PSBT_OK, psbt_sign(&psbt, &bitcoin_service_test, approve_on_wait));

    // The fixture has exactly one input and it is ours, so it must have gained a partial signature.
    TEST_ASSERT_EQUAL(1, psbt.num_inputs);
    psbt_kv_t *partial_sig = psbt_find_kv(&psbt.inputs[0], PSBT_IN_PARTIAL_SIG);
    TEST_ASSERT_NOT_NULL(partial_sig);

    // The key of a PSBT_IN_PARTIAL_SIG record is the compressed pubkey that signed.
    // It must be the key at the input's own derivation path, not just any key of ours.
    // Otherwise the signature sits on a record that claims something the partition never did.
    // The fixture names that key in its PSBT_IN_BIP32_DERIVATION record.
    psbt_kv_t *deriv = psbt_find_kv(&psbt.inputs[0], PSBT_IN_BIP32_DERIVATION);
    TEST_ASSERT_NOT_NULL(deriv);
    TEST_ASSERT_EQUAL(BITCOIN_PUBKEY_SIZE, partial_sig->key_data_len);
    TEST_ASSERT_EQUAL(BITCOIN_PUBKEY_SIZE, deriv->key_data_len);
    TEST_ASSERT_ARRAY_EQUAL(deriv->key_data, partial_sig->key_data, BITCOIN_PUBKEY_SIZE);

    // A DER signature with the sighash type appended.
    // It must be the type the PSBT asked for, which is the only type the partition signs.
    TEST_ASSERT_TRUE(partial_sig->value_data_len >= 9);
    TEST_ASSERT_TRUE(partial_sig->value_data_len <= BITCOIN_SIGNATURE_MAX_SIZE + 1);
    TEST_ASSERT_EQUAL(0x30, partial_sig->value_data[0]);
    TEST_ASSERT_EQUAL(BITCOIN_SIGHASH_ALL,
                      partial_sig->value_data[partial_sig->value_data_len - 1]);

    // The signed PSBT must still serialize.
    uint8_t signed_raw[4096];
    size_t signed_raw_size = sizeof(signed_raw);
    TEST_ASSERT_EQUAL(PSBT_OK, psbt_to_bin(&psbt, signed_raw, &signed_raw_size));

    char b64[4096 * 2];
    size_t b64_len;
    TEST_ASSERT_EQUAL(
        0, base64_encode((uint8_t *)b64, sizeof(b64), &b64_len, signed_raw, signed_raw_size));

    // Deterministic. secp256k1_ecdsa_sign() with a NULL nonce function is RFC6979,
    // and the randomized context only blinds the multiplication.
    // So this string is the same across runs and reboots, and we can pin it.
    TEST_ASSERT_STR_EQUAL(expected_signed_psbt_b64, b64);

    psbt_free(&psbt);
}

static void init()
{
    int res = base64_decode(psbt_raw, sizeof(psbt_raw), &psbt_raw_size,
                            (const uint8_t *)psbt_base64, strlen(psbt_base64));
    TEST_ASSERT_EQUAL(0, res);
}

// The record counts come from a compactsize and are multiplied by the record size,
// which k_heap_alloc truncates to size_t.
// A count picked so the product wraps gave a small buffer, and a fill loop that wrote past it.
static void test_malformed_tx_counts(void)
{
    // Input count 0x0CCCCCCD, with five well formed 41 byte inputs behind it.
    // Times the record size, the count wrapped to a few bytes, and the old code wrote five records.
    static const uint8_t bad_inputs[4 + 5 + 41 * 5] = {0x02, 0x00, 0x00, 0x00, 0xFE,
                                                       0xCD, 0xCC, 0xCC, 0x0C};

    // One input, then output count 0x10000001, which wrapped the same way.
    static const uint8_t bad_outputs[96] = {
        [0] = 0x02, [4] = 0x01, [46] = 0xFE, [47] = 0x01, [50] = 0x10};

    // The segwit marker and flag, one input, one output,
    // then a witness count of 8 with only two items behind it.
    // BIP174 has no witnesses in the unsigned tx, so the marker is refused.
    static const uint8_t short_witness[61] = {
        [0] = 0x02, [5] = 0x01, [6] = 0x01, [48] = 0x01, [58] = 0x08};

    static const struct {
        const uint8_t *data;
        size_t len;
    } cases[] = {
        {bad_inputs, sizeof(bad_inputs)},
        {bad_outputs, sizeof(bad_outputs)},
        {short_witness, sizeof(short_witness)},
    };

    // Twice each. The second run fails the same way only if the first gave its memory back.
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        for (int pass = 0; pass < 2; pass++) {
            psbt_tx_t tx;
            TEST_ASSERT_EQUAL(PSBT_READ_ERROR,
                              psbt_tx_create_from_bin(&tx, cases[i].data, cases[i].len));
        }
    }
}

// psbt_create_from_bin rejects this after parse_map has already put records in the global map.
// Without the psbt_free calls every attempt leaked them into an 8192 byte pool.
static void test_malformed_psbt_frees_pool(void)
{
    // Magic, one record with an unknown key type, separator. No PSBT_GLOBAL_UNSIGNED_TX.
    static const uint8_t no_unsigned_tx[] = {0x70, 0x73, 0x62, 0x74, 0xFF, 0x01, 0x99,
                                             0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x00};

    bool all_rejected = true;
    for (int i = 0; i < 300 && all_rejected; i++) {
        psbt_t psbt = {0};
        all_rejected =
            psbt_create_from_bin(&psbt, no_unsigned_tx, sizeof(no_unsigned_tx)) == PSBT_READ_ERROR;
    }
    TEST_ASSERT_TRUE(all_rejected);
}

// k_heap does not clear memory. This leaves a bad pointer in every free block,
// as an earlier user of the pool could, so an uninitialized map is not an empty list by luck.
static void dirty_pool(void)
{
    static void *blocks[64];
    size_t n = 0;

    while (n < ARRAY_SIZE(blocks) && (blocks[n] = k_heap_alloc(&psbt_heap, 128, K_NO_WAIT))) {
        memset(blocks[n], 0xA5, 128);
        n++;
    }
    while (n > 0) {
        k_heap_free(&psbt_heap, blocks[--n]);
    }
}

// Found by sim/fuzz/fuzz_psbt. Two bugs, and each cut of the example PSBT hits one of them:
// - parse_map took the end of the data for the 0x00 that ends a map.
//   A cut PSBT parsed, and the maps after the cut came out empty.
// - With that fixed, a cut inside output map 0 fails there.
//   psbt_free then walked output map 1, which nobody had initialized yet,
//   and freed the pointers it found in it.
static void test_truncated_psbt(void)
{
    bool all_rejected = true;

    for (size_t len = 0; len < psbt_raw_size && all_rejected; len++) {
        psbt_t psbt;

        dirty_pool();
        if (psbt_create_from_bin(&psbt, psbt_raw, len) == PSBT_OK) {
            psbt_free(&psbt);
            all_rejected = false;
        }
    }
    TEST_ASSERT_TRUE(all_rejected);
}

// Found by sim/fuzz/fuzz_psbt.
// compactsize_read checked the bytes after a 0xFD header,
// against a count that still held the header, so it read one byte past the end.
// Then *remaining wrapped to SIZE_MAX, and every later bounds check passed.
// The 0xFF after the cut makes the old code read a canonical 0xFFFF.
// It then fails later, on the heap, with PSBT_OOB_WRITE.
static void test_compactsize_at_end(void)
{
    static const uint8_t buf[] = {0x70, 0x73, 0x62, 0x74, 0xFF, 0xFD, 0xFF, 0xFF};
    psbt_t psbt;

    TEST_ASSERT_EQUAL(PSBT_READ_ERROR, psbt_create_from_bin(&psbt, buf, sizeof(buf) - 1));
}

// Found by sim/fuzz/fuzz_psbt. psbt_tx set num_inputs before it allocated the array.
// With the pool full, the array was NULL and psbt_tx_free walked num_inputs entries of it.
static void test_tx_full_pool(void)
{
    // Two zeroed inputs and no outputs: enough bytes for the input count check.
    static const uint8_t two_inputs[4 + 1 + 41 * 2 + 1 + 4] = {[4] = 0x02};
    static void *blocks[256];
    static const size_t sizes[] = {256, 64, 8};
    size_t n = 0;
    psbt_tx_t tx;

    // Big blocks first, then small ones, until not even a small one fits.
    for (size_t s = 0; s < ARRAY_SIZE(sizes); s++) {
        while (n < ARRAY_SIZE(blocks) &&
               (blocks[n] = k_heap_alloc(&psbt_heap, sizes[s], K_NO_WAIT))) {
            n++;
        }
    }
    TEST_ASSERT_TRUE(n < ARRAY_SIZE(blocks));

    psbt_result_t res = psbt_tx_create_from_bin(&tx, two_inputs, sizeof(two_inputs));

    while (n > 0) {
        k_heap_free(&psbt_heap, blocks[--n]);
    }
    TEST_ASSERT_EQUAL(PSBT_READ_ERROR, res);
}

void psbt_test_run_all(void)
{
    init();

    // These all run: the test service has no opcode that reaches Protected Storage,
    // so no wallet on the device is at risk.
    test_serialize_deserialize();
    test_signer();
    test_malformed_tx_counts();
    test_malformed_psbt_frees_pool();
    test_truncated_psbt();
    test_compactsize_at_end();
    test_tx_full_pool();
}
