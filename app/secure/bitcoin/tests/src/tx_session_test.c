// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/bitcoin_core.h"
#include "shared/hash.h"
#include "shared/test_util.h"
#include "shared/tx_records.h"
#include "shared/wire.h"
#include "bip39.h"
#include "sighash.h"
#include "test_wallet.h"
#include "tx_session.h"
#include <string.h>

// m/84'/1'/... is testnet, so addresses render with the "tb" HRP.
#define PATH_IN_0 "m/84'/1'/0'/0/0"
#define PATH_CHANGE "m/84'/1'/0'/1/0"

static void make_begin(bitcoin_tx_begin_t *begin, uint32_t n_in, uint32_t n_out,
                       uint32_t sighash_type)
{
    *begin = (bitcoin_tx_begin_t){
        .version = 2,
        .locktime = 0,
        .num_inputs = n_in,
        .num_outputs = n_out,
        .sighash_type = sighash_type,
    };
}

static void make_output(bitcoin_tx_output_t *out, uint64_t amount, const uint8_t *script,
                        uint8_t script_len)
{
    *out = (bitcoin_tx_output_t){.amount = amount, .script_len = script_len};
    memcpy(out->script, script, script_len);
}

// An arbitrary P2WPKH scriptPubKey that is not ours.
static const uint8_t foreign_script[22] = {0x00, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                           0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                                           0xFF, 0x01, 0x02, 0x03, 0x04, 0x05};

// A taproot output. We cannot sign it, but a transaction can pay to it.
// Its address is 62 characters, the case a 64-byte summary line used to truncate.
static const uint8_t taproot_script[34] = {0x51, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                                           0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                                           0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

// A minimal legacy previous tx: one input filled from `seed`, and one output of `amount` at vout 0.
// `txid` gets its double SHA256, as an outpoint names it.
#define PREV_TX_SIZE (4 + 1 + 41 + 1 + 8 + 1 + sizeof(foreign_script) + 4)
#define PREV_TX_AMOUNT_AT (4 + 1 + 41 + 1)

static void make_prev_tx(uint8_t buf[PREV_TX_SIZE], uint8_t seed, uint64_t amount, uint8_t *txid)
{
    uint8_t outpoint[36];
    wire_w w = wire_writer(buf, PREV_TX_SIZE);

    memset(outpoint, seed, sizeof(outpoint));
    wire_put_le32(&w, 2);
    wire_put_u8(&w, 1);
    wire_put_field(&w, outpoint, sizeof(outpoint), sizeof(outpoint));
    wire_put_u8(&w, 0); // empty scriptSig
    wire_put_le32(&w, 0xFFFFFFFF);
    wire_put_u8(&w, 1);
    wire_put_le64(&w, amount);
    wire_put_u8(&w, sizeof(foreign_script));
    wire_put_field(&w, foreign_script, sizeof(foreign_script), sizeof(foreign_script));
    wire_put_le32(&w, 0);
    TEST_ASSERT_TRUE(w.ok && w.pos == PREV_TX_SIZE);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, hash_double_sha256(buf, PREV_TX_SIZE, txid, BITCOIN_TXID_SIZE));
}

// Adds an input that spends output 0 of a prev tx made from `seed`.
static psa_status_t add_input(wallet_session_t *w, uint8_t seed, uint64_t amount, const char *path)
{
    uint8_t prev_tx[PREV_TX_SIZE];
    bitcoin_tx_input_t in = {.vout = 0, .sequence = 0xFFFFFFFF};

    make_prev_tx(prev_tx, seed, amount, in.txid);
    return bitcoin_core_tx_input(w, &in, path, prev_tx, sizeof(prev_tx));
}

// Begins a tx of `n_in` inputs and one external output of `amount`.
static void begin_paying(wallet_session_t *w, uint32_t n_in, uint64_t amount)
{
    bitcoin_tx_begin_t begin;
    bitcoin_tx_output_t out;

    make_begin(&begin, n_in, 1, BITCOIN_SIGHASH_ALL);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_begin(w, &begin));
    make_output(&out, amount, foreign_script, sizeof(foreign_script));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_output(w, &out, ""));
}

// Drives a one-input one-output session to APPROVED.
// The payment is external, so we need no change script. The input path gives the network.
static void approve_one_input_tx(wallet_session_t *w)
{
    uint8_t tx_id[32];

    begin_paying(w, 1, 90000);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, add_input(w, 0xAB, 100000, PATH_IN_0));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_confirm(w, tx_id));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_approve_programmatic(w));
}

// The P2WPKH scriptPubKey of the test wallet's key at `path`.
// Derived here from the mnemonic, because get_xpub refuses some of the paths we need.
static void own_p2wpkh(const char *path, uint8_t script[22])
{
    uint8_t seed[BIP39_SEED_SIZE];
    bip32_extended_privkey_t master;
    bip32_extended_privkey_t key;
    bip32_extended_pubkey_t pub;
    uint8_t sha[32];

    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip39_mnemonic_to_seed(TEST_MNEMONIC, "", seed));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_seed_to_master_privkey(seed, sizeof(seed), &master));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_extended_privkey_derive_from_path(&master, path, &key));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_extended_pubkey_from_privkey(&key, &pub));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, hash_sha256(pub.pubkey, sizeof(pub.pubkey), sha, 32));
    script[0] = 0x00;
    script[1] = 0x14;
    TEST_ASSERT_EQUAL(PSA_SUCCESS, hash_ripemd160(sha, 32, &script[2], 20));
}

// Streams one external output, one change output to our key at `change_path`, and one input.
// Returns the confirm status and, on success, the amount row 0 says leaves the wallet.
static psa_status_t confirm_with_change(wallet_session_t *w, const char *change_path,
                                        const char *in_path, uint64_t *sent)
{
    bitcoin_tx_begin_t begin;
    bitcoin_tx_output_t out;
    bitcoin_tx_summary_t row;
    uint8_t script[22];
    uint8_t tx_id[32];

    make_begin(&begin, 1, 2, BITCOIN_SIGHASH_ALL);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_begin(w, &begin));
    make_output(&out, 10000, foreign_script, sizeof(foreign_script));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_output(w, &out, ""));
    own_p2wpkh(change_path, script);
    make_output(&out, 85000, script, sizeof(script));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_output(w, &out, change_path));

    psa_status_t status = add_input(w, 0xAB, 100000, in_path);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = bitcoin_core_tx_confirm(w, tx_id);
    if (status != PSA_SUCCESS) {
        return status;
    }
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_summary(w, 0, &row));
    *sent = row.amount;
    return PSA_SUCCESS;
}

// An external payment of 10000, change of 85000 at PATH_CHANGE, and one input of 100000.
static void stream_change_tx(wallet_session_t *w)
{
    bitcoin_tx_begin_t begin;
    bitcoin_tx_output_t out;
    uint8_t change_script[22];

    make_begin(&begin, 1, 2, BITCOIN_SIGHASH_ALL);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_begin(w, &begin));
    make_output(&out, 10000, foreign_script, sizeof(foreign_script));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_output(w, &out, ""));
    own_p2wpkh(PATH_CHANGE, change_script);
    make_output(&out, 85000, change_script, sizeof(change_script));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_output(w, &out, PATH_CHANGE));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, add_input(w, 0xAB, 100000, PATH_IN_0));
}

// Drives a one-input two-output transaction all the way to a signature.
static void test_full_flow_signs_after_approval(void)
{
    wallet_session_t *w = open_test_wallet();

    stream_change_tx(w);

    // Signing before the approval must fail.
    uint8_t sig[BITCOIN_SIGNATURE_MAX_SIZE];
    size_t sig_size = sizeof(sig);
    uint8_t pubkey[BITCOIN_PUBKEY_SIZE];
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE,
                      bitcoin_core_tx_sign_input(w, 0, PATH_IN_0, sig, &sig_size, pubkey));

    // That failure resets the session, so build it again up to READY.
    stream_change_tx(w);

    uint8_t tx_id[32];
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_confirm(w, tx_id));

    // The fee is 100000 - 10000 - 85000 = 5000 sats.
    // Only the 10000 leaves the wallet, the change must not count as spent.
    bitcoin_tx_summary_t row;
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_summary(w, 0, &row));
    TEST_ASSERT_EQUAL(BITCOIN_TX_SUMMARY_KIND_TOTAL, row.kind);
    TEST_ASSERT_EQUAL(10000, row.amount);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_summary(w, 2, &row));
    TEST_ASSERT_EQUAL(BITCOIN_TX_SUMMARY_KIND_FEE, row.kind);
    TEST_ASSERT_EQUAL(5000, row.amount);

    // The external output renders as a testnet address. The change is not shown at all.
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_summary(w, 1, &row));
    TEST_ASSERT_EQUAL(BITCOIN_TX_SUMMARY_KIND_OUTPUT, row.kind);
    TEST_ASSERT_ARRAY_EQUAL(row.address, "tb1", 3);

    uint32_t poll = 0;
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_poll(w, &poll));
    TEST_ASSERT_EQUAL(BITCOIN_TX_PENDING, poll);

    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_approve_programmatic(w));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_poll(w, &poll));
    TEST_ASSERT_EQUAL(BITCOIN_TX_APPROVED, poll);

    sig_size = sizeof(sig);
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      bitcoin_core_tx_sign_input(w, 0, PATH_IN_0, sig, &sig_size, pubkey));
    TEST_ASSERT_TRUE(sig_size >= 8 && sig_size <= BITCOIN_SIGNATURE_MAX_SIZE);
    TEST_ASSERT_EQUAL(0x30, sig[0]); // DER SEQUENCE

    // One signature per input, so one approval cannot produce more.
    sig_size = sizeof(sig);
    TEST_ASSERT_EQUAL(PSA_ERROR_ALREADY_EXISTS,
                      bitcoin_core_tx_sign_input(w, 0, PATH_IN_0, sig, &sig_size, pubkey));

    bitcoin_core_close(w);
}

// A path that does not really control the output must not count as change.
// Otherwise the "amount leaving the wallet" the user approves is wrong.
static void test_change_must_match_script(void)
{
    wallet_session_t *w = open_test_wallet();
    bitcoin_tx_begin_t begin;
    bitcoin_tx_output_t out;
    bitcoin_tx_summary_t row;
    uint8_t tx_id[32];

    make_begin(&begin, 1, 1, BITCOIN_SIGHASH_ALL);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_begin(w, &begin));

    // It claims to be change, but the script belongs to someone else.
    make_output(&out, 90000, foreign_script, sizeof(foreign_script));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_output(w, &out, PATH_CHANGE));

    TEST_ASSERT_EQUAL(PSA_SUCCESS, add_input(w, 0xCD, 100000, PATH_IN_0));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_confirm(w, tx_id));

    // Counted as leaving the wallet, not as change.
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_summary(w, 0, &row));
    TEST_ASSERT_EQUAL(BITCOIN_TX_SUMMARY_KIND_TOTAL, row.kind);
    TEST_ASSERT_EQUAL(90000, row.amount);

    bitcoin_core_close(w);
}

// Our key and our script, but a path no wallet scans for change.
// The output must be shown as a payment, or that money would vanish from the review.
static void test_change_path_shape(void)
{
    wallet_session_t *w = open_test_wallet();
    uint64_t sent = 0;

    static const char *const external[] = {
        "m/84'/1'/0'/0/5",    // receive chain
        "m/44'/1'/0'/1/0",    // BIP44 wallets do not scan P2WPKH
        "m/84'/1'/0/1/0",     // unhardened account
        "m/84'/1'/0'/1/1000", // past the index bound
        "m/84'/1'/0'/1/0/0",  // too deep
    };

    for (size_t i = 0; i < sizeof(external) / sizeof(external[0]); i++) {
        TEST_ASSERT_EQUAL(PSA_SUCCESS, confirm_with_change(w, external[i], PATH_IN_0, &sent));
        TEST_ASSERT_EQUAL(95000, sent);
    }

    TEST_ASSERT_EQUAL(PSA_SUCCESS, confirm_with_change(w, "m/84'/1'/0'/1/999", PATH_IN_0, &sent));
    TEST_ASSERT_EQUAL(10000, sent);

    bitcoin_core_close(w);
}

// The first change fixes the account. Change in a second account is shown.
static void test_change_one_account(void)
{
    wallet_session_t *w = open_test_wallet();
    bitcoin_tx_begin_t begin;
    bitcoin_tx_output_t out;
    bitcoin_tx_summary_t row;
    uint8_t script[22];
    uint8_t tx_id[32];

    make_begin(&begin, 1, 2, BITCOIN_SIGHASH_ALL);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_begin(w, &begin));
    own_p2wpkh(PATH_CHANGE, script);
    make_output(&out, 50000, script, sizeof(script));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_output(w, &out, PATH_CHANGE));
    own_p2wpkh("m/84'/1'/1'/1/0", script);
    make_output(&out, 40000, script, sizeof(script));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_output(w, &out, "m/84'/1'/1'/1/0"));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, add_input(w, 0xAB, 100000, PATH_IN_0));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_confirm(w, tx_id));

    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_summary(w, 0, &row));
    TEST_ASSERT_EQUAL(40000, row.amount);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_summary(w, 1, &row));
    TEST_ASSERT_EQUAL(BITCOIN_TX_SUMMARY_KIND_OUTPUT, row.kind);
    TEST_ASSERT_EQUAL(40000, row.amount);

    bitcoin_core_close(w);
}

// An input from another account than the change is refused before the review.
static void test_input_account_must_match_change(void)
{
    wallet_session_t *w = open_test_wallet();
    uint8_t tx_id[32];
    uint64_t sent = 0;

    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      confirm_with_change(w, PATH_CHANGE, "m/84'/1'/1'/0/0", &sent));
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, bitcoin_core_tx_confirm(w, tx_id));

    // A non-BIP84 input path cannot name the account, so it is refused too.
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      confirm_with_change(w, PATH_CHANGE, "m/44'/1'/0'/0/0", &sent));

    bitcoin_core_close(w);
}

// Input paths are hints. The sign path is what spends, so it gets the same rule.
static void test_sign_account_must_match_change(void)
{
    wallet_session_t *w = open_test_wallet();
    uint8_t sig[BITCOIN_SIGNATURE_MAX_SIZE];
    uint8_t pubkey[BITCOIN_PUBKEY_SIZE];
    size_t sig_size = sizeof(sig);
    uint64_t sent = 0;

    TEST_ASSERT_EQUAL(PSA_SUCCESS, confirm_with_change(w, PATH_CHANGE, "", &sent));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_approve_programmatic(w));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      bitcoin_core_tx_sign_input(w, 0, "m/84'/1'/1'/0/0", sig, &sig_size, pubkey));
    sig_size = sizeof(sig);
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE,
                      bitcoin_core_tx_sign_input(w, 0, PATH_IN_0, sig, &sig_size, pubkey));

    TEST_ASSERT_EQUAL(PSA_SUCCESS, confirm_with_change(w, PATH_CHANGE, "", &sent));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_approve_programmatic(w));
    sig_size = sizeof(sig);
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      bitcoin_core_tx_sign_input(w, 0, PATH_IN_0, sig, &sig_size, pubkey));

    bitcoin_core_close(w);
}

static void test_rejects_non_sighash_all(void)
{
    wallet_session_t *w = open_test_wallet();
    bitcoin_tx_begin_t begin;

    make_begin(&begin, 1, 1, 0x02); // SIGHASH_NONE
    TEST_ASSERT_EQUAL(PSA_ERROR_NOT_SUPPORTED, bitcoin_core_tx_begin(w, &begin));

    make_begin(&begin, 1, 1, 0x81); // SIGHASH_ALL | ANYONECANPAY
    TEST_ASSERT_EQUAL(PSA_ERROR_NOT_SUPPORTED, bitcoin_core_tx_begin(w, &begin));

    bitcoin_core_close(w);
}

static void test_rejects_too_many_inputs(void)
{
    wallet_session_t *w = open_test_wallet();
    bitcoin_tx_begin_t begin;

    make_begin(&begin, BITCOIN_TX_MAX_INPUTS + 1, 1, BITCOIN_SIGHASH_ALL);
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, bitcoin_core_tx_begin(w, &begin));

    make_begin(&begin, 0, 1, BITCOIN_SIGHASH_ALL);
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, bitcoin_core_tx_begin(w, &begin));

    bitcoin_core_close(w);
}

// Paying out more than we spend means one of the numbers we show is wrong,
// so it must never reach a confirmation screen.
static void test_rejects_outputs_exceeding_inputs(void)
{
    wallet_session_t *w = open_test_wallet();

    begin_paying(w, 1, 200000);

    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, add_input(w, 0xEF, 100000, PATH_IN_0));

    bitcoin_core_close(w);
}

// An out-of-order call must fail and drop the session,
// so a caller cannot find its way into a state that skips the approval.
static void test_out_of_order_fails_closed(void)
{
    wallet_session_t *w = open_test_wallet();
    bitcoin_tx_begin_t begin;
    uint8_t tx_id[32];
    uint32_t poll = 0;

    // Confirm with no session at all.
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, bitcoin_core_tx_confirm(w, tx_id));
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, bitcoin_core_tx_poll(w, &poll));
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, bitcoin_core_tx_approve_programmatic(w));

    // An input while we still expect outputs.
    make_begin(&begin, 1, 2, BITCOIN_SIGHASH_ALL);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_begin(w, &begin));
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, add_input(w, 0x01, 100000, PATH_IN_0));

    // ...and the session is gone, not just refused.
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, bitcoin_core_tx_confirm(w, tx_id));

    bitcoin_core_close(w);
}

// The production wallet must never open without going through Protected Storage.
// This is the one test that names the production session,
// and the only proof of the isolation the rest of the suite depends on.
// No other test may call bitcoin_core_* on this session.
static void test_production_session_refuses_bypass(void)
{
    wallet_session_t *prod = bitcoin_core_session_production();

    // The open state is compared before and after, not asserted,
    // so this works whether or not the user has the wallet open.
    // It still catches a refusal that opened the session anyway: BAD_STATE would become SUCCESS.
    // It also runs before anything touches session state.
    uint8_t fingerprint[BITCOIN_FINGERPRINT_SIZE];
    psa_status_t before = bitcoin_core_get_fingerprint(prod, fingerprint);

    TEST_ASSERT_EQUAL(PSA_ERROR_NOT_PERMITTED,
                      bitcoin_core_open_ephemeral(prod, TEST_MNEMONIC, ""));

    psa_status_t after = bitcoin_core_get_fingerprint(prod, fingerprint);
    TEST_ASSERT_EQUAL(before, after);
}

// "Native P2WPKH" from BIP143 itself.
static void test_bip143_vector(void)
{
    // The BIP example spends two inputs.
    // Input 1 is the P2WPKH one, with value 600000000 and nSequence 0xffffffff.
    static const uint8_t expected[32] = {
        0xc3, 0x7a, 0xf3, 0x11, 0x16, 0xd1, 0xb2, 0x7c, 0xaf, 0x68, 0xaa,
        0xe9, 0xe3, 0xac, 0x82, 0xf1, 0x47, 0x79, 0x29, 0x01, 0x4d, 0x5b,
        0x91, 0x76, 0x57, 0xd0, 0xeb, 0x49, 0x47, 0x8c, 0xb6, 0x70,
    };
    // dSHA256 of the two outpoints, from the worked example in the spec.
    static const uint8_t hash_prevouts[32] = {
        0x96, 0xb8, 0x27, 0xc8, 0x48, 0x3d, 0x4e, 0x9b, 0x96, 0x71, 0x2b,
        0x67, 0x13, 0xa7, 0xb6, 0x8d, 0x6e, 0x80, 0x03, 0xa7, 0x81, 0xfe,
        0xba, 0x36, 0xc3, 0x11, 0x43, 0x47, 0x0b, 0x4e, 0xfd, 0x37,
    };
    // dSHA256(eeffffff ffffffff), the nSequence values of the two inputs.
    static const uint8_t hash_sequence[32] = {
        0x52, 0xb0, 0xa6, 0x42, 0xee, 0xa2, 0xfb, 0x7a, 0xe6, 0x38, 0xc3,
        0x6f, 0x62, 0x52, 0xb6, 0x75, 0x02, 0x93, 0xdb, 0xe5, 0x74, 0xa8,
        0x06, 0x98, 0x4b, 0x8e, 0x4d, 0x85, 0x48, 0x33, 0x9a, 0x3b,
    };
    static const uint8_t hash_outputs[32] = {
        0x86, 0x3e, 0xf3, 0xe1, 0xa9, 0x2a, 0xfb, 0xfd, 0xb9, 0x7f, 0x31,
        0xad, 0x0f, 0xc7, 0x68, 0x3e, 0xe9, 0x43, 0xe9, 0xab, 0xcf, 0x25,
        0x01, 0x59, 0x0f, 0xf8, 0xf6, 0x55, 0x1f, 0x47, 0xe5, 0xe5,
    };
    static const uint8_t txid[32] = {
        0xef, 0x51, 0xe1, 0xb8, 0x04, 0xcc, 0x89, 0xd1, 0x82, 0xd2, 0x79,
        0x65, 0x5c, 0x3a, 0xa8, 0x9e, 0x81, 0x5b, 0x1b, 0x30, 0x9f, 0xe2,
        0x87, 0xd9, 0xb2, 0xb5, 0x5d, 0x57, 0xb9, 0x0e, 0xc6, 0x8a,
    };
    static const uint8_t script_code[25] = {0x76, 0xa9, 0x14, 0x1d, 0x0f, 0x17, 0x2a, 0x0e, 0xcb,
                                            0x48, 0xae, 0xe1, 0xbe, 0x1f, 0x26, 0x87, 0xd2, 0x96,
                                            0x3a, 0xe3, 0x3f, 0x71, 0xa1, 0x88, 0xac};

    sighash_bip143_params_t params = {
        .version = 1,
        .hash_prevouts = hash_prevouts,
        .hash_sequence = hash_sequence,
        .txid = txid,
        .vout = 1,
        .script_code = script_code,
        .script_code_len = sizeof(script_code),
        .amount = 600000000ULL,
        .sequence = 0xffffffff,
        .hash_outputs = hash_outputs,
        .locktime = 0x11,
        .sighash_type = BITCOIN_SIGHASH_ALL,
    };

    uint8_t actual[32];
    TEST_ASSERT_EQUAL(PSA_SUCCESS, sighash_bip143(&params, actual));
    TEST_ASSERT_ARRAY_EQUAL(expected, actual, 32);
}

static void test_btc_formatter(void)
{
    char buf[32];

    TEST_ASSERT_TRUE(tx_format_btc(0, buf, sizeof(buf)));
    TEST_ASSERT_STR_EQUAL(buf, "0.00000000");

    TEST_ASSERT_TRUE(tx_format_btc(1, buf, sizeof(buf)));
    TEST_ASSERT_STR_EQUAL(buf, "0.00000001");

    TEST_ASSERT_TRUE(tx_format_btc(18922, buf, sizeof(buf)));
    TEST_ASSERT_STR_EQUAL(buf, "0.00018922");

    TEST_ASSERT_TRUE(tx_format_btc(100000000ULL, buf, sizeof(buf)));
    TEST_ASSERT_STR_EQUAL(buf, "1.00000000");

    // 21M BTC, the point where a double starts to lose satoshis.
    TEST_ASSERT_TRUE(tx_format_btc(2100000000000000ULL, buf, sizeof(buf)));
    TEST_ASSERT_STR_EQUAL(buf, "21000000.00000000");
}

// The records are the ABI between the two images. These bytes pin the layout.
static void test_record_layout(void)
{
    static const uint8_t begin_bytes[BITCOIN_TX_BEGIN_REC_SIZE] = {
        0x02, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x01, 0, 0, 0, 0x03, 0, 0, 0, 0x01, 0, 0, 0};
    bitcoin_tx_begin_t begin = {2, 0x11223344, 1, 3, BITCOIN_SIGHASH_ALL};
    bitcoin_tx_begin_t begin_back;
    bitcoin_tx_begin_rec_t begin_rec;

    bitcoin_tx_begin_pack(&begin, &begin_rec);
    TEST_ASSERT_ARRAY_EQUAL(begin_bytes, begin_rec.bytes, sizeof(begin_bytes));
    bitcoin_tx_begin_unpack(&begin_rec, &begin_back);
    TEST_ASSERT_EQUAL(0x11223344, begin_back.locktime);
    TEST_ASSERT_EQUAL(3, begin_back.num_outputs);

    static const uint8_t output_head[11] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
                                            0x02, 0x01, 0x02, 0xAA, 0xBB};
    static const uint8_t zeros[BITCOIN_TX_SCRIPT_MAX_SIZE] = {0};
    bitcoin_tx_output_t out = {
        .amount = 0x0102030405060708ULL, .script_len = 2, .script = {0xAA, 0xBB}};
    bitcoin_tx_output_t out_back;
    bitcoin_tx_output_rec_t out_rec;

    TEST_ASSERT_TRUE(bitcoin_tx_output_pack(&out, &out_rec));
    TEST_ASSERT_ARRAY_EQUAL(output_head, out_rec.bytes, sizeof(output_head));
    TEST_ASSERT_ARRAY_EQUAL(zeros, &out_rec.bytes[11], BITCOIN_TX_OUTPUT_REC_SIZE - 11);
    TEST_ASSERT_TRUE(bitcoin_tx_output_unpack(&out_rec, &out_back));
    TEST_ASSERT_EQUAL(2, out_back.script_len);
    TEST_ASSERT_TRUE(out_back.amount == out.amount);
    TEST_ASSERT_ARRAY_EQUAL(out.script, out_back.script, BITCOIN_TX_SCRIPT_MAX_SIZE);

    // NS picks script_len. One past the field must be refused, not copied.
    out_rec.bytes[8] = BITCOIN_TX_SCRIPT_MAX_SIZE + 1;
    TEST_ASSERT_FALSE(bitcoin_tx_output_unpack(&out_rec, &out_back));
    out.script_len = BITCOIN_TX_SCRIPT_MAX_SIZE + 1;
    TEST_ASSERT_FALSE(bitcoin_tx_output_pack(&out, &out_rec));

    static const uint8_t input_tail[8] = {0x05, 0, 0, 0, 0xFE, 0xFF, 0xFF, 0xFF};
    bitcoin_tx_input_t in = {.vout = 5, .sequence = 0xFFFFFFFE};
    bitcoin_tx_input_t in_back;
    bitcoin_tx_input_rec_t in_rec;

    memset(in.txid, 0xAB, sizeof(in.txid));
    bitcoin_tx_input_pack(&in, &in_rec);
    TEST_ASSERT_ARRAY_EQUAL(in.txid, in_rec.bytes, BITCOIN_TXID_SIZE);
    TEST_ASSERT_EQUAL(BITCOIN_TX_INPUT_REC_SIZE, BITCOIN_TXID_SIZE + sizeof(input_tail));
    TEST_ASSERT_ARRAY_EQUAL(input_tail, &in_rec.bytes[BITCOIN_TXID_SIZE], sizeof(input_tail));
    bitcoin_tx_input_unpack(&in_rec, &in_back);
    TEST_ASSERT_EQUAL(0xFFFFFFFE, in_back.sequence);
    TEST_ASSERT_ARRAY_EQUAL(in.txid, in_back.txid, BITCOIN_TXID_SIZE);
}

// The cursor is what keeps a new record from writing past its buffer.
static void test_wire_cursor_bounds(void)
{
    uint8_t buf[3] = {0};
    wire_w w = wire_writer(buf, sizeof(buf));
    wire_r r = wire_reader(buf, sizeof(buf));
    uint8_t field[4] = {1, 2, 3, 4};

    wire_put_le32(&w, 0xFFFFFFFF);
    TEST_ASSERT_FALSE(w.ok);
    wire_put_u8(&w, 0x55); // sticky, so this writes nothing
    TEST_ASSERT_EQUAL(0, buf[0]);

    TEST_ASSERT_EQUAL(0, wire_get_le32(&r));
    TEST_ASSERT_FALSE(r.ok);

    w = wire_writer(buf, sizeof(buf));
    wire_put_field(&w, field, sizeof(field), 2);
    TEST_ASSERT_FALSE(w.ok);
}

// The coin type uses the same parser as key derivation,
// so a path shape that could never produce a key cannot silently pick a network either.
static void test_rejects_malformed_input_path(void)
{
    wallet_session_t *w = open_test_wallet();
    uint8_t tx_id[32];

    static const char *const bad[] = {"M/84'/1'/0'/0/0", "m/x/1", "m/84'/4294967296"};

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        begin_paying(w, 1, 90000);

        TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, add_input(w, 0xAB, 100000, bad[i]));
        TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, bitcoin_core_tx_confirm(w, tx_id));
    }

    // Well formed but too short to name a network.
    // We accept it, it tells us nothing, and the transaction stays unconfirmable.
    begin_paying(w, 1, 90000);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, add_input(w, 0xAB, 100000, "m/84'"));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, bitcoin_core_tx_confirm(w, tx_id));

    // An unhardened coin type is not a BIP44 network, so it names none.
    begin_paying(w, 1, 90000);
    TEST_ASSERT_EQUAL(PSA_ERROR_NOT_SUPPORTED, add_input(w, 0xAB, 100000, "m/84'/1/0'/0/0"));
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, bitcoin_core_tx_confirm(w, tx_id));

    bitcoin_core_close(w);
}

// One transaction, one network.
// Mixing them means one of the addresses we show uses an HRP that does not belong to it.
static void test_rejects_mixed_coin_types(void)
{
    wallet_session_t *w = open_test_wallet();
    bitcoin_tx_begin_t begin;
    bitcoin_tx_output_t out;
    uint8_t tx_id[32];

    make_begin(&begin, 1, 1, BITCOIN_SIGHASH_ALL);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_begin(w, &begin));

    // Testnet from the output path...
    make_output(&out, 90000, foreign_script, sizeof(foreign_script));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_output(w, &out, PATH_CHANGE));

    // ...mainnet from the input path.
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, add_input(w, 0xAB, 100000, "m/84'/0'/0'/0/0"));
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, bitcoin_core_tx_confirm(w, tx_id));

    bitcoin_core_close(w);
}

// With no path anywhere we have nothing to take the network from,
// and the addresses would use a guessed HRP.
static void test_confirm_requires_network(void)
{
    wallet_session_t *w = open_test_wallet();
    uint8_t tx_id[32];

    begin_paying(w, 1, 90000);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, add_input(w, 0xAB, 100000, ""));

    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, bitcoin_core_tx_confirm(w, tx_id));
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, bitcoin_core_tx_confirm(w, tx_id));

    bitcoin_core_close(w);
}

// The summary said testnet, so the signing keys must be testnet keys.
// Otherwise a transaction shown as play money spends real coins.
static void test_sign_path_network_must_match(void)
{
    wallet_session_t *w = open_test_wallet();
    uint8_t sig[BITCOIN_SIGNATURE_MAX_SIZE];
    uint8_t pubkey[BITCOIN_PUBKEY_SIZE];
    size_t sig_size = sizeof(sig);

    approve_one_input_tx(w);

    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      bitcoin_core_tx_sign_input(w, 0, "m/84'/0'/0'/0/0", sig, &sig_size, pubkey));

    // It took the approval with it, so the correct path cannot follow up.
    sig_size = sizeof(sig);
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE,
                      bitcoin_core_tx_sign_input(w, 0, PATH_IN_0, sig, &sig_size, pubkey));

    bitcoin_core_close(w);
}

// A bad signing path is protocol misuse like any other.
// It drops the session instead of leaving it approved for another try.
static void test_sign_input_bad_path_fails_closed(void)
{
    wallet_session_t *w = open_test_wallet();
    uint8_t sig[BITCOIN_SIGNATURE_MAX_SIZE];
    uint8_t pubkey[BITCOIN_PUBKEY_SIZE];
    size_t sig_size = sizeof(sig);

    approve_one_input_tx(w);

    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      bitcoin_core_tx_sign_input(w, 0, "m/x/1", sig, &sig_size, pubkey));

    sig_size = sizeof(sig);
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE,
                      bitcoin_core_tx_sign_input(w, 0, PATH_IN_0, sig, &sig_size, pubkey));

    bitcoin_core_close(w);
}

// A taproot address is 62 characters.
// Truncating it hides the checksum and the end an attacker would have to grind,
// so the row must arrive complete.
static void test_taproot_output_renders_full_address(void)
{
    wallet_session_t *w = open_test_wallet();
    bitcoin_tx_begin_t begin;
    bitcoin_tx_output_t out;
    uint8_t tx_id[32];
    bitcoin_tx_summary_t row;

    make_begin(&begin, 1, 1, BITCOIN_SIGHASH_ALL);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_begin(w, &begin));
    make_output(&out, 90000, taproot_script, sizeof(taproot_script));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_output(w, &out, ""));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, add_input(w, 0xAB, 100000, PATH_IN_0));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_confirm(w, tx_id));

    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_summary(w, 1, &row));
    TEST_ASSERT_EQUAL(BITCOIN_TX_SUMMARY_KIND_OUTPUT, row.kind);
    TEST_ASSERT_EQUAL(62, strlen(row.address));
    TEST_ASSERT_ARRAY_EQUAL(row.address, "tb1p", 4);

    bitcoin_core_close(w);
}

// The user approves a total.
// Every destination inside it must have been listed, or they agree to something they never saw.
static void test_rejects_unshowable_outputs(void)
{
    wallet_session_t *w = open_test_wallet();
    bitcoin_tx_begin_t begin;
    bitcoin_tx_output_t out;
    uint8_t tx_id[32];

    make_begin(&begin, 1, BITCOIN_TX_MAX_SHOWN_OUTPUTS + 1, BITCOIN_SIGHASH_ALL);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_begin(w, &begin));

    for (uint32_t i = 0; i < BITCOIN_TX_MAX_SHOWN_OUTPUTS + 1; i++) {
        make_output(&out, 1000, foreign_script, sizeof(foreign_script));
        TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_output(w, &out, ""));
    }

    TEST_ASSERT_EQUAL(PSA_SUCCESS, add_input(w, 0xAB, 100000, PATH_IN_0));

    TEST_ASSERT_EQUAL(PSA_ERROR_NOT_SUPPORTED, bitcoin_core_tx_confirm(w, tx_id));
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, bitcoin_core_tx_confirm(w, tx_id));

    bitcoin_core_close(w);
}

// Nothing above the money supply is a real amount.
// The cap is what keeps every total in this session away from overflow.
static void test_rejects_amount_over_max_money(void)
{
    wallet_session_t *w = open_test_wallet();
    bitcoin_tx_begin_t begin;
    bitcoin_tx_output_t out;
    uint8_t tx_id[32];

    make_begin(&begin, 1, 1, BITCOIN_SIGHASH_ALL);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_begin(w, &begin));
    make_output(&out, 2100000000000001ULL, foreign_script, sizeof(foreign_script));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, bitcoin_core_tx_output(w, &out, ""));
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, bitcoin_core_tx_confirm(w, tx_id));

    // An input that claims more than exists goes the same way.
    begin_paying(w, 1, 90000);
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      add_input(w, 0xAB, 2100000000000001ULL, PATH_IN_0));

    bitcoin_core_close(w);
}

// The top index must work.
// signed_mask is 16 bits and MAX_INPUTS fills it exactly,
// so index 15 is the bit an off-by-one would drop.
static void test_max_inputs_boundary(void)
{
    wallet_session_t *w = open_test_wallet();
    uint8_t tx_id[32];
    uint8_t sig[BITCOIN_SIGNATURE_MAX_SIZE];
    uint8_t pubkey[BITCOIN_PUBKEY_SIZE];
    size_t sig_size = sizeof(sig);
    const uint32_t last = BITCOIN_TX_MAX_INPUTS - 1;

    begin_paying(w, BITCOIN_TX_MAX_INPUTS, 90000);

    for (uint32_t i = 0; i < BITCOIN_TX_MAX_INPUTS; i++) {
        TEST_ASSERT_EQUAL(PSA_SUCCESS, add_input(w, (uint8_t)i, 10000, PATH_IN_0));
    }

    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_confirm(w, tx_id));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_approve_programmatic(w));

    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      bitcoin_core_tx_sign_input(w, last, PATH_IN_0, sig, &sig_size, pubkey));

    sig_size = sizeof(sig);
    TEST_ASSERT_EQUAL(PSA_ERROR_ALREADY_EXISTS,
                      bitcoin_core_tx_sign_input(w, last, PATH_IN_0, sig, &sig_size, pubkey));

    bitcoin_core_close(w);
}

// bitcoin_core_status() is the only storage call a test may make on the test session.
// key_storage_exists() only reads, under the test UIDs that key_storage_test.c owns.
static void test_status_reports_session_state(void)
{
    wallet_session_t *w = open_test_wallet();
    uint32_t state = 0xFFFFFFFF;
    uint32_t attempts = 0;

    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_status(w, &state, &attempts));
    TEST_ASSERT_EQUAL(BITCOIN_STATUS_OPEN, state);
    TEST_ASSERT_EQUAL(BITCOIN_ATTEMPTS_NA, attempts);

    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_close(w));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_status(w, &state, &attempts));
    // NONE or LOCKED, depending on whether key_storage_test.c left a blob in the test namespace.
    // Asserting one exactly would tie the two suites together.
    TEST_ASSERT_NOT_EQUAL(BITCOIN_STATUS_OPEN, state);
    // Either way, the attempt count is reported exactly when it means something.
    if (state == BITCOIN_STATUS_LOCKED) {
        TEST_ASSERT_NOT_EQUAL(BITCOIN_ATTEMPTS_NA, attempts);
    } else {
        TEST_ASSERT_EQUAL(BITCOIN_ATTEMPTS_NA, attempts);
    }

    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, bitcoin_core_status(w, NULL, &attempts));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, bitcoin_core_status(w, &state, NULL));
}

// The approve press on the review screen goes through bitcoin_core_tx_approve_user().
// The test wallet has no screen, so it must refuse there and leave the session waiting.
// The tx_id it reports is the one confirm() bound.
static void test_user_approval_refused_on_test_wallet(void)
{
    wallet_session_t *w = open_test_wallet();
    uint8_t tx_id[32];
    uint8_t read_id[32];
    uint32_t poll = 0;

    begin_paying(w, 1, 90000);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, add_input(w, 0xAB, 100000, PATH_IN_0));

    // READY has a summary but no tx_id yet.
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, bitcoin_core_tx_get_tx_id(w, read_id));

    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_confirm(w, tx_id));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_tx_id(w, read_id));
    TEST_ASSERT_ARRAY_EQUAL(tx_id, read_id, sizeof(tx_id));

    TEST_ASSERT_EQUAL(PSA_ERROR_NOT_PERMITTED, bitcoin_core_tx_approve_user(w, tx_id));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_poll(w, &poll));
    TEST_ASSERT_EQUAL(BITCOIN_TX_PENDING, poll);

    bitcoin_core_close(w);
}

// Starts a one-input one-output session and offers `prev_tx` for the input.
static psa_status_t offer_prev_tx(wallet_session_t *w, const uint8_t *prev_tx, size_t len,
                                  const uint8_t *txid, uint32_t vout)
{
    bitcoin_tx_input_t in = {.vout = vout, .sequence = 0xFFFFFFFF};

    memcpy(in.txid, txid, BITCOIN_TXID_SIZE);
    begin_paying(w, 1, 1000);
    return bitcoin_core_tx_input(w, &in, PATH_IN_0, prev_tx, len);
}

// Offers bytes whose txid matches, so only the parser can refuse them.
static psa_status_t offer_self_hashed(wallet_session_t *w, const uint8_t *prev_tx, size_t len)
{
    uint8_t txid[BITCOIN_TXID_SIZE];

    TEST_ASSERT_EQUAL(PSA_SUCCESS, hash_double_sha256(prev_tx, len, txid, sizeof(txid)));
    return offer_prev_tx(w, prev_tx, len, txid, 0);
}

// The segwit v0 fee attack. NS lowers the amount of an input so the fee looks small.
// BIP143 alone would sign that.
// The prev tx no longer hashes to the outpoint txid, so it is refused and the session is dropped.
static void test_prev_tx_txid_must_match(void)
{
    wallet_session_t *w = open_test_wallet();
    uint8_t prev_tx[PREV_TX_SIZE];
    uint8_t txid[BITCOIN_TXID_SIZE];
    uint8_t tx_id[32];
    bitcoin_tx_summary_t row;

    make_prev_tx(prev_tx, 0x42, 100000, txid);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, offer_prev_tx(w, prev_tx, sizeof(prev_tx), txid, 0));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_confirm(w, tx_id));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_summary(w, 2, &row));
    TEST_ASSERT_EQUAL(BITCOIN_TX_SUMMARY_KIND_FEE, row.kind);
    TEST_ASSERT_EQUAL(99000, row.amount);

    prev_tx[PREV_TX_AMOUNT_AT + 1] ^= 0x01;
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      offer_prev_tx(w, prev_tx, sizeof(prev_tx), txid, 0));
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, bitcoin_core_tx_confirm(w, tx_id));

    // The right bytes for another outpoint go the same way.
    make_prev_tx(prev_tx, 0x42, 100000, txid);
    txid[0] ^= 0x01;
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
                      offer_prev_tx(w, prev_tx, sizeof(prev_tx), txid, 0));

    bitcoin_core_close(w);
}

// Each of these hashes to the txid we offer with it, so only the parser refuses them.
static void test_prev_tx_malformed(void)
{
    wallet_session_t *w = open_test_wallet();
    uint8_t good[PREV_TX_SIZE];
    uint8_t buf[PREV_TX_SIZE + 2];
    uint8_t txid[BITCOIN_TXID_SIZE];

    make_prev_tx(good, 0x42, 100000, txid);
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, offer_prev_tx(w, good, sizeof(good), txid, 1));
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, offer_self_hashed(w, good, sizeof(good) - 1));

    memcpy(buf, good, sizeof(good));
    buf[sizeof(good)] = 0x00;
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, offer_self_hashed(w, buf, sizeof(good) + 1));

    // A segwit marker with a flag BIP144 does not define.
    memcpy(buf, good, 4);
    buf[4] = 0x00;
    buf[5] = 0x02;
    memcpy(&buf[6], &good[4], sizeof(good) - 4);
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, offer_self_hashed(w, buf, sizeof(good) + 2));

    // The input count as FD 01 00. Bitcoin refuses that encoding.
    memcpy(buf, good, 4);
    buf[4] = 0xFD;
    buf[5] = 0x01;
    buf[6] = 0x00;
    memcpy(&buf[7], &good[5], sizeof(good) - 5);
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, offer_self_hashed(w, buf, sizeof(good) + 2));

    // No outputs, so there is no amount to read.
    memcpy(buf, good, PREV_TX_AMOUNT_AT);
    buf[PREV_TX_AMOUNT_AT - 1] = 0x00;
    memset(&buf[PREV_TX_AMOUNT_AT], 0, 4);
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_ARGUMENT, offer_self_hashed(w, buf, PREV_TX_AMOUNT_AT + 4));

    bitcoin_core_close(w);
}

// A prev tx in the BIP144 form, with witness data. Made with btclib, which also gave the txid.
// The txid leaves out the witness. Output 1 is 250000 sats.
static void test_prev_tx_segwit_form(void)
{
    static const uint8_t prev_tx[264] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18,
        0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0xfd,
        0xff, 0xff, 0xff, 0x3f, 0x3e, 0x3d, 0x3c, 0x3b, 0x3a, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34,
        0x33, 0x32, 0x31, 0x30, 0x2f, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x29, 0x28, 0x27, 0x26, 0x25,
        0x24, 0x23, 0x22, 0x21, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x02,
        0x39, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
        0x13, 0x90, 0xd0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
        0x26, 0x27, 0x02, 0x47, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x21, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
        0x1d, 0x1e, 0x1f, 0x20, 0x00, 0x00, 0x00, 0x10, 0x00,
    };
    static const uint8_t txid[BITCOIN_TXID_SIZE] = {
        0xdf, 0x3d, 0x65, 0xf2, 0xc7, 0x33, 0x02, 0x7a, 0x82, 0x38, 0xda,
        0xdc, 0xfe, 0x92, 0x6b, 0x6b, 0xf4, 0x61, 0xbe, 0x5d, 0xd2, 0x11,
        0x2c, 0xa5, 0x71, 0xa8, 0x78, 0xca, 0xcb, 0xa6, 0xc5, 0xcc,
    };
    wallet_session_t *w = open_test_wallet();
    uint8_t tx_id[32];
    bitcoin_tx_summary_t row;

    TEST_ASSERT_EQUAL(PSA_SUCCESS, offer_prev_tx(w, prev_tx, sizeof(prev_tx), txid, 1));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_confirm(w, tx_id));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_summary(w, 2, &row));
    TEST_ASSERT_EQUAL(249000, row.amount);

    bitcoin_core_close(w);
}

// The fee counts every input, ours or not, and each amount comes from its own prev tx.
static void test_fee_comes_from_prev_txs(void)
{
    wallet_session_t *w = open_test_wallet();
    uint8_t tx_id[32];
    bitcoin_tx_summary_t row;

    begin_paying(w, 2, 90000);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, add_input(w, 0x01, 60000, PATH_IN_0));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, add_input(w, 0x02, 40000, ""));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_confirm(w, tx_id));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_summary(w, 2, &row));
    TEST_ASSERT_EQUAL(BITCOIN_TX_SUMMARY_KIND_FEE, row.kind);
    TEST_ASSERT_EQUAL(10000, row.amount);

    bitcoin_core_close(w);
}

// tx_session itself, with no wallet session: the production session is off limits here.
// One input of 100000 sats and one output, streamed to AWAITING_USER.
// The caller picks the fields the details come from.
// Empty paths and an external output need no key, so the master is a zeroed stand-in.
static psa_status_t stream_details_tx(tx_session_t *s, uint32_t version, uint32_t locktime,
                                      uint32_t sequence, const uint8_t *script, uint8_t script_len,
                                      uint64_t amount, uint8_t *tx_id)
{
    static const bip32_extended_privkey_t master;
    bitcoin_tx_begin_t begin = {
        .version = version,
        .locktime = locktime,
        .num_inputs = 1,
        .num_outputs = 1,
        .sighash_type = BITCOIN_SIGHASH_ALL,
    };
    bitcoin_tx_output_t out;
    bitcoin_tx_input_t in = {.sequence = sequence};
    uint8_t prev_tx[PREV_TX_SIZE];

    make_output(&out, amount, script, script_len);
    make_prev_tx(prev_tx, 0xAB, 100000, in.txid);

    TEST_ASSERT_EQUAL(PSA_SUCCESS, tx_session_begin(s, &begin));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, tx_session_add_output(s, &out, "", &master));
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      tx_session_add_input(s, &in, PATH_IN_0, prev_tx, sizeof(prev_tx)));
    return tx_session_confirm(s, tx_id);
}

// A press approves only the tx_id the screen read.
// Any other id means the transaction changed under the screen, so the session is dropped.
// A second press after the approval refuses and keeps the approval,
// because NS may be signing right then.
static void test_user_approval_binds_tx_id(void)
{
    static tx_session_t s;
    uint8_t tx_id[32];
    uint8_t other[32];
    uint32_t poll = 0;

    tx_session_reset(&s);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, stream_details_tx(&s, 2, 0, 0xFFFFFFFF, foreign_script,
                                                     sizeof(foreign_script), 90000, tx_id));
    memcpy(other, tx_id, sizeof(other));
    other[0] ^= 1;
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, tx_session_approve_user(&s, other));
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, tx_session_poll(&s, &poll));

    TEST_ASSERT_EQUAL(PSA_SUCCESS, stream_details_tx(&s, 2, 0, 0xFFFFFFFF, foreign_script,
                                                     sizeof(foreign_script), 90000, tx_id));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, tx_session_approve_user(&s, tx_id));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, tx_session_poll(&s, &poll));
    TEST_ASSERT_EQUAL(BITCOIN_TX_APPROVED, poll);

    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, tx_session_approve_user(&s, tx_id));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, tx_session_poll(&s, &poll));
    TEST_ASSERT_EQUAL(BITCOIN_TX_APPROVED, poll);

    tx_session_reset(&s);
}

static bitcoin_tx_details_t details_of(uint32_t version, uint32_t locktime, uint32_t sequence,
                                       uint64_t amount)
{
    static tx_session_t s;
    bitcoin_tx_details_t d = {0};
    uint8_t tx_id[32];

    tx_session_reset(&s);
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      stream_details_tx(&s, version, locktime, sequence, foreign_script,
                                        sizeof(foreign_script), amount, tx_id));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, tx_session_get_details(&s, &d));
    tx_session_reset(&s);
    return d;
}

// The user could not check a script we cannot name,
// so confirm refuses it and no tx_id exists for the review to show.
static void test_rejects_unknown_output_script(void)
{
    static const uint8_t op_return[] = {0x6a, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f};
    static tx_session_t s;
    uint8_t tx_id[32];

    tx_session_reset(&s);
    TEST_ASSERT_EQUAL(PSA_ERROR_NOT_SUPPORTED, stream_details_tx(&s, 2, 0, 0xFFFFFFFF, op_return,
                                                                 sizeof(op_return), 0, tx_id));
    TEST_ASSERT_EQUAL(TX_STATE_IDLE, s.state);
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, tx_session_get_tx_id(&s, tx_id));
}

static void test_p2pkh_output_renders_base58(void)
{
    static const uint8_t p2pkh[25] = {
        0x76, 0xa9, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
        0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6, 0x88, 0xac,
    };
    static tx_session_t s;
    bitcoin_tx_summary_t row;
    uint8_t tx_id[32];

    tx_session_reset(&s);
    TEST_ASSERT_EQUAL(PSA_SUCCESS,
                      stream_details_tx(&s, 2, 0, 0xFFFFFFFF, p2pkh, sizeof(p2pkh), 90000, tx_id));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, tx_session_get_summary(&s, 1, &row));
    TEST_ASSERT_EQUAL(BITCOIN_TX_SUMMARY_KIND_OUTPUT, row.kind);
    TEST_ASSERT_STR_EQUAL("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", row.address);
    tx_session_reset(&s);
}

// 5% of send + fee is the limit. Here send + fee is always the 100000 input.
static void test_high_fee_threshold(void)
{
    static tx_session_t idle;
    bitcoin_tx_details_t d;

    tx_session_reset(&idle);
    TEST_ASSERT_EQUAL(PSA_ERROR_BAD_STATE, tx_session_get_details(&idle, &d));

    TEST_ASSERT_FALSE(details_of(2, 0, 0xFFFFFFFF, 99000).high_fee);
    TEST_ASSERT_FALSE(details_of(2, 0, 0xFFFFFFFF, 95000).high_fee);
    TEST_ASSERT_TRUE(details_of(2, 0, 0xFFFFFFFF, 94999).high_fee);
    TEST_ASSERT_TRUE(details_of(2, 0, 0xFFFFFFFF, 10000).high_fee);
}

// With no send, the fee is all that leaves, so it is compared with the inputs.
static void test_high_fee_self_transfer(void)
{
    static const uint64_t change[] = {99000, 95000, 94999};
    static const bool high[] = {false, false, true};
    uint8_t own[22];

    own_p2wpkh(PATH_CHANGE, own);
    for (size_t i = 0; i < sizeof(change) / sizeof(change[0]); i++) {
        wallet_session_t *w = open_test_wallet();
        bitcoin_tx_begin_t begin;
        bitcoin_tx_output_t out;
        bitcoin_tx_summary_t row;
        bitcoin_tx_details_t d = {0};
        uint8_t tx_id[32];

        make_begin(&begin, 1, 1, BITCOIN_SIGHASH_ALL);
        TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_begin(w, &begin));
        make_output(&out, change[i], own, sizeof(own));
        TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_output(w, &out, PATH_CHANGE));
        TEST_ASSERT_EQUAL(PSA_SUCCESS, add_input(w, 0xCD, 100000, PATH_IN_0));
        TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_confirm(w, tx_id));
        TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_summary(w, 0, &row));
        TEST_ASSERT_EQUAL(0, row.amount);
        TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_tx_get_details(w, &d));
        TEST_ASSERT_EQUAL(high[i], d.high_fee);
        bitcoin_core_close(w);
    }
}

static void test_details_locks(void)
{
    bitcoin_tx_details_t d = details_of(2, 0, 0xFFFFFFFF, 99000);

    TEST_ASSERT_FALSE(d.locktime_active || d.relative_lock || d.rbf);

    // Every input final, so Bitcoin ignores the locktime.
    TEST_ASSERT_FALSE(details_of(2, 870000, 0xFFFFFFFF, 99000).locktime_active);

    d = details_of(2, 870000, 0xFFFFFFFE, 99000);
    TEST_ASSERT_TRUE(d.locktime_active);
    TEST_ASSERT_EQUAL(870000, d.locktime);
    TEST_ASSERT_FALSE(d.rbf);

    d = details_of(2, 1700000000, 0xFFFFFFFD, 99000);
    TEST_ASSERT_TRUE(d.locktime_active);
    TEST_ASSERT_EQUAL(1700000000, d.locktime);
    TEST_ASSERT_TRUE(d.rbf);
    TEST_ASSERT_FALSE(d.relative_lock);

    // BIP68: only v2, only with bit 31 clear, and only with a nonzero value.
    d = details_of(2, 0, 10, 99000);
    TEST_ASSERT_TRUE(d.relative_lock);
    TEST_ASSERT_TRUE(d.rbf);
    TEST_ASSERT_FALSE(details_of(1, 0, 10, 99000).relative_lock);
    TEST_ASSERT_FALSE(details_of(2, 0, 0, 99000).relative_lock);
    TEST_ASSERT_FALSE(details_of(2, 0, 0x80000010, 99000).relative_lock);
}

void tx_session_test_run_all(void)
{
    test_btc_formatter();
    test_record_layout();
    test_wire_cursor_bounds();
    test_bip143_vector();
    test_full_flow_signs_after_approval();
    test_change_must_match_script();
    test_change_path_shape();
    test_change_one_account();
    test_input_account_must_match_change();
    test_sign_account_must_match_change();
    test_rejects_non_sighash_all();
    test_rejects_too_many_inputs();
    test_rejects_outputs_exceeding_inputs();
    test_out_of_order_fails_closed();
    test_rejects_malformed_input_path();
    test_rejects_mixed_coin_types();
    test_confirm_requires_network();
    test_sign_path_network_must_match();
    test_sign_input_bad_path_fails_closed();
    test_taproot_output_renders_full_address();
    test_rejects_unshowable_outputs();
    test_rejects_amount_over_max_money();
    test_max_inputs_boundary();
    test_prev_tx_txid_must_match();
    test_prev_tx_malformed();
    test_prev_tx_segwit_form();
    test_fee_comes_from_prev_txs();
    test_status_reports_session_state();
    test_user_approval_refused_on_test_wallet();
    test_user_approval_binds_tx_id();
    test_rejects_unknown_output_script();
    test_p2pkh_output_renders_base58();
    test_high_fee_threshold();
    test_high_fee_self_transfer();
    test_details_locks();
    test_production_session_refuses_bypass();
}
