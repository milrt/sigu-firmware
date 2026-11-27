// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The tx session as a malicious NS drives it:
// any call in any order, with paths, scripts and previous transactions picked from the input.
// The harness is the review screen:
// it reads the tx_id and the rows, and passes that tx_id to approve.
// It keeps its own list of what it sent, and stops on any of these:
//   - a sighash without an approval, or after a call that changed the session since
//   - an index signed twice under one approval
//   - a row that changed between the approval and a sighash
//   - an output that is not ours (a script the harness did not derive) and is on no row
//   - a Send row that is not the sum of the output rows, or a Fee row that is not in - out
// app/ stays as it is: this file includes tx_session.c to reach the session fields.

#include "tx_session.c"

#include "base58.h"
#include <stdlib.h>

#define OUTS_MAX 24
#define ROWS_MAX (BITCOIN_TX_MAX_SHOWN_OUTPUTS + 2)

static bip32_extended_privkey_t master;
static tx_session_t s;

// What the harness sent since the last begin.
static struct {
    uint64_t amount;
    uint8_t script[BITCOIN_TX_SCRIPT_MAX_SIZE];
    uint8_t len;
    bool ours; // derived from `master` by the harness
} outs[OUTS_MAX];
static uint32_t n_outs;
static uint64_t sum_in;
static uint64_t sum_out;
static bool overflow; // more outputs than the list holds, so the output checks are off

static bool approved;
static uint16_t signed_h;
static bitcoin_tx_summary_t rows_at_ok[ROWS_MAX];
static uint32_t n_rows_at_ok;

static const uint8_t *in;
static size_t left;

static uint8_t u8(void)
{
    if (left == 0) {
        return 0;
    }
    left--;
    return *in++;
}

static uint64_t u64(void)
{
    uint64_t v = 0;

    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)u8() << (8 * i);
    }
    return v;
}

static void die(const char *why)
{
    fprintf(stderr, "INVARIANT: %s\n", why);
    abort();
}

static void changed(void)
{
    approved = false;
    signed_h = 0;
}

// Paths a wallet or an attacker would send, valid and not.
static const char *const paths[] = {
    "",
    "m/84'/1'/0'/1/0",
    "m/84'/1'/0'/1/1",
    "m/84'/1'/0'/1/999",
    "m/84'/1'/0'/1/1000",
    "m/84'/1'/0'/0/0",
    "m/84'/1'/0'/0/1",
    "m/84'/1'/1'/1/0",
    "m/84'/1'/1'/0/0",
    "m/84'/0'/0'/1/0",
    "m/84'/0'/0'/0/0",
    "m/84h/1h/0h/1/0",
    "m/84H/1H/0H/1/2",
    "m/49'/1'/0'/1/0",
    "m/84'/1/0'/1/0",
    "m/84'/1'/0'/1'/0",
    "m/84'/1'/0'/1/0'",
    "m/84'/1'/0'/1",
    "m/84'/1'/0'/1/0/0",
    "m/84'/2'/0'/1/0",
    "m/0/1'",
    "m/1'/0'",
    "m",
    "m/",
    "x/84'/1'/0'/1/0",
    "m/84'/1'/0'/1/4294967295",
    "m/84'/1'/0'/2147483648/0",
    "m/84'/1'/2147483647'/1/0",
};
#define N_PATHS (sizeof(paths) / sizeof(paths[0]))

static bool our_script(const char *path, uint8_t out[SCRIPT_P2WPKH_SIZE])
{
    uint8_t pub[BITCOIN_PUBKEY_SIZE];

    return derive_pubkey(&master, path, pub) == PSA_SUCCESS &&
           script_p2wpkh_from_pubkey(pub, out) == PSA_SUCCESS;
}

static void op_begin(void)
{
    bitcoin_tx_begin_t b = {
        .version = u8() < 200 ? 2 : (uint32_t)u64(),
        .locktime = u8() < 200 ? 0 : (uint32_t)u64(),
        .num_inputs = u8() % 20,
        .num_outputs = u8() % 14,
        .sighash_type = u8() < 250 ? BITCOIN_SIGHASH_ALL : u8(),
    };

    changed();
    n_outs = 0;
    sum_in = 0;
    sum_out = 0;
    overflow = false;
    tx_session_begin(&s, &b);
}

static void op_output(void)
{
    bitcoin_tx_output_t o = {0};
    const char *path = paths[u8() % N_PATHS];
    uint8_t kind = u8() % 8;
    uint8_t amount_kind = u8() % 4;
    bool ours = false;

    o.amount = amount_kind == 0 ? u8() : amount_kind == 1 ? u64() % 100000 : u64();
    if (kind <= 2) {
        // A script of ours, with the path that makes it, another path, or none.
        const char *made = paths[1 + u8() % 12];

        ours = our_script(made, o.script);
        o.script_len = SCRIPT_P2WPKH_SIZE;
        if (kind == 0) {
            path = made;
        }
        if (!ours) {
            memset(o.script, 0x41, sizeof(o.script));
            o.script[0] = 0x00;
            o.script[1] = 0x14;
        }
    } else {
        static const uint8_t lens[] = {22, 34, 34, 25, 23, 0, 34, 5};
        static const uint8_t first[] = {0x00, 0x00, 0x51, 0x76, 0xa9, 0x00, 0x52, 0x6a};

        o.script_len = lens[kind];
        for (int i = 0; i < o.script_len; i++) {
            o.script[i] = u8();
        }
        if (o.script_len >= 2 && u8() < 240) {
            o.script[0] = first[kind];
            o.script[1] = (uint8_t)(o.script_len - 2);
            if (kind == 3) {
                memcpy(o.script, "\x76\xa9\x14", 3);
                memcpy(o.script + 23, "\x88\xac", 2);
            } else if (kind == 4) {
                memcpy(o.script, "\xa9\x14", 2);
                o.script[22] = 0x87;
            }
        }
    }
    changed();
    if (tx_session_add_output(&s, &o, path, &master) != PSA_SUCCESS) {
        return;
    }
    if (n_outs == OUTS_MAX) {
        overflow = true;
        return;
    }
    outs[n_outs].amount = o.amount;
    outs[n_outs].len = o.script_len;
    memcpy(outs[n_outs].script, o.script, sizeof(o.script));
    outs[n_outs].ours = ours;
    n_outs++;
    sum_out += o.amount;
}

// A legacy tx with one input and up to 3 outputs. Returns its length.
static size_t make_prev(uint8_t *tx, uint64_t amounts[3], uint32_t *n)
{
    wire_w w = wire_writer(tx, 256);

    *n = 1 + u8() % 3;
    wire_put_le32(&w, 2);
    wire_put_u8(&w, 1);
    for (int i = 0; i < 36; i++) {
        wire_put_u8(&w, u8());
    }
    wire_put_u8(&w, 0);
    wire_put_le32(&w, 0xffffffff);
    wire_put_u8(&w, (uint8_t)*n);
    for (uint32_t i = 0; i < *n; i++) {
        uint8_t kind = u8() % 3;

        amounts[i] = kind == 0 ? u8() : kind == 1 ? u64() % 1000000 : u64();
        wire_put_le64(&w, amounts[i]);
        wire_put_u8(&w, 22);
        wire_put_u8(&w, 0);
        wire_put_u8(&w, 20);
        for (int j = 0; j < 20; j++) {
            wire_put_u8(&w, (uint8_t)j);
        }
    }
    wire_put_le32(&w, 0);
    return w.pos;
}

static void op_input(void)
{
    uint8_t tx[256];
    uint64_t amounts[3] = {0};
    uint32_t n = 0;
    size_t len = make_prev(tx, amounts, &n);
    bitcoin_tx_input_t i = {.vout = u8() % 4,
                            .sequence = u8() < 128 ? 0xfffffffd : (uint32_t)u64()};
    const char *path = paths[u8() % N_PATHS];
    uint8_t lie = u8();

    hash_double_sha256(tx, len, i.txid, 32);
    if (lie == 1) {
        i.txid[0] ^= 1; // another tx
    } else if (lie == 2 && len > 60) {
        tx[47] ^= 1; // the amount of output 0, after the txid was taken
    }
    changed();
    if (tx_session_add_input(&s, &i, path, tx, len) != PSA_SUCCESS) {
        return;
    }
    if (lie == 1 || lie == 2 || i.vout >= n) {
        die("an input was taken with a prev tx that is not the outpoint's");
    }
    sum_in += amounts[i.vout];
}

static uint32_t read_rows(bitcoin_tx_summary_t rows[ROWS_MAX])
{
    uint32_t n = 0;

    while (n < ROWS_MAX && tx_session_get_summary(&s, n, &rows[n]) == PSA_SUCCESS) {
        n++;
    }
    return n;
}

// What the review shows must say where every coin goes.
static void check_rows(void)
{
    bitcoin_tx_summary_t rows[ROWS_MAX];
    uint32_t n = read_rows(rows);
    uint64_t shown = 0;
    bool used[ROWS_MAX] = {false};

    if (n < 2 || rows[0].kind != BITCOIN_TX_SUMMARY_KIND_TOTAL ||
        rows[n - 1].kind != BITCOIN_TX_SUMMARY_KIND_FEE) {
        die("a confirmed tx without a Send row and a Fee row");
    }
    for (uint32_t i = 1; i + 1 < n; i++) {
        if (rows[i].kind != BITCOIN_TX_SUMMARY_KIND_OUTPUT || rows[i].address[0] == '\0') {
            die("an output row without an address");
        }
        shown += rows[i].amount;
    }
    if (rows[0].amount != shown) {
        die("Send is not the sum of the output rows");
    }
    if (rows[n - 1].amount != sum_in - sum_out || sum_in < sum_out) {
        die("Fee is not inputs minus outputs");
    }
    if (overflow) {
        return;
    }
    for (uint32_t o = 0; o < n_outs; o++) {
        char address[BITCOIN_ADDRESS_MAX_SIZE];
        bool found = false;

        if (outs[o].ours) {
            continue;
        }
        if (script_to_address(outs[o].script, outs[o].len, s.coin_type, address, sizeof(address)) !=
            PSA_SUCCESS) {
            die("a confirmed tx with an output that has no address");
        }
        for (uint32_t i = 1; i + 1 < n && !found; i++) {
            if (!used[i] && rows[i].amount == outs[o].amount && !strcmp(rows[i].address, address)) {
                used[i] = true;
                found = true;
            }
        }
        if (!found) {
            die("an output that is not ours is on no row");
        }
    }
}

static void op_confirm(void)
{
    uint8_t id[32];

    changed();
    if (tx_session_confirm(&s, id) == PSA_SUCCESS) {
        check_rows();
    }
}

// The review screen: tx_id and rows in one go, then approve with that tx_id. Or a stale tx_id.
static void op_approve(void)
{
    static uint8_t stale[32];
    uint8_t id[32];
    bool use_stale = u8() < 40;

    if (tx_session_get_tx_id(&s, id) != PSA_SUCCESS) {
        return;
    }
    if (use_stale && memcmp(stale, id, sizeof(id)) != 0) {
        if (tx_session_approve_user(&s, stale) == PSA_SUCCESS) {
            die("approved with another tx_id");
        }
        changed();
        memcpy(stale, id, sizeof(id));
        return;
    }
    memcpy(stale, id, sizeof(id));
    n_rows_at_ok = read_rows(rows_at_ok);
    if (tx_session_approve_user(&s, id) == PSA_SUCCESS) {
        approved = true;
        signed_h = 0;
    }
}

static void op_sign(void)
{
    uint8_t sighash[32];
    uint8_t pub[BITCOIN_PUBKEY_SIZE];
    bitcoin_tx_summary_t rows[ROWS_MAX];
    uint32_t index = u8() % 20;
    const char *path = paths[u8() % N_PATHS];
    uint32_t coin = 0;

    if (tx_session_input_sighash(&s, index, path, &master, sighash, pub) != PSA_SUCCESS) {
        changed();
        return;
    }
    if (!approved) {
        die("a sighash with no approval of this session");
    }
    if (index >= BITCOIN_TX_MAX_INPUTS || (signed_h & (1u << index))) {
        die("an index signed twice");
    }
    if (read_rows(rows) != n_rows_at_ok ||
        memcmp(rows, rows_at_ok, sizeof(rows[0]) * n_rows_at_ok)) {
        die("the rows changed after the approval");
    }
    if (bip32_path_coin_type(path, &coin) != PSA_SUCCESS || coin != s.coin_type) {
        die("signed with a key of another network than the one shown");
    }
    signed_h |= (uint16_t)(1u << index);
    tx_session_mark_signed(&s, index);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static bool ready;
    uint32_t r;

    if (!ready) {
        static const uint8_t seed[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9};

        ready = true;
        base58_init();
        if (psa_crypto_init() != PSA_SUCCESS ||
            bip32_seed_to_master_privkey(seed, sizeof(seed), &master) != PSA_SUCCESS) {
            abort();
        }
    }
    in = data;
    left = size;
    tx_session_reset(&s);
    changed();
    n_outs = 0;
    sum_in = 0;
    sum_out = 0;
    overflow = false;

    while (left > 0) {
        switch (u8() % 10) {
        case 0:
            op_begin();
            break;
        case 1:
        case 2:
            op_output();
            break;
        case 3:
        case 4:
            op_input();
            break;
        case 5:
            op_confirm();
            break;
        case 6:
            if (tx_session_poll(&s, &r) != PSA_SUCCESS) {
                changed();
            }
            break;
        case 7:
            op_approve();
            break;
        case 8:
            op_sign();
            break;
        default:
            tx_session_reset(&s);
            changed();
            break;
        }
    }
    return 0;
}
