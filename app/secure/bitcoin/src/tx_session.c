// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "tx_session.h"
#include "script.h"
#include "shared/mem_util.h"
#include "shared/wire.h"
#include "sighash.h"
#include "tfm_log.h"
#include <string.h>

// The money supply, in satoshis. Every amount and running total is capped at it,
// so overflow cannot happen, and every number we show stays below 21000000.00000000.
#define TX_MAX_MONEY 2100000000000000ULL

// A wallet scans the change chain from index 0 and stops after about 20 unused addresses,
// so change far past that needs a deep rescan.
// Above this bound the output shows as a payment, with its address and amount.
#define TX_CHANGE_MAX_INDEX 1000u

void tx_session_reset(tx_session_t *s)
{
    if (!s) {
        return;
    }

    // PSA allows an abort on an operation that is not active, or only zeroed.
    hash_sha256_stream_abort(&s->outputs_stream);

    mem_zeroize(s, sizeof(*s));
    s->state = TX_STATE_IDLE;
}

// Any misuse of the protocol drops the whole session.
// It never leaves a state the caller can retry from.
static psa_status_t fail_closed(tx_session_t *s, psa_status_t status)
{
    tx_session_reset(s);
    return status;
}

static psa_status_t note_coin_type(tx_session_t *s, const char *path)
{
    uint32_t coin_type = 0;
    psa_status_t status = bip32_path_coin_type(path, &coin_type);

    if (status == PSA_ERROR_DOES_NOT_EXIST) {
        return PSA_SUCCESS; // Valid path, but too short to name a network.
    }
    if (status != PSA_SUCCESS) {
        return status;
    }

    // We only have mainnet and testnet HRPs,
    // and a transaction that mixes coin types is broken, not just unusual.
    if (coin_type != 0 && coin_type != 1) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (s->coin_type_set && s->coin_type != coin_type) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    s->coin_type = coin_type;
    s->coin_type_set = true;
    return PSA_SUCCESS;
}

// The coin type was already checked by note_coin_type().
// Any other path can still be ours, but no wallet would look for the change there.
static bool is_change_path(const tx_session_t *s, const char *path, uint32_t *account_out)
{
    bip32_bip84_path_t p;

    if (bip32_path_bip84(path, &p) != PSA_SUCCESS) {
        return false;
    }
    if (p.chain != 1 || p.index >= TX_CHANGE_MAX_INDEX) {
        return false;
    }
    if (s->account_set && p.account != s->account) {
        return false;
    }
    *account_out = p.account;
    return true;
}

// Change went to one account.
// If we sign inputs from another account,
// the wallet that tracks those inputs does not see the change.
static psa_status_t check_account(const tx_session_t *s, const char *path)
{
    bip32_bip84_path_t p;

    if (!s->account_set) {
        return PSA_SUCCESS;
    }
    if (bip32_path_bip84(path, &p) != PSA_SUCCESS || p.account != s->account) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return PSA_SUCCESS;
}

static psa_status_t derive_pubkey(const bip32_extended_privkey_t *master, const char *path,
                                  uint8_t *pubkey_out)
{
    bip32_extended_privkey_t derived;
    bip32_extended_pubkey_t pubkey;

    psa_status_t status = bip32_extended_privkey_derive_from_path(master, path, &derived);
    if (status != PSA_SUCCESS) {
        mem_zeroize(&derived, sizeof(derived));
        return status;
    }

    status = bip32_extended_pubkey_from_privkey(&derived, &pubkey);
    mem_zeroize(&derived, sizeof(derived));
    if (status != PSA_SUCCESS) {
        mem_zeroize(&pubkey, sizeof(pubkey));
        return status;
    }

    memcpy(pubkey_out, pubkey.pubkey, BITCOIN_PUBKEY_SIZE);
    mem_zeroize(&pubkey, sizeof(pubkey));
    return PSA_SUCCESS;
}

psa_status_t tx_session_begin(tx_session_t *s, const bitcoin_tx_begin_t *begin)
{
    if (!s || !begin) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // A new begin always throws away what came before,
    // so a half-streamed session cannot leak into a new one.
    tx_session_reset(s);

    if (begin->num_inputs == 0 || begin->num_inputs > BITCOIN_TX_MAX_INPUTS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (begin->num_outputs == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    // NONE, SINGLE and ANYONECANPAY each change what the transaction commits to,
    // so the summary we show would not match what gets authorized.
    if (begin->sighash_type != BITCOIN_SIGHASH_ALL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    psa_status_t status = hash_sha256_stream_init(&s->outputs_stream);
    if (status != PSA_SUCCESS) {
        return status;
    }

    s->version = begin->version;
    s->locktime = begin->locktime;
    s->sighash_type = begin->sighash_type;
    s->num_inputs = begin->num_inputs;
    s->num_outputs = begin->num_outputs;
    s->state = TX_STATE_COLLECT_OUTPUTS;
    return PSA_SUCCESS;
}

psa_status_t tx_session_add_output(tx_session_t *s, const bitcoin_tx_output_t *out,
                                   const char *path, const bip32_extended_privkey_t *master)
{
    if (!s || !out || !master) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (s->state != TX_STATE_COLLECT_OUTPUTS) {
        return fail_closed(s, PSA_ERROR_BAD_STATE);
    }
    if (out->script_len > BITCOIN_TX_SCRIPT_MAX_SIZE) {
        return fail_closed(s, PSA_ERROR_INVALID_ARGUMENT);
    }

    // num_outputs has no limit on purpose: outputs are streamed, not stored.
    // So we check the running total as well as the single amount.
    if (out->amount > TX_MAX_MONEY || s->total_out > TX_MAX_MONEY - out->amount) {
        return fail_closed(s, PSA_ERROR_INVALID_ARGUMENT);
    }

    // Fold into hashOutputs: amount LE64 | compactsize(script_len) | script.
    uint8_t header[9];
    tx_put_le64(header, out->amount);
    header[8] = out->script_len; // always < 253 given the cap above
    psa_status_t status = hash_sha256_stream_update(&s->outputs_stream, header, sizeof(header));
    if (status != PSA_SUCCESS) {
        return fail_closed(s, status);
    }
    status = hash_sha256_stream_update(&s->outputs_stream, out->script, out->script_len);
    if (status != PSA_SUCCESS) {
        return fail_closed(s, status);
    }

    s->total_out += out->amount;

    bool is_change = false;
    uint32_t account = 0;
    if (path && path[0] != '\0') {
        status = note_coin_type(s, path);
        if (status != PSA_SUCCESS) {
            return fail_closed(s, status);
        }
    }

    if (path && path[0] != '\0' && is_change_path(s, path, &account)) {
        uint8_t pubkey[BITCOIN_PUBKEY_SIZE];
        status = derive_pubkey(master, path, pubkey);
        if (status != PSA_SUCCESS) {
            mem_zeroize(pubkey, sizeof(pubkey));
            return fail_closed(s, status);
        }

        // The caller claims this output is our change.
        // Rebuild the scriptPubKey from our own derived key and compare bytes before we believe it.
        uint8_t expected[SCRIPT_P2WPKH_SIZE];
        status = script_p2wpkh_from_pubkey(pubkey, expected);
        mem_zeroize(pubkey, sizeof(pubkey));
        if (status != PSA_SUCCESS) {
            return fail_closed(s, status);
        }

        if (out->script_len == sizeof(expected) &&
            memcmp(expected, out->script, sizeof(expected)) == 0) {
            is_change = true;
            s->change_total += out->amount;
            s->account = account;
            s->account_set = true;
        }
    }

    if (!is_change) {
        if (s->external_count < BITCOIN_TX_MAX_SHOWN_OUTPUTS) {
            s->shown[s->external_count] = *out;
        }
        s->external_count++;
    }

    s->outputs_seen++;
    if (s->outputs_seen == s->num_outputs) {
        status =
            hash_sha256_stream_finish(&s->outputs_stream, s->hash_outputs, sizeof(s->hash_outputs));
        if (status != PSA_SUCCESS) {
            return fail_closed(s, status);
        }
        // hashOutputs is SHA256(SHA256(outputs)), and the stream already did the inner SHA256.
        // Hashing twice here would give a digest nobody else computes.
        uint8_t inner[32];
        memcpy(inner, s->hash_outputs, sizeof(inner));
        status = hash_sha256(inner, sizeof(inner), s->hash_outputs, sizeof(s->hash_outputs));
        mem_zeroize(inner, sizeof(inner));
        if (status != PSA_SUCCESS) {
            return fail_closed(s, status);
        }
        s->state = TX_STATE_COLLECT_INPUTS;
    }

    return PSA_SUCCESS;
}

// Refuses a non-canonical encoding.
// Bitcoin refuses it too, so such a tx has no txid that an outpoint could name.
static uint64_t read_compactsize(wire_r *r)
{
    uint8_t first = wire_get_u8(r);
    uint64_t value = first;
    uint64_t min = 0;

    if (first == 0xFD) {
        value = wire_get_le(r, 2);
        min = 0xFD;
    } else if (first == 0xFE) {
        value = wire_get_le(r, 4);
        min = 0x10000;
    } else if (first == 0xFF) {
        value = wire_get_le64(r);
        min = 0x100000000ULL;
    }
    if (value < min) {
        r->ok = false;
    }
    return value;
}

// The length is a u64 from the tx.
// We compare it before the cast, because size_t is 32 bits on the device.
static void skip_bytes(wire_r *r, uint64_t n)
{
    if (n > r->size - r->pos) {
        r->ok = false;
        return;
    }
    wire_r_take(r, (size_t)n);
}

static psa_status_t prev_txid(const uint8_t *tx, size_t len, bool segwit, size_t witness_start,
                              uint8_t *txid_out)
{
    hash_sha256_stream_t stream;
    uint8_t inner[32];

    psa_status_t status = hash_sha256_stream_init(&stream);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (!segwit) {
        status = hash_sha256_stream_update(&stream, tx, len);
    } else {
        // The txid leaves out the marker, the flag and the witness.
        status = hash_sha256_stream_update(&stream, tx, 4);
        if (status == PSA_SUCCESS) {
            status = hash_sha256_stream_update(&stream, tx + 6, witness_start - 6);
        }
        if (status == PSA_SUCCESS) {
            status = hash_sha256_stream_update(&stream, tx + len - 4, 4);
        }
    }
    if (status != PSA_SUCCESS) {
        hash_sha256_stream_abort(&stream);
        return status;
    }
    status = hash_sha256_stream_finish(&stream, inner, sizeof(inner));
    if (status == PSA_SUCCESS) {
        status = hash_sha256(inner, sizeof(inner), txid_out, BITCOIN_TXID_SIZE);
    }
    mem_zeroize(inner, sizeof(inner));
    return status;
}

// Reads the amount of output `vout` from a previous transaction and computes its txid.
// Every loop stops at the first read past the end, and each pass reads at least one byte,
// so a huge count cannot make a long loop.
static psa_status_t prev_tx_output(const uint8_t *tx, size_t len, uint32_t vout, uint8_t *txid_out,
                                   uint64_t *amount_out)
{
    wire_r r = wire_reader(tx, len);
    bool segwit = false;
    bool found = false;

    if (!tx) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    wire_get_le32(&r); // version
    if (len >= 6 && tx[4] == 0x00) {
        // BIP144 marker.
        // A legacy tx cannot have 0 inputs, so 0x00 here means the segwit form,
        // and only flag 0x01 is defined.
        if (tx[5] != 0x01) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        segwit = true;
        skip_bytes(&r, 2);
    }

    uint64_t num_in = read_compactsize(&r);
    for (uint64_t i = 0; i < num_in && r.ok; i++) {
        skip_bytes(&r, 36); // outpoint
        skip_bytes(&r, read_compactsize(&r));
        skip_bytes(&r, 4); // sequence
    }

    uint64_t num_out = read_compactsize(&r);
    for (uint64_t i = 0; i < num_out && r.ok; i++) {
        uint64_t amount = wire_get_le64(&r);

        skip_bytes(&r, read_compactsize(&r));
        if (i == vout) {
            *amount_out = amount;
            found = true;
        }
    }

    size_t witness_start = r.pos;
    if (segwit) {
        for (uint64_t i = 0; i < num_in && r.ok; i++) {
            uint64_t items = read_compactsize(&r);

            for (uint64_t j = 0; j < items && r.ok; j++) {
                skip_bytes(&r, read_compactsize(&r));
            }
        }
    }
    wire_get_le32(&r); // locktime

    if (!r.ok || r.pos != len || num_in == 0 || !found) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return prev_txid(tx, len, segwit, witness_start, txid_out);
}

psa_status_t tx_session_add_input(tx_session_t *s, const bitcoin_tx_input_t *in, const char *path,
                                  const uint8_t *prev_tx, size_t prev_tx_len)
{
    if (!s || !in) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (s->state != TX_STATE_COLLECT_INPUTS) {
        return fail_closed(s, PSA_ERROR_BAD_STATE);
    }

    // The amount is never a claim.
    // It is in the tx the outpoint names, and the txid proves we read that tx.
    uint8_t txid[BITCOIN_TXID_SIZE];
    uint64_t amount = 0;
    psa_status_t status = prev_tx_output(prev_tx, prev_tx_len, in->vout, txid, &amount);
    if (status != PSA_SUCCESS) {
        return fail_closed(s, status);
    }
    if (memcmp(txid, in->txid, sizeof(txid)) != 0) {
        return fail_closed(s, PSA_ERROR_INVALID_ARGUMENT);
    }

    if (amount > TX_MAX_MONEY || s->total_in > TX_MAX_MONEY - amount) {
        return fail_closed(s, PSA_ERROR_INVALID_ARGUMENT);
    }

    if (path && path[0] != '\0') {
        psa_status_t coin_status = note_coin_type(s, path);
        if (coin_status == PSA_SUCCESS) {
            coin_status = check_account(s, path);
        }
        if (coin_status != PSA_SUCCESS) {
            return fail_closed(s, coin_status);
        }
    }

    // Bounded by the state machine: COLLECT_INPUTS ends on the last input,
    // so inputs_seen < num_inputs <= MAX_INPUTS.
    s->inputs[s->inputs_seen].in = *in;
    s->inputs[s->inputs_seen].amount = amount;

    s->total_in += amount;
    s->inputs_seen++;

    if (s->inputs_seen == s->num_inputs) {
        // From the stored rows in one go, not streamed.
        // Inputs are capped, so this is cheaper than two hash operations open across IPC calls.
        uint8_t prevouts[BITCOIN_TX_MAX_INPUTS * 36];
        uint8_t sequences[BITCOIN_TX_MAX_INPUTS * 4];

        for (uint32_t i = 0; i < s->num_inputs; i++) {
            memcpy(&prevouts[i * 36], s->inputs[i].in.txid, BITCOIN_TXID_SIZE);
            tx_put_le32(&prevouts[i * 36 + 32], s->inputs[i].in.vout);
            tx_put_le32(&sequences[i * 4], s->inputs[i].in.sequence);
        }

        status = hash_double_sha256(prevouts, s->num_inputs * 36, s->hash_prevouts, 32);
        if (status == PSA_SUCCESS) {
            status = hash_double_sha256(sequences, s->num_inputs * 4, s->hash_sequence, 32);
        }
        mem_zeroize(prevouts, sizeof(prevouts));
        mem_zeroize(sequences, sizeof(sequences));
        if (status != PSA_SUCCESS) {
            return fail_closed(s, status);
        }

        // Such a transaction cannot be broadcast,
        // and it means one of the numbers we are about to show is wrong.
        if (s->total_in < s->total_out) {
            return fail_closed(s, PSA_ERROR_INVALID_ARGUMENT);
        }

        s->state = TX_STATE_READY;
    }

    return PSA_SUCCESS;
}

// Binds an approval to this exact transaction.
// It covers everything the summary showed: the Send line, the Fee line and the address HRP.
// Otherwise the recheck at sign time could miss a change after the user agreed.
static psa_status_t compute_tx_id(const tx_session_t *s, uint8_t *out32)
{
    uint8_t material[32 * 3 + 32];
    size_t offset = 0;

    memcpy(&material[offset], s->hash_prevouts, 32);
    offset += 32;
    memcpy(&material[offset], s->hash_sequence, 32);
    offset += 32;
    memcpy(&material[offset], s->hash_outputs, 32);
    offset += 32;
    tx_put_le32(&material[offset], s->version);
    offset += 4;
    tx_put_le32(&material[offset], s->locktime);
    offset += 4;
    tx_put_le32(&material[offset], s->sighash_type);
    offset += 4;
    tx_put_le64(&material[offset], s->total_in);
    offset += 8;
    tx_put_le64(&material[offset], s->change_total);
    offset += 8;
    tx_put_le32(&material[offset], s->coin_type);
    offset += 4;

    return hash_sha256(material, offset, out32, 32);
}

psa_status_t tx_session_confirm(tx_session_t *s, uint8_t *tx_id_out)
{
    if (!s || !tx_id_out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (s->state != TX_STATE_READY) {
        return fail_closed(s, PSA_ERROR_BAD_STATE);
    }
    // No path resolved, so there is no network, and the addresses would use a guessed HRP.
    if (!s->coin_type_set) {
        return fail_closed(s, PSA_ERROR_INVALID_ARGUMENT);
    }
    // If some destinations did not fit,
    // the user would approve a total without seeing where all of the money goes.
    if (s->external_count > BITCOIN_TX_MAX_SHOWN_OUTPUTS) {
        return fail_closed(s, PSA_ERROR_NOT_SUPPORTED);
    }

    psa_status_t status = compute_tx_id(s, s->tx_id);
    if (status != PSA_SUCCESS) {
        return fail_closed(s, status);
    }

    // Every row must render before an approval. A row that fails is one the user never sees.
    // That covers the address, built from the script, and the amount text.
    // Only DOES_NOT_EXIST means "that was the last one".
    for (uint32_t line = 0;; line++) {
        bitcoin_tx_summary_t row;
        char amount[32];

        status = tx_session_get_summary(s, line, &row);
        if (status == PSA_ERROR_DOES_NOT_EXIST) {
            break;
        }
        if (status != PSA_SUCCESS) {
            return fail_closed(s, status);
        }
        if (!tx_format_btc(row.amount, amount, sizeof(amount))) {
            return fail_closed(s, PSA_ERROR_GENERIC_ERROR);
        }

        switch (row.kind) {
        case BITCOIN_TX_SUMMARY_KIND_TOTAL:
            INFO("Send %s BTC\n", amount);
            break;
        case BITCOIN_TX_SUMMARY_KIND_OUTPUT:
            INFO("%s -> %s\n", amount, row.address);
            break;
        default:
            INFO("Fee %s BTC\n", amount);
            break;
        }
    }

    bitcoin_tx_details_t details;

    status = tx_session_get_details(s, &details);
    if (status != PSA_SUCCESS) {
        return fail_closed(s, status);
    }
    if (details.high_fee) {
        INFO("High fee\n");
    }
    if (details.locktime_active) {
        INFO("Locktime %u\n", (unsigned)details.locktime);
    }
    if (details.relative_lock) {
        INFO("Relative lock\n");
    }
    if (details.rbf) {
        INFO("RBF\n");
    }

    s->state = TX_STATE_AWAITING_USER;

    memcpy(tx_id_out, s->tx_id, 32);
    return PSA_SUCCESS;
}

psa_status_t tx_session_poll(tx_session_t *s, uint32_t *result)
{
    if (!s || !result) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (s->state == TX_STATE_APPROVED) {
        *result = BITCOIN_TX_APPROVED;
        return PSA_SUCCESS;
    }
    if (s->state != TX_STATE_AWAITING_USER) {
        return fail_closed(s, PSA_ERROR_BAD_STATE);
    }

    *result = BITCOIN_TX_PENDING;
    return PSA_SUCCESS;
}

psa_status_t tx_session_get_tx_id(const tx_session_t *s, uint8_t *tx_id_out)
{
    if (!s || !tx_id_out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (s->state != TX_STATE_AWAITING_USER && s->state != TX_STATE_APPROVED) {
        return PSA_ERROR_BAD_STATE;
    }

    memcpy(tx_id_out, s->tx_id, 32);
    return PSA_SUCCESS;
}

// A second press while NS signs is not an error.
// It must not reset the session, so any state but AWAITING_USER only refuses.
psa_status_t tx_session_approve_user(tx_session_t *s, const uint8_t *tx_id)
{
    if (!s || !tx_id) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (s->state != TX_STATE_AWAITING_USER) {
        return PSA_ERROR_BAD_STATE;
    }
    // The transaction changed after the screen read it.
    // The user saw a different one, so we drop this one.
    if (memcmp(s->tx_id, tx_id, 32) != 0) {
        return fail_closed(s, PSA_ERROR_BAD_STATE);
    }

    s->state = TX_STATE_APPROVED;
    INFO("OK pressed: transaction approved.\n");
    return PSA_SUCCESS;
}

#ifdef SIGU_SELFTEST
psa_status_t tx_session_approve_programmatic(tx_session_t *s)
{
    if (!s) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (s->state != TX_STATE_AWAITING_USER) {
        return fail_closed(s, PSA_ERROR_BAD_STATE);
    }

    s->state = TX_STATE_APPROVED;
    return PSA_SUCCESS;
}
#endif

psa_status_t tx_session_input_sighash(tx_session_t *s, uint32_t index, const char *path,
                                      const bip32_extended_privkey_t *master, uint8_t *sighash_out,
                                      uint8_t *pubkey_out)
{
    if (!s || !path || !master || !sighash_out || !pubkey_out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (s->state != TX_STATE_APPROVED) {
        return fail_closed(s, PSA_ERROR_BAD_STATE);
    }
    if (index >= s->num_inputs) {
        return fail_closed(s, PSA_ERROR_INVALID_ARGUMENT);
    }
    if (s->signed_mask & (uint16_t)(1u << index)) {
        return fail_closed(s, PSA_ERROR_ALREADY_EXISTS);
    }

    // Recomputing the binding stops an approved session from changing into something else.
    uint8_t tx_id[32];
    psa_status_t status = compute_tx_id(s, tx_id);
    if (status != PSA_SUCCESS) {
        return fail_closed(s, status);
    }
    if (memcmp(tx_id, s->tx_id, sizeof(tx_id)) != 0) {
        return fail_closed(s, PSA_ERROR_INVALID_SIGNATURE);
    }

    // The network of the summary must match the signing key,
    // or a tx shown as testnet could be signed with mainnet keys.
    // confirm() already guarantees coin_type_set, but this is where the coins move.
    uint32_t coin_type = 0;
    status = bip32_path_coin_type(path, &coin_type);
    if (status != PSA_SUCCESS) {
        return fail_closed(s, status);
    }
    if (!s->coin_type_set || coin_type != s->coin_type) {
        return fail_closed(s, PSA_ERROR_INVALID_ARGUMENT);
    }
    // Input paths are only hints.
    // This is the path that signs, so the account rule is enforced here.
    status = check_account(s, path);
    if (status != PSA_SUCCESS) {
        return fail_closed(s, status);
    }

    status = derive_pubkey(master, path, pubkey_out);
    if (status != PSA_SUCCESS) {
        return fail_closed(s, status);
    }

    // scriptCode comes from the key we derived, never from a supplied pubkey.
    uint8_t script_code[SCRIPT_CODE_P2WPKH_SIZE];
    status = script_code_p2wpkh_from_pubkey(pubkey_out, script_code);
    if (status != PSA_SUCCESS) {
        return fail_closed(s, status);
    }

    const tx_input_row_t *row = &s->inputs[index];
    sighash_bip143_params_t params = {
        .version = s->version,
        .hash_prevouts = s->hash_prevouts,
        .hash_sequence = s->hash_sequence,
        .txid = row->in.txid,
        .vout = row->in.vout,
        .script_code = script_code,
        .script_code_len = sizeof(script_code),
        .amount = row->amount,
        .sequence = row->in.sequence,
        .hash_outputs = s->hash_outputs,
        .locktime = s->locktime,
        .sighash_type = s->sighash_type,
    };

    status = sighash_bip143(&params, sighash_out);
    mem_zeroize(script_code, sizeof(script_code));
    if (status != PSA_SUCCESS) {
        return fail_closed(s, status);
    }
    return PSA_SUCCESS;
}

psa_status_t tx_session_mark_signed(tx_session_t *s, uint32_t index)
{
    if (!s || index >= s->num_inputs) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    // A tripwire, not a path NS can reach.
    // The only caller is bitcoin_core_tx_sign_input(), after a signature already exists.
    if (s->state != TX_STATE_APPROVED) {
        return PSA_ERROR_BAD_STATE;
    }
    s->signed_mask |= (uint16_t)(1u << index);
    return PSA_SUCCESS;
}

psa_status_t tx_session_get_summary(const tx_session_t *s, uint32_t line, bitcoin_tx_summary_t *out)
{
    if (!s || !out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (s->state != TX_STATE_READY && s->state != TX_STATE_AWAITING_USER &&
        s->state != TX_STATE_APPROVED) {
        return PSA_ERROR_BAD_STATE;
    }

    memset(out, 0, sizeof(*out));

    // Row 0 is the total leaving the wallet, then one row per external output, then the fee.
    // Change is not shown: it was checked against our own key.
    // confirm() refuses more external outputs than slots, so no row is missing.
    if (line == 0) {
        out->kind = BITCOIN_TX_SUMMARY_KIND_TOTAL;
        out->amount = s->total_out - s->change_total;
        return PSA_SUCCESS;
    }

    if (line <= s->external_count) {
        const bitcoin_tx_output_t *o = &s->shown[line - 1];

        out->kind = BITCOIN_TX_SUMMARY_KIND_OUTPUT;
        out->amount = o->amount;
        return script_to_address(o->script, o->script_len, s->coin_type, out->address,
                                 sizeof(out->address));
    }

    if (line == s->external_count + 1) {
        out->kind = BITCOIN_TX_SUMMARY_KIND_FEE;
        out->amount = s->total_in - s->total_out;
        return PSA_SUCCESS;
    }

    return PSA_ERROR_DOES_NOT_EXIST;
}

// BIP68: a sequence with bit 31 clear is a relative lock in a v2 tx.
// The low 16 bits are the value, so 0 waits for nothing.
static bool is_relative_lock(uint32_t version, uint32_t sequence)
{
    return version >= 2 && !(sequence & 0x80000000u) && (sequence & 0xFFFFu) != 0;
}

psa_status_t tx_session_get_details(const tx_session_t *s, bitcoin_tx_details_t *out)
{
    if (!s || !out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (s->state != TX_STATE_READY && s->state != TX_STATE_AWAITING_USER &&
        s->state != TX_STATE_APPROVED) {
        return PSA_ERROR_BAD_STATE;
    }

    memset(out, 0, sizeof(*out));

    // Every amount is capped at TX_MAX_MONEY, so fee * 20 fits in a u64.
    // With no send, all that leaves is the fee, so we compare with the inputs.
    uint64_t send = s->total_out - s->change_total;
    uint64_t fee = s->total_in - s->total_out;
    uint64_t base = send ? send + fee : s->total_in;
    out->high_fee = fee * 20 > base;

    bool all_final = true;
    for (uint32_t i = 0; i < s->num_inputs; i++) {
        uint32_t seq = s->inputs[i].in.sequence;

        all_final = all_final && seq == 0xFFFFFFFFu;
        out->rbf = out->rbf || seq < 0xFFFFFFFEu;
        out->relative_lock = out->relative_lock || is_relative_lock(s->version, seq);
    }

    // Bitcoin ignores the locktime when every input is final.
    out->locktime_active = s->locktime != 0 && !all_final;
    out->locktime = s->locktime;
    return PSA_SUCCESS;
}
