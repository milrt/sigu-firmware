// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The signing session of one transaction.
//
// NS sends amounts, scripts, outpoints and paths.
// The partition derives every key, rebuilds every script,
// and computes the commitment hashes, the BIP143 preimages and the summary itself.
//
// Input amounts come from the prev txs: each one is hashed, and its txid must match the outpoint.
// BIP143 commits only to the amount of the input it signs.
// Without this check, NS could run two sessions and lie about a different input in each.
// Each review would show a small fee,
// and the two signatures would combine into a tx with a large fee.
//
// The review screen draws only from tx_session_get_summary() and tx_session_get_details(),
// so it shows the numbers the signature commits to.
// The approve press proves a human pressed a key only the partition reads.
// It does not prove they read the screen.
//
// Outputs go into hash_outputs as they arrive, and only the external ones are kept for the review.
// Inputs are kept, because each BIP143 preimage is built after the approval.
//
//   IDLE --begin--> COLLECT_OUTPUTS --last output--> COLLECT_INPUTS --last input--> READY
//   READY --confirm--> AWAITING_USER --approve--> APPROVED --sign_input, once per input
//
// Abort resets the session to IDLE.
// A begin, output, input, confirm, poll or sign out of order resets it too and fails,
// so a caller cannot search for a state that skips the approval.

#pragma once

#include "bip32.h"
#include "bitcoin/bitcoin_core.h"
#include "shared/hash.h"
#include "shared/tx_records.h"
#include <psa/crypto.h>
#include <stdbool.h>

typedef enum {
    TX_STATE_IDLE = 0,
    TX_STATE_COLLECT_OUTPUTS,
    TX_STATE_COLLECT_INPUTS,
    TX_STATE_READY,
    TX_STATE_AWAITING_USER,
    TX_STATE_APPROVED,
} tx_state_t;

// Where an approval may come from. Set in the session's static initializer, never changed.
// BUTTON is 0, so a zeroed value asks for a key press.
typedef enum {
    APPROVAL_BUTTON = 0,
    APPROVAL_PROGRAMMATIC,
} approval_source_t;

// An input as the session keeps it. The amount is the one read from the prev tx, never a claim.
typedef struct {
    bitcoin_tx_input_t in;
    uint64_t amount;
} tx_input_row_t;

typedef struct {
    tx_state_t state;

    // From begin.
    uint32_t version;
    uint32_t locktime;
    uint32_t sighash_type;
    uint32_t num_inputs;
    uint32_t num_outputs;

    uint32_t inputs_seen;
    uint32_t outputs_seen;
    uint64_t total_in;
    uint64_t total_out;
    uint64_t change_total;

    tx_input_row_t inputs[BITCOIN_TX_MAX_INPUTS];
    // The first BITCOIN_TX_MAX_SHOWN_OUTPUTS external outputs. Confirm refuses a tx with more.
    bitcoin_tx_output_t shown[BITCOIN_TX_MAX_SHOWN_OUTPUTS];
    uint32_t external_count;

    hash_sha256_stream_t outputs_stream;
    uint8_t hash_prevouts[32];
    uint8_t hash_sequence[32];
    uint8_t hash_outputs[32];

    // Binds the approval to this transaction.
    // It is computed again on every sign_input, so an approved session cannot change.
    uint8_t tx_id[32];

    // One bit per input, so one approval gives at most one signature per input.
    _Static_assert(BITCOIN_TX_MAX_INPUTS <= 16, "signed_mask is uint16_t");
    uint16_t signed_mask;

    // From the first path that resolves. Every later path must have the same one.
    // It picks the address HRP and the network whose keys may sign.
    uint32_t coin_type;
    bool coin_type_set;

    // From the first change output.
    // Later change, input and sign paths must use the same account,
    // so the change lands where the wallet looks for it.
    uint32_t account;
    bool account_set;
} tx_session_t;

void tx_session_reset(tx_session_t *s);

psa_status_t tx_session_begin(tx_session_t *s, const bitcoin_tx_begin_t *begin);

// `path` is NULL or empty for an output that is not ours.
// An output is change only at m/84'/c'/a'/1/i, with i below a bound and a the account of the tx,
// and only if the P2WPKH script of that key matches byte for byte.
// Anything else counts as an external payment, which is the safe way to be wrong:
// a wallet does not scan other paths, so change there would be lost.
psa_status_t tx_session_add_output(tx_session_t *s, const bitcoin_tx_output_t *out,
                                   const char *path, const bip32_extended_privkey_t *master);

// `prev_tx` is the tx that `in` spends, in network serialization, with or without the witness.
// Its txid must equal in->txid, and the amount is its output in->vout.
// Every input needs it, ours or not, because the fee counts all of them.
//
// `path` is optional, not kept, and signs nothing.
// It gives the coin type, and it must name the account of the change.
// Confirm refuses a tx where no path, input or change, gives a coin type.
psa_status_t tx_session_add_input(tx_session_t *s, const bitcoin_tx_input_t *in, const char *path,
                                  const uint8_t *prev_tx, size_t prev_tx_len);

// Computes the tx_id and opens the review.
// Refuses a tx with no coin type, with more external outputs than `shown` holds,
// or with an output that has no address (only P2PKH, P2SH, P2WPKH, P2WSH and P2TR do).
// The user cannot approve what the panel cannot show.
psa_status_t tx_session_confirm(tx_session_t *s, uint8_t *tx_id_out);

// BITCOIN_TX_PENDING or BITCOIN_TX_APPROVED. A rejected tx was reset, so the poll fails.
psa_status_t tx_session_poll(tx_session_t *s, uint32_t *result);

// The review.
// These work only in AWAITING_USER and APPROVED,
// so a summary read with the tx_id describes the tx that id binds.
//
// Row `line` of the summary: the total, one row per external output, then the fee.
// PSA_ERROR_DOES_NOT_EXIST past the last row.
// The address comes from the stored script, so the screen never builds one.
psa_status_t tx_session_get_summary(const tx_session_t *s, uint32_t line,
                                    bitcoin_tx_summary_t *out);
psa_status_t tx_session_get_details(const tx_session_t *s, bitcoin_tx_details_t *out);
psa_status_t tx_session_get_tx_id(const tx_session_t *s, uint8_t *tx_id_out);

// The approve press. Approves only if `tx_id` is the tx waiting for the user,
// so the press approves the tx the screen showed.
// Only bitcoin_core_tx_approve_user() calls it, after it checked the wallet session.
psa_status_t tx_session_approve_user(tx_session_t *s, const uint8_t *tx_id);

#ifdef SIGU_SELFTEST
// The test service's approval.
// Only bitcoin_core_tx_approve_programmatic() calls it, after it checked the wallet session.
psa_status_t tx_session_approve_programmatic(tx_session_t *s);
#endif

// The BIP143 sighash of input `index`, from the stored row and the committed hashes,
// and the compressed pubkey for the PSBT partial signature.
psa_status_t tx_session_input_sighash(tx_session_t *s, uint32_t index, const char *path,
                                      const bip32_extended_privkey_t *master, uint8_t *sighash_out,
                                      uint8_t *pubkey_out);

// Marks `index` signed.
// It is separate from the sighash, so an index is spent only after the signature worked.
psa_status_t tx_session_mark_signed(tx_session_t *s, uint32_t index);
