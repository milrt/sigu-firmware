// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The wallet sessions of the partition.
// The IPC handlers in bitcoin_service.c and the screens call this.
// Calls that say "panel only" have no opcode, so NS cannot reach them.

#pragma once

#include "shared/bitcoin_service_defs.h"
#include "shared/tx_records.h"
#include <psa/crypto.h>
#include <stdbool.h>
#include <stddef.h>

// Sessions

// Opaque. The instances below are the only ones,
// and the service a message arrived on picks the one a call works on.
typedef struct wallet_session wallet_session_t;

// The user's wallet: approval by key press, and the production PS UIDs.
wallet_session_t *bitcoin_core_session_production(void);

#ifdef SIGU_SELFTEST
// The self-test wallet: approval without a key press, and its own PS UIDs.
// It is safe only because it never holds a real key:
// only bitcoin_core_open_ephemeral() seeds it, from a mnemonic the caller gives, never from PS.
// So the test service signs only for a published test vector. A release build does not have it.
wallet_session_t *bitcoin_core_session_test(void);
#endif

// Panics unless the sessions still have those properties. tfm_bitcoin_init() calls it once.
void bitcoin_core_init(void);

// Wallet state

// One of BITCOIN_STATUS_*.
// A PS error is returned as the error, never as a state,
// so a broken PS does not look like "no wallet, set one up".
// A record this app cannot read is UNREADABLE, never NONE.
// `attempts_out` is the wrong PINs left when LOCKED, else BITCOIN_ATTEMPTS_NA.
psa_status_t bitcoin_core_status(wallet_session_t *w, uint32_t *state_out, uint32_t *attempts_out);

// Whether PS holds a wallet, whatever the session state.
// A temporary wallet reports OPEN in the status but has no record.
// PSA_ERROR_DATA_INVALID for a record this app cannot read.
psa_status_t bitcoin_core_stored(wallet_session_t *w, bool *exists);

// Setup, panel only.
// Create writes the new words to `mnemonic_out`, so the panel shows them in the same call.
// Create and recover start a setup, confirm stores it under `pin`, and abort drops it.
// Confirm clears the session whatever the result.
psa_status_t bitcoin_core_create(wallet_session_t *w, size_t entropy_size, char *mnemonic_out,
                                 size_t mnemonic_size);
psa_status_t bitcoin_core_recover(wallet_session_t *w, const char *mnemonic);
psa_status_t bitcoin_core_confirm(wallet_session_t *w, const char *pin);
psa_status_t bitcoin_core_abort_setup(wallet_session_t *w);

// Open and close, panel only.
// A temporary wallet comes from words typed on the panel, with no PS and no PIN.
// Only the production session takes one.
psa_status_t bitcoin_core_open(wallet_session_t *w, const char *pin, const char *passphrase);
psa_status_t bitcoin_core_open_temporary(wallet_session_t *w, const char *mnemonic,
                                         const char *passphrase);
bool bitcoin_core_is_temporary(wallet_session_t *w);
psa_status_t bitcoin_core_close(wallet_session_t *w);

#ifdef SIGU_SELFTEST
// Opens the test session from `mnemonic`, with no PS and no PIN, in place of an open wallet.
// Refused on the production session.
psa_status_t bitcoin_core_open_ephemeral(wallet_session_t *w, const char *mnemonic,
                                         const char *passphrase);
#endif

// Wipes, panel only.
// Destroy removes the stored wallet after the PIN, and a wrong PIN costs a try.
// Once the record is gone, by destroy or by the last wrong PIN, the session closes too.
// Discard removes only an unreadable record, with no PIN because none can be checked.
// It refuses a readable record with PSA_ERROR_BAD_STATE.
psa_status_t bitcoin_core_destroy(wallet_session_t *w, const char *pin);
psa_status_t bitcoin_core_discard_unreadable(wallet_session_t *w);

// Keys

// BIP84 paths only, because P2WPKH is the only script this partition spends from.
// The path's coin type picks the xpub version bytes and the address HRP,
// so a caller cannot label a key for a network it was not derived under.
psa_status_t bitcoin_core_get_xpub(wallet_session_t *w, const char *derivation_path, char *xpub,
                                   size_t xpub_size);
psa_status_t bitcoin_core_get_address(wallet_session_t *w, const char *derivation_path,
                                      char *address, size_t address_size);
psa_status_t bitcoin_core_get_fingerprint(wallet_session_t *w,
                                          uint8_t fingerprint[BITCOIN_FINGERPRINT_SIZE]);

// Signing. tx_session.h has the state machine and the checks.
// For an input, `prev_tx` is the tx it spends, and the amount comes from it.
// `path` is optional. It is not kept and does not pick the signing key.
psa_status_t bitcoin_core_tx_begin(wallet_session_t *w, const bitcoin_tx_begin_t *begin);
psa_status_t bitcoin_core_tx_output(wallet_session_t *w, const bitcoin_tx_output_t *out,
                                    const char *path);
psa_status_t bitcoin_core_tx_input(wallet_session_t *w, const bitcoin_tx_input_t *in,
                                   const char *path, const uint8_t *prev_tx, size_t prev_tx_len);
psa_status_t bitcoin_core_tx_confirm(wallet_session_t *w, uint8_t *tx_id32);
psa_status_t bitcoin_core_tx_poll(wallet_session_t *w, uint32_t *result);
psa_status_t bitcoin_core_tx_sign_input(wallet_session_t *w, uint32_t index, const char *path,
                                        uint8_t *signature, size_t *signature_size,
                                        uint8_t *pubkey);
psa_status_t bitcoin_core_tx_abort(wallet_session_t *w);

// The review screen

// What the total page shows next to the summary. The tx_id covers all of it.
typedef struct {
    bool high_fee;        // the fee is over 5% of what leaves the wallet
    bool locktime_active; // locktime != 0 and some input sequence is not final
    uint32_t locktime;    // below 500000000 a block height, else a unix time
    bool relative_lock;   // a BIP68 lock on some input
    bool rbf;             // BIP125: some sequence is below 0xFFFFFFFE
} bitcoin_tx_details_t;

// Panel only. The screen reads the tx_id with the rows, and approve passes it back,
// so the press approves the transaction on screen.
// A different tx_id fails closed. Approval refuses on the test session.
psa_status_t bitcoin_core_tx_get_summary(wallet_session_t *w, uint32_t line,
                                         bitcoin_tx_summary_t *out);
psa_status_t bitcoin_core_tx_get_details(wallet_session_t *w, bitcoin_tx_details_t *out);
psa_status_t bitcoin_core_tx_get_tx_id(wallet_session_t *w, uint8_t *tx_id32);
psa_status_t bitcoin_core_tx_approve_user(wallet_session_t *w, const uint8_t *tx_id32);

#ifdef SIGU_SELFTEST
// The test service's stand-in for the approve press. Refused on the production session.
psa_status_t bitcoin_core_tx_approve_programmatic(wallet_session_t *w);
#endif
