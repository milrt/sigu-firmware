// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The NS side of the ABI in shared/bitcoin_service_defs.h. One function per opcode.
// Each call connects, calls and closes.

#pragma once

#include "shared/bitcoin_service_defs.h"
#include "shared/tx_records.h"
#include <psa/crypto.h>
#include <stddef.h>

// The service a call goes to.
// It picks the wallet session in the partition, and nothing in the payload does.
typedef struct {
    uint32_t sid;
    uint32_t version;
} bitcoin_service_t;

extern const bitcoin_service_t bitcoin_service; // the user's wallet

#ifdef CONFIG_SIGU_SELFTEST
extern const bitcoin_service_t bitcoin_service_test; // the test wallet
#endif

// Production service only, because it reads PS.
// One of BITCOIN_STATUS_*, and the wrong PINs left when LOCKED, else BITCOIN_ATTEMPTS_NA.
psa_status_t bitcoin_client_status(uint32_t *state_out, uint32_t *attempts_out);

// Keys, on either service. The xpub at `derivation_path`, NUL terminated.
// `xpub_size` is the buffer size in and the written size out.
psa_status_t bitcoin_client_get_xpub(const bitcoin_service_t *svc, const char *derivation_path,
                                     char *xpub_out, size_t *xpub_size);
psa_status_t bitcoin_client_get_fingerprint(const bitcoin_service_t *svc,
                                            bitcoin_fingerprint_t *fingerprint);

// Signing, on either service.
// The partition builds the sighash itself,
// so a signature needs the whole transaction and the approve press on the panel.
// The order is fixed: begin, the outputs, the inputs, confirm, poll until approved,
// then one sign_input per input. A wrong order fails and drops the transaction.
psa_status_t bitcoin_client_tx_begin(const bitcoin_service_t *svc, const bitcoin_tx_begin_t *begin);

// `change_path` is NULL or "" for an output that is not ours.
// With a path, the partition derives the scriptPubKey again before it calls the output change.
psa_status_t bitcoin_client_tx_output(const bitcoin_service_t *svc, const bitcoin_tx_output_t *out,
                                      const char *change_path);

// `prev_tx` is the tx this input spends (PSBT_IN_NON_WITNESS_UTXO).
// The partition checks its txid and reads the amount from it.
// `path` is NULL for an input that is not ours.
// It sets the network and must match the change account, but does not pick the signing key.
psa_status_t bitcoin_client_tx_input(const bitcoin_service_t *svc, const bitcoin_tx_input_t *in,
                                     const char *path, const uint8_t *prev_tx, size_t prev_tx_len);

psa_status_t bitcoin_client_tx_confirm(const bitcoin_service_t *svc);

// Does not block. `result` is one of BITCOIN_TX_*, so call it again while the user reads.
psa_status_t bitcoin_client_tx_poll(const bitcoin_service_t *svc, uint32_t *result);

psa_status_t bitcoin_client_tx_sign_input(const bitcoin_service_t *svc, uint32_t index,
                                          const char *derivation_path, uint8_t *signature_der,
                                          size_t *signature_size, bitcoin_pubkey_t *pubkey_out);
psa_status_t bitcoin_client_tx_abort(const bitcoin_service_t *svc);

// The card, production service only, because these change the panel.

// Replaces the file list and the card state.
// `names` is `n` slots of BITCOIN_FILE_NAME_MAX_SIZE bytes.
// `fw` is the firmware state, and `installs` is `n_installs` install records.
// A refused list leaves the partition with an empty one.
psa_status_t bitcoin_client_files_set(const char *names, size_t n, uint32_t card,
                                      const uint8_t fw[BITCOIN_FW_STATE_SIZE],
                                      const uint8_t *installs, size_t n_installs);

// Takes the job the user started on the panel.
// `kind` is one of BITCOIN_JOB_*, and `name` is the file of a sign job, else empty.
psa_status_t bitcoin_client_files_poll(char name[BITCOIN_FILE_NAME_MAX_SIZE], uint32_t *kind);

// Ends the job the last poll took, with a BITCOIN_FILES_* or BITCOIN_INSTALL_* code.
psa_status_t bitcoin_client_files_result(uint32_t code);

#ifdef CONFIG_SIGU_SELFTEST
// The test service. These take no `svc`, so no caller can aim them at the user's wallet.
psa_status_t bitcoin_client_test_run_all(void);

// Opens the test wallet from `mnemonic`, in place of an open one. No PIN, nothing stored.
psa_status_t bitcoin_client_test_open_ephemeral(const char *mnemonic, const char *passphrase);

// Stands in for the approve press on the review screen.
// Call it while psbt_sign() waits, from its `on_wait`.
psa_status_t bitcoin_client_test_approve(void);
#endif
