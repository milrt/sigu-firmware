// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/bitcoin_core.h"
#include "base58.h"
#include "display/display.h"
#include "drivers/tamper.h"
#include "files/files.h"
#include "shared/bitcoin_service_defs.h"
#include "shared/mem_util.h"
#include "shared/tx_records.h"
#include "shared/wire.h"
#include "spu.h"
#include "tfm_log.h"
#include <psa/service.h>
#include <psa_manifest/tfm_bitcoin_partition.h>
#include <stdbool.h>
#include <string.h>

#ifdef SIGU_SELFTEST
#include "bitcoin/secure_bitcoin_test.h"
#endif

// sbrk workaround for secp256k1. newlib expects (void *)-1 as the out-of-memory value.
// With NULL the allocator computes a wrong heap end instead of reporting the failure.
void *_sbrk(ptrdiff_t incr)
{
    (void)incr;
    return (void *)-1;
}

// Rejects an argument that does not fit instead of truncating it.
// A shortened mnemonic or passphrase derives a different key,
// and two secrets with the same prefix become one. A shortened path names another key.
static psa_status_t read_string_arg(psa_msg_t *msg, uint32_t index, char *out_buf,
                                    size_t out_buf_size)
{
    if (msg->in_size[index] >= out_buf_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t bytes_read = psa_read(msg->handle, index, out_buf, out_buf_size - 1);
    out_buf[bytes_read] = '\0';
    return PSA_SUCCESS;
}

// A u32 or a fixed record. Fails unless `size` bytes arrive.
static psa_status_t read_exact(psa_msg_t *msg, uint32_t index, void *buf, size_t size)
{
    return psa_read(msg->handle, index, buf, size) == size ? PSA_SUCCESS
                                                           : PSA_ERROR_INVALID_ARGUMENT;
}

// A missing or empty path invec leaves `buf` empty, which means "not ours".
static psa_status_t read_opt_path(psa_msg_t *msg, uint32_t index, char buf[BITCOIN_PATH_MAX_SIZE])
{
    buf[0] = '\0';
    if (msg->in_size[index] == 0) {
        return PSA_SUCCESS;
    }
    return read_string_arg(msg, index, buf, BITCOIN_PATH_MAX_SIZE);
}

static psa_status_t write_out(psa_msg_t *msg, uint32_t index, const void *buf, size_t len)
{
    if (msg->out_size[index] < len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    psa_write(msg->handle, index, buf, len);
    return PSA_SUCCESS;
}

static psa_status_t write_str(psa_msg_t *msg, uint32_t index, const char *s)
{
    return write_out(msg, index, s, strlen(s) + 1);
}

static psa_status_t tfm_bitcoin_status_ipc(wallet_session_t *w, psa_msg_t *msg)
{
    uint32_t state = BITCOIN_STATUS_NONE;
    uint32_t attempts = BITCOIN_ATTEMPTS_NA;

    psa_status_t status = bitcoin_core_status(w, &state, &attempts);
    if (status == PSA_SUCCESS && msg->out_size[1] < sizeof(attempts)) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (status == PSA_SUCCESS) {
        status = write_out(msg, 0, &state, sizeof(state));
    }
    if (status == PSA_SUCCESS) {
        psa_write(msg->handle, 1, &attempts, sizeof(attempts));
    }
    return status;
}

static psa_status_t tfm_bitcoin_get_xpub_ipc(wallet_session_t *w, psa_msg_t *msg)
{
    char path[BITCOIN_PATH_MAX_SIZE] = {0};
    char xpub[BITCOIN_XPUB_MAX_SIZE] = {0};

    psa_status_t status = read_string_arg(msg, 0, path, sizeof(path));
    if (status == PSA_SUCCESS) {
        status = bitcoin_core_get_xpub(w, path, xpub, sizeof(xpub));
    }
    if (status == PSA_SUCCESS) {
        status = write_str(msg, 0, xpub);
    }
    return status;
}

#ifdef SIGU_SELFTEST
static psa_status_t tfm_bitcoin_open_ephemeral_ipc(wallet_session_t *w, psa_msg_t *msg)
{
    char mnemonic[BITCOIN_MNEMONIC_MAX_SIZE] = {0};
    char passphrase[BITCOIN_PASSPHRASE_MAX_SIZE] = {0};

    psa_status_t status = read_string_arg(msg, 0, mnemonic, sizeof(mnemonic));
    if (status == PSA_SUCCESS) {
        status = read_string_arg(msg, 1, passphrase, sizeof(passphrase));
    }
    if (status == PSA_SUCCESS) {
        status = bitcoin_core_open_ephemeral(w, mnemonic, passphrase);
    }

    mem_zeroize(mnemonic, sizeof(mnemonic));
    mem_zeroize(passphrase, sizeof(passphrase));
    return status;
}
#endif

static psa_status_t tfm_bitcoin_get_fingerprint_ipc(wallet_session_t *w, psa_msg_t *msg)
{
    uint8_t fingerprint[BITCOIN_FINGERPRINT_SIZE] = {0};

    psa_status_t status = bitcoin_core_get_fingerprint(w, fingerprint);
    if (status == PSA_SUCCESS) {
        status = write_out(msg, 0, fingerprint, sizeof(fingerprint));
    }
    return status;
}

static psa_status_t tfm_bitcoin_tx_begin_ipc(wallet_session_t *w, psa_msg_t *msg)
{
    bitcoin_tx_begin_rec_t rec;
    bitcoin_tx_begin_t begin;

    psa_status_t status = read_exact(msg, 0, &rec, sizeof(rec));
    if (status == PSA_SUCCESS) {
        bitcoin_tx_begin_unpack(&rec, &begin);
        status = bitcoin_core_tx_begin(w, &begin);
    }
    return status;
}

// A bad record or path aborts the tx. Misuse fails closed wherever we catch it.
static psa_status_t tfm_bitcoin_tx_output_ipc(wallet_session_t *w, psa_msg_t *msg)
{
    bitcoin_tx_output_rec_t rec;
    bitcoin_tx_output_t out;
    char path[BITCOIN_PATH_MAX_SIZE];

    psa_status_t status = read_exact(msg, 0, &rec, sizeof(rec));
    if (status != PSA_SUCCESS) {
        return status;
    }

    // A path is only a claim. It is checked by rebuilding the scriptPubKey.
    status = read_opt_path(msg, 1, path);
    if (status == PSA_SUCCESS && !bitcoin_tx_output_unpack(&rec, &out)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
    }
    if (status == PSA_SUCCESS) {
        status = bitcoin_core_tx_output(w, &out, path);
    } else {
        bitcoin_core_tx_abort(w);
    }

    mem_zeroize(path, sizeof(path));
    return status;
}

// The prev tx of one input, in2 of TFM_BITCOIN_TX_INPUT.
// Static because the partition stack is small, and one thread handles every message.
static uint8_t prev_tx_buf[BITCOIN_PREV_TX_MAX_SIZE];

static psa_status_t tfm_bitcoin_tx_input_ipc(wallet_session_t *w, psa_msg_t *msg)
{
    bitcoin_tx_input_rec_t rec;
    bitcoin_tx_input_t in;
    char path[BITCOIN_PATH_MAX_SIZE];
    const size_t prev_tx_len = msg->in_size[2];

    psa_status_t status = read_exact(msg, 0, &rec, sizeof(rec));
    if (status != PSA_SUCCESS) {
        return status;
    }

    // Optional. It sets the network, see tx_session_add_input().
    status = read_opt_path(msg, 1, path);
    if (status == PSA_SUCCESS && (prev_tx_len == 0 || prev_tx_len > sizeof(prev_tx_buf))) {
        status = PSA_ERROR_INVALID_ARGUMENT;
    }
    if (status == PSA_SUCCESS) {
        status = read_exact(msg, 2, prev_tx_buf, prev_tx_len);
    }
    if (status == PSA_SUCCESS) {
        bitcoin_tx_input_unpack(&rec, &in);
        status = bitcoin_core_tx_input(w, &in, path, prev_tx_buf, prev_tx_len);
    } else {
        bitcoin_core_tx_abort(w);
    }

    mem_zeroize(path, sizeof(path));
    return status;
}

// NS gets no tx_id. The review screen reads it and passes it back on approve.
static psa_status_t tfm_bitcoin_tx_confirm_ipc(wallet_session_t *w)
{
    uint8_t tx_id[BITCOIN_TXID_SIZE];

    return bitcoin_core_tx_confirm(w, tx_id);
}

static psa_status_t tfm_bitcoin_tx_poll_ipc(wallet_session_t *w, psa_msg_t *msg)
{
    uint32_t result = BITCOIN_TX_PENDING;

    psa_status_t status = bitcoin_core_tx_poll(w, &result);
    if (status == PSA_SUCCESS) {
        status = write_out(msg, 0, &result, sizeof(result));
    }
    return status;
}

static psa_status_t tfm_bitcoin_tx_sign_input_ipc(wallet_session_t *w, psa_msg_t *msg)
{
    uint32_t index = 0;
    char path[BITCOIN_PATH_MAX_SIZE] = {0};
    uint8_t signature[BITCOIN_SIGNATURE_MAX_SIZE] = {0};
    uint8_t pubkey[BITCOIN_PUBKEY_SIZE] = {0};
    size_t signature_size = sizeof(signature);

    psa_status_t status = read_exact(msg, 0, &index, sizeof(index));
    if (status == PSA_SUCCESS) {
        status = read_string_arg(msg, 1, path, sizeof(path));
    }
    if (status == PSA_SUCCESS) {
        status = bitcoin_core_tx_sign_input(w, index, path, signature, &signature_size, pubkey);
    }

    // Both sizes first, so NS gets both outvecs or neither.
    if (status == PSA_SUCCESS &&
        (msg->out_size[0] < signature_size || msg->out_size[1] < sizeof(pubkey))) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (status == PSA_SUCCESS) {
        psa_write(msg->handle, 0, signature, signature_size);
        psa_write(msg->handle, 1, pubkey, sizeof(pubkey));
        if (w == bitcoin_core_session_production()) {
            files_job_note_signed();
        }
    }

    mem_zeroize(path, sizeof(path));
    mem_zeroize(signature, sizeof(signature));
    return status;
}

// in2 is the firmware state, in3 the install records (0 to BITCOIN_INSTALLS_MAX).
// A bad state resets it, and a bad record leaves no install files.
static psa_status_t read_install(psa_msg_t *msg)
{
    uint8_t records[BITCOIN_INSTALLS_MAX * BITCOIN_INSTALL_RECORD_SIZE];
    uint8_t fw[BITCOIN_FW_STATE_SIZE];
    size_t len = msg->in_size[3];
    uint32_t boot_version;
    uint8_t status;
    wire_r r;

    files_set_fw(0, BITCOIN_FW_OK);
    files_set_installs(NULL, 0);
    if (read_exact(msg, 2, fw, sizeof(fw)) != PSA_SUCCESS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    r = wire_reader(fw, sizeof(fw));
    boot_version = wire_get_le32(&r);
    status = wire_get_u8(&r);
    if (!r.ok || status > BITCOIN_FW_CONFIRMING) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    files_set_fw(boot_version, status);
    display_fw_state(status);
    if (len > sizeof(records) || (len > 0 && read_exact(msg, 3, records, len) != PSA_SUCCESS) ||
        !files_set_installs(records, len)) {
        files_set_installs(NULL, 0);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return PSA_SUCCESS;
}

// One name per psa_read(), so the list never sits on the stack.
// A bad name leaves an empty list, because a half list would look complete on the panel.
// in1 is the card state.
static psa_status_t tfm_bitcoin_files_set_ipc(psa_msg_t *msg)
{
    const size_t in_size = msg->in_size[0];
    uint32_t card = BITCOIN_CARD_NONE;
    char name[BITCOIN_FILE_NAME_MAX_SIZE];

    files_clear();
    if (psa_read(msg->handle, 1, &card, sizeof(card)) != sizeof(card) ||
        card > BITCOIN_CARD_ERROR) {
        files_set_card(BITCOIN_CARD_NONE);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    files_set_card(card);

    if (in_size % sizeof(name) != 0 || in_size / sizeof(name) > BITCOIN_FILES_MAX) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    for (size_t i = 0; i < in_size / sizeof(name); i++) {
        if (psa_read(msg->handle, 0, name, sizeof(name)) != sizeof(name) || name[0] == '\0' ||
            !files_add(name)) {
            files_clear();
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    return read_install(msg);
}

// out0 gets the name to sign, NUL terminated, or only a NUL for no job, an install or an export.
// out1 gets the job kind. The sizes are checked before the take, so a short outvec loses nothing.
static psa_status_t tfm_bitcoin_files_poll_ipc(psa_msg_t *msg)
{
    uint32_t kind = BITCOIN_JOB_SIGN;
    const char *name;

    if (msg->out_size[0] < BITCOIN_FILE_NAME_MAX_SIZE || msg->out_size[1] < sizeof(kind)) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    name = files_job_take(&kind);
    if (name) {
        psa_write(msg->handle, 0, name, BITCOIN_FILE_NAME_MAX_SIZE);
    } else {
        psa_write(msg->handle, 0, "", 1);
    }
    psa_write(msg->handle, 1, &kind, sizeof(kind));
    return PSA_SUCCESS;
}

static psa_status_t tfm_bitcoin_files_result_ipc(psa_msg_t *msg)
{
    uint32_t code = 0;

    if (read_exact(msg, 0, &code, sizeof(code)) != PSA_SUCCESS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return files_job_finish(code) ? PSA_SUCCESS : PSA_ERROR_BAD_STATE;
}

#ifdef SIGU_SELFTEST
static psa_status_t tfm_bitcoin_test_run_ipc(psa_msg_t *msg)
{
    psa_status_t rc = secure_bitcoin_test_run_all();

    (void)msg;
    // The test library does not see the drivers, so the hardware is checked here.
    if (!tamper_ok()) {
        ERROR("tamper detectors not locked\n");
        return PSA_ERROR_GENERIC_ERROR;
    }
    INFO("Tamper detectors: locked\n");
    return rc;
}

static psa_status_t tfm_bitcoin_test_tx_approve_ipc(wallet_session_t *w, psa_msg_t *msg)
{
    (void)msg;
    return bitcoin_core_tx_approve_programmatic(w);
}

#endif

// Opcodes that reach key_storage_*, so PS. Dispatched ONLY from the production service.
// Kept apart, so "the test service cannot touch storage" is checked at two call sites.
//
// Returns false without replying if the opcode is not one of these.
static bool dispatch_storage_op(wallet_session_t *w, psa_msg_t *msg, psa_status_t *rc)
{
    switch (msg->type) {
    case TFM_BITCOIN_STATUS:
        *rc = tfm_bitcoin_status_ipc(w, msg);
        return true;
    default:
        return false;
    }
}

// Opcodes on an open in-RAM session, with no storage.
// Every service dispatches them, each on its own wallet: the SID picks the session.
//
// Returns false without replying if the opcode is not one of these.
static bool dispatch_session_op(wallet_session_t *w, psa_msg_t *msg, psa_status_t *rc)
{
    switch (msg->type) {
    case TFM_BITCOIN_GET_XPUB:
        *rc = tfm_bitcoin_get_xpub_ipc(w, msg);
        return true;
    case TFM_BITCOIN_GET_FINGERPRINT:
        *rc = tfm_bitcoin_get_fingerprint_ipc(w, msg);
        return true;
    case TFM_BITCOIN_TX_BEGIN:
        *rc = tfm_bitcoin_tx_begin_ipc(w, msg);
        return true;
    case TFM_BITCOIN_TX_OUTPUT:
        *rc = tfm_bitcoin_tx_output_ipc(w, msg);
        return true;
    case TFM_BITCOIN_TX_INPUT:
        *rc = tfm_bitcoin_tx_input_ipc(w, msg);
        return true;
    case TFM_BITCOIN_TX_CONFIRM:
        *rc = tfm_bitcoin_tx_confirm_ipc(w);
        return true;
    case TFM_BITCOIN_TX_POLL:
        *rc = tfm_bitcoin_tx_poll_ipc(w, msg);
        return true;
    case TFM_BITCOIN_TX_SIGN_INPUT:
        *rc = tfm_bitcoin_tx_sign_input_ipc(w, msg);
        return true;
    case TFM_BITCOIN_TX_ABORT:
        *rc = bitcoin_core_tx_abort(w);
        return true;
    default:
        return false;
    }
}

// Production service: the production wallet only, and no opcode that approves a transaction.
// Approval comes from the approve press on the review screen.
// TFM_BITCOIN_TX_POLL only reports it.
//
// The TFM_BITCOIN_FILES_* opcodes change what the panel shows, so the test service has none.
// They touch no wallet and no PS.
// FILES_SET can change the failed install bit in the ITS config record, see status.c.
static void handle_bitcoin_signal(psa_msg_t *msg)
{
    wallet_session_t *w = bitcoin_core_session_production();
    psa_status_t rc = PSA_ERROR_NOT_SUPPORTED;

    switch (msg->type) {
    case PSA_IPC_CONNECT:
    case PSA_IPC_DISCONNECT:
        psa_reply(msg->handle, PSA_SUCCESS);
        return;
    case TFM_BITCOIN_FILES_SET:
        psa_reply(msg->handle, tfm_bitcoin_files_set_ipc(msg));
        return;
    case TFM_BITCOIN_FILES_POLL:
        psa_reply(msg->handle, tfm_bitcoin_files_poll_ipc(msg));
        return;
    case TFM_BITCOIN_FILES_RESULT:
        psa_reply(msg->handle, tfm_bitcoin_files_result_ipc(msg));
        return;
    default:
        break;
    }

    if (dispatch_storage_op(w, msg, &rc) || dispatch_session_op(w, msg, &rc)) {
        psa_reply(msg->handle, rc);
        return;
    }

    // An unknown opcode is a caller bug, not a reason to kill the secure world.
    // Never psa_panic() here, NS could use it as a DoS.
    psa_reply(msg->handle, PSA_ERROR_NOT_SUPPORTED);
}

#ifdef SIGU_SELFTEST
// Test service: the test wallet only, seeded from a mnemonic the caller gives, never from PS.
// The only way to the programmatic approval and the ephemeral open.
//
// dispatch_storage_op() is not called here on purpose, so the test wallet lives only in RAM.
// The exception is TFM_BITCOIN_TEST_RUN:
// the self-tests store, load and wipe a blob under key_storage_uids_test, the code they test.
// They never name the production UID.
static void handle_bitcoin_test_signal(psa_msg_t *msg)
{
    wallet_session_t *w = bitcoin_core_session_test();
    psa_status_t rc = PSA_ERROR_NOT_SUPPORTED;

    // Everything below gives `w` to code that approves transactions without a button press.
    // If this were ever the production session, the confirmation gate would be gone.
    if (w == bitcoin_core_session_production()) {
        psa_panic();
    }

    switch (msg->type) {
    case PSA_IPC_CONNECT:
    case PSA_IPC_DISCONNECT:
        psa_reply(msg->handle, PSA_SUCCESS);
        return;
    case TFM_BITCOIN_TEST_RUN:
        psa_reply(msg->handle, tfm_bitcoin_test_run_ipc(msg));
        return;
    case TFM_BITCOIN_TEST_TX_APPROVE:
        psa_reply(msg->handle, tfm_bitcoin_test_tx_approve_ipc(w, msg));
        return;
    case TFM_BITCOIN_TEST_OPEN_EPHEMERAL:
        psa_reply(msg->handle, tfm_bitcoin_open_ephemeral_ipc(w, msg));
        return;
    default:
        break;
    }

    if (dispatch_session_op(w, msg, &rc)) {
        psa_reply(msg->handle, rc);
        return;
    }

    psa_reply(msg->handle, PSA_ERROR_NOT_SUPPORTED);
}
#endif

static void get_and_handle(psa_signal_t signal, void (*handle)(psa_msg_t *msg))
{
    psa_msg_t msg;

    if (psa_get(signal, &msg) != PSA_SUCCESS) {
        psa_panic();
    }
    handle(&msg);
}

void tfm_bitcoin_init(void)
{
    psa_signal_t known = TFM_BITCOIN_SIGNAL | TFM_TIMER22_IRQ_SIGNAL;

#ifdef SIGU_SELFTEST
    known |= TFM_BITCOIN_TEST_SIGNAL;
#endif

    // The wallet is air-gapped, so this partition takes the RADIO before NS runs:
    // NS starts only after every secure partition waits in psa_wait().
    // TF-M has no Kconfig or named MMIO for the RADIO, so the SPU is set here.
    // At isolation level 1 this partition is privileged.
    // The lock holds until reset, and any NS access to the RADIO faults.
    spu_peripheral_config_secure(NRF_RADIO_S_BASE, SPU_LOCK_CONF_LOCKED);
    tamper_init();

    // By hand: TF-M's IPC model runs no static constructors before the partition entry.
    base58_init();
    bitcoin_core_init();
    display_init();
    psa_irq_enable(TFM_TIMER22_IRQ_SIGNAL);

    // One thread for the IPC and the panel. Messages go first and their handlers are short.
    // The tick runs in the same pass, so a busy NS cannot stop the screen and the keys.
    while (1) {
        psa_signal_t signal = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

        if (signal & ~known) {
            psa_panic();
        }
        if (signal & TFM_BITCOIN_SIGNAL) {
            get_and_handle(TFM_BITCOIN_SIGNAL, handle_bitcoin_signal);
        }
#ifdef SIGU_SELFTEST
        if (signal & TFM_BITCOIN_TEST_SIGNAL) {
            get_and_handle(TFM_BITCOIN_TEST_SIGNAL, handle_bitcoin_test_signal);
        }
#endif
        if (signal & TFM_TIMER22_IRQ_SIGNAL) {
            display_tick();
            psa_eoi(TFM_TIMER22_IRQ_SIGNAL);
        }
    }
}
