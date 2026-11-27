// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/bitcoin_client.h"
#include "psa_manifest/sid.h"
#include "shared/bitcoin_service_defs.h"
#include <psa/client.h>
#include <string.h>

const bitcoin_service_t bitcoin_service = {
    .sid = TFM_BITCOIN_SID,
    .version = TFM_BITCOIN_VERSION,
};

#ifdef CONFIG_SIGU_SELFTEST
const bitcoin_service_t bitcoin_service_test = {
    .sid = TFM_BITCOIN_TEST_SID,
    .version = TFM_BITCOIN_TEST_VERSION,
};
#endif

static psa_status_t call(const bitcoin_service_t *svc, int32_t op, psa_invec *in, size_t in_len,
                         psa_outvec *out, size_t out_len)
{
    psa_handle_t handle = psa_connect(svc->sid, svc->version);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_status_t status = psa_call(handle, op, in, in_len, out, out_len);
    psa_close(handle);
    return status;
}

static size_t str_len(const char *s)
{
    return s ? strlen(s) + 1 : 0;
}

psa_status_t bitcoin_client_status(uint32_t *state_out, uint32_t *attempts_out)
{
    if (!state_out || !attempts_out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    psa_outvec out_vec[] = {
        {.base = state_out, .len = sizeof(*state_out)},
        {.base = attempts_out, .len = sizeof(*attempts_out)},
    };

    return call(&bitcoin_service, TFM_BITCOIN_STATUS, NULL, 0, out_vec, IOVEC_LEN(out_vec));
}

psa_status_t bitcoin_client_get_xpub(const bitcoin_service_t *svc, const char *derivation_path,
                                     char *xpub_out, size_t *xpub_size)
{
    if (!xpub_out || !xpub_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_invec in_vec[] = {{.base = derivation_path, .len = str_len(derivation_path)}};
    psa_outvec out_vec[] = {{.base = xpub_out, .len = *xpub_size}};

    psa_status_t status =
        call(svc, TFM_BITCOIN_GET_XPUB, in_vec, IOVEC_LEN(in_vec), out_vec, IOVEC_LEN(out_vec));

    if (status == PSA_SUCCESS) {
        *xpub_size = out_vec[0].len;
    }
    return status;
}

psa_status_t bitcoin_client_get_fingerprint(const bitcoin_service_t *svc,
                                            bitcoin_fingerprint_t *fingerprint)
{
    if (!fingerprint) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_outvec out_vec[] = {{.base = fingerprint, .len = sizeof(*fingerprint)}};

    return call(svc, TFM_BITCOIN_GET_FINGERPRINT, NULL, 0, out_vec, IOVEC_LEN(out_vec));
}

// An empty or NULL path goes as a zero-length invec, which means "not ours".
static psa_invec path_vec(const char *path)
{
    size_t len = (path && path[0] != '\0') ? strlen(path) + 1 : 0;

    return (psa_invec){.base = path, .len = len};
}

psa_status_t bitcoin_client_tx_begin(const bitcoin_service_t *svc, const bitcoin_tx_begin_t *begin)
{
    if (!begin) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    bitcoin_tx_begin_rec_t rec;
    bitcoin_tx_begin_pack(begin, &rec);
    psa_invec in_vec[] = {{.base = &rec, .len = sizeof(rec)}};

    return call(svc, TFM_BITCOIN_TX_BEGIN, in_vec, IOVEC_LEN(in_vec), NULL, 0);
}

psa_status_t bitcoin_client_tx_output(const bitcoin_service_t *svc, const bitcoin_tx_output_t *out,
                                      const char *change_path)
{
    bitcoin_tx_output_rec_t rec;

    if (!out || !bitcoin_tx_output_pack(out, &rec)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_invec in_vec[] = {{.base = &rec, .len = sizeof(rec)}, path_vec(change_path)};

    return call(svc, TFM_BITCOIN_TX_OUTPUT, in_vec, IOVEC_LEN(in_vec), NULL, 0);
}

psa_status_t bitcoin_client_tx_input(const bitcoin_service_t *svc, const bitcoin_tx_input_t *in,
                                     const char *path, const uint8_t *prev_tx, size_t prev_tx_len)
{
    if (!in || !prev_tx || prev_tx_len == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    bitcoin_tx_input_rec_t rec;
    bitcoin_tx_input_pack(in, &rec);
    psa_invec in_vec[] = {
        {.base = &rec, .len = sizeof(rec)},
        path_vec(path),
        {.base = prev_tx, .len = prev_tx_len},
    };

    return call(svc, TFM_BITCOIN_TX_INPUT, in_vec, IOVEC_LEN(in_vec), NULL, 0);
}

psa_status_t bitcoin_client_tx_confirm(const bitcoin_service_t *svc)
{
    return call(svc, TFM_BITCOIN_TX_CONFIRM, NULL, 0, NULL, 0);
}

psa_status_t bitcoin_client_tx_poll(const bitcoin_service_t *svc, uint32_t *result)
{
    if (!result) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_outvec out_vec[] = {{.base = result, .len = sizeof(*result)}};

    return call(svc, TFM_BITCOIN_TX_POLL, NULL, 0, out_vec, IOVEC_LEN(out_vec));
}

psa_status_t bitcoin_client_tx_sign_input(const bitcoin_service_t *svc, uint32_t index,
                                          const char *derivation_path, uint8_t *signature_der,
                                          size_t *signature_size, bitcoin_pubkey_t *pubkey_out)
{
    if (!derivation_path || !signature_der || !signature_size || !pubkey_out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_invec in_vec[] = {
        {.base = &index, .len = sizeof(index)},
        {.base = derivation_path, .len = strlen(derivation_path) + 1},
    };

    psa_outvec out_vec[] = {
        {.base = signature_der, .len = *signature_size},
        {.base = pubkey_out, .len = sizeof(*pubkey_out)},
    };

    psa_status_t status = call(svc, TFM_BITCOIN_TX_SIGN_INPUT, in_vec, IOVEC_LEN(in_vec), out_vec,
                               IOVEC_LEN(out_vec));

    if (status == PSA_SUCCESS) {
        *signature_size = out_vec[0].len;
    }
    return status;
}

psa_status_t bitcoin_client_tx_abort(const bitcoin_service_t *svc)
{
    return call(svc, TFM_BITCOIN_TX_ABORT, NULL, 0, NULL, 0);
}

psa_status_t bitcoin_client_files_set(const char *names, size_t n, uint32_t card,
                                      const uint8_t fw[BITCOIN_FW_STATE_SIZE],
                                      const uint8_t *installs, size_t n_installs)
{
    if (n > BITCOIN_FILES_MAX || (n > 0 && !names) || !fw || n_installs > BITCOIN_INSTALLS_MAX ||
        (n_installs > 0 && !installs)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_invec in_vec[] = {
        {.base = names, .len = n * BITCOIN_FILE_NAME_MAX_SIZE},
        {.base = &card, .len = sizeof(card)},
        {.base = fw, .len = BITCOIN_FW_STATE_SIZE},
        {.base = installs, .len = n_installs * BITCOIN_INSTALL_RECORD_SIZE},
    };

    return call(&bitcoin_service, TFM_BITCOIN_FILES_SET, in_vec, IOVEC_LEN(in_vec), NULL, 0);
}

// The last byte stays NUL whatever the partition wrote.
psa_status_t bitcoin_client_files_poll(char name[BITCOIN_FILE_NAME_MAX_SIZE], uint32_t *kind)
{
    psa_outvec out_vec[] = {
        {.base = name, .len = BITCOIN_FILE_NAME_MAX_SIZE},
        {.base = kind, .len = sizeof(*kind)},
    };
    psa_status_t status;

    if (!name || !kind) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    name[0] = '\0';
    *kind = BITCOIN_JOB_SIGN;
    status = call(&bitcoin_service, TFM_BITCOIN_FILES_POLL, NULL, 0, out_vec, IOVEC_LEN(out_vec));
    name[BITCOIN_FILE_NAME_MAX_SIZE - 1] = '\0';
    return status;
}

psa_status_t bitcoin_client_files_result(uint32_t code)
{
    psa_invec in_vec[] = {{.base = &code, .len = sizeof(code)}};

    return call(&bitcoin_service, TFM_BITCOIN_FILES_RESULT, in_vec, IOVEC_LEN(in_vec), NULL, 0);
}

#ifdef CONFIG_SIGU_SELFTEST
psa_status_t bitcoin_client_test_run_all(void)
{
    return call(&bitcoin_service_test, TFM_BITCOIN_TEST_RUN, NULL, 0, NULL, 0);
}

psa_status_t bitcoin_client_test_open_ephemeral(const char *mnemonic, const char *passphrase)
{
    if (!mnemonic || !passphrase) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_invec in_vec[] = {
        {.base = mnemonic, .len = strlen(mnemonic) + 1},
        {.base = passphrase, .len = strlen(passphrase) + 1},
    };

    return call(&bitcoin_service_test, TFM_BITCOIN_TEST_OPEN_EPHEMERAL, in_vec, IOVEC_LEN(in_vec),
                NULL, 0);
}

psa_status_t bitcoin_client_test_approve(void)
{
    return call(&bitcoin_service_test, TFM_BITCOIN_TEST_TX_APPROVE, NULL, 0, NULL, 0);
}

#endif
