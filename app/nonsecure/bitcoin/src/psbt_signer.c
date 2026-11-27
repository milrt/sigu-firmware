// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/psbt_signer.h"
#include "bitcoin/bitcoin_client.h"
#include "bitcoin/psbt.h"
#include "bitcoin/psbt_result.h"
#include "bitcoin/psbt_tx.h"
#include "psbt_heap.h"
#include "shared/tx_records.h"
#include <psa/crypto.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>

LOG_MODULE_REGISTER(psbt_signer);

// Transport only: fields out of the PSBT, the wait for the approval, signatures back.
// The partition builds the BIP143 preimage itself and trusts nothing from here.

// Formats a BIP32 derivation path as a string, e.g. "m/44'/0'/0'/0".
static psbt_result_t parse_derivation_path(const uint8_t *value_data, size_t value_len,
                                           char *path_str, size_t path_size)
{
    if (value_len < 4 || ((value_len - 4) % 4 != 0)) {
        return PSBT_READ_ERROR;
    }

    const uint8_t *ptr = value_data + 4;
    size_t num_elements = (value_len - 4) / 4;
    char *p = path_str;
    size_t remaining = path_size;
    int written = snprintf(p, remaining, "m");
    if (written < 0 || (size_t)written >= remaining) {
        return PSBT_OOB_WRITE;
    }

    p += written;
    remaining -= written;
    for (size_t i = 0; i < num_elements; i++) {
        uint32_t num = sys_get_le32(ptr);
        ptr += 4;
        written = snprintf(p, remaining, "/%u%s", num & 0x7FFFFFFF, (num & 0x80000000) ? "'" : "");
        if (written < 0 || (size_t)written >= remaining) {
            return PSBT_OOB_WRITE;
        }
        p += written;
        remaining -= written;
    }
    return PSBT_OK;
}

// Returns the derivation path for a map entry that belongs to this wallet,
// or PSBT_NOT_IMPLEMENTED if the entry is not ours.
static psbt_result_t map_own_path(psbt_map_t *map, uint8_t key_type,
                                  const uint8_t *wallet_fingerprint, char *path_str,
                                  size_t path_size)
{
    psbt_kv_t *deriv = psbt_find_kv(map, key_type);

    if (!deriv || deriv->value_data_len < 4) {
        return PSBT_NOT_IMPLEMENTED;
    }
    if (memcmp(deriv->value_data, wallet_fingerprint, BITCOIN_FINGERPRINT_SIZE) != 0) {
        return PSBT_NOT_IMPLEMENTED;
    }
    return parse_derivation_path(deriv->value_data, deriv->value_data_len, path_str, path_size);
}

// The declared type goes through, not an assumed ALL,
// so the partition refuses NONE/SINGLE/ANYONECANPAY instead of signing something else.
static psbt_result_t declared_sighash_type(psbt_t *psbt, uint32_t *out)
{
    uint32_t found = BITCOIN_SIGHASH_ALL;
    bool seen = false;

    for (size_t i = 0; i < psbt->num_inputs; i++) {
        psbt_kv_t *kv = psbt_find_kv(&psbt->inputs[i], PSBT_IN_SIGHASH_TYPE);

        if (!kv || kv->value_data_len != 4) {
            continue;
        }

        uint32_t value = sys_get_le32(kv->value_data);
        if (seen && value != found) {
            LOG_ERR("Inputs declare conflicting sighash types");
            return PSBT_READ_ERROR;
        }
        found = value;
        seen = true;
    }

    *out = found;
    return PSBT_OK;
}

static psbt_result_t stream_outputs(psbt_t *psbt, const psbt_tx_t *tx,
                                    const uint8_t *wallet_fingerprint, const bitcoin_service_t *svc)
{
    for (size_t i = 0; i < tx->num_outputs; i++) {
        char path_str[BITCOIN_PATH_MAX_SIZE] = {0};

        // Only a claim. The partition checks it before it counts the output as change.
        bool own = i < psbt->num_outputs &&
                   map_own_path(&psbt->outputs[i], PSBT_OUT_BIP32_DERIVATION, wallet_fingerprint,
                                path_str, sizeof(path_str)) == PSBT_OK;

        psa_status_t status = bitcoin_client_tx_output(svc, &tx->outputs[i], own ? path_str : NULL);
        if (status != PSA_SUCCESS) {
            LOG_ERR("Output %zu rejected by secure partition: %d", i, (int)status);
            return PSBT_INVALID_STATE;
        }
    }
    return PSBT_OK;
}

static psbt_result_t stream_inputs(psbt_t *psbt, const psbt_tx_t *tx,
                                   const uint8_t *wallet_fingerprint, const bitcoin_service_t *svc)
{
    for (size_t i = 0; i < tx->num_inputs; i++) {
        char path_str[BITCOIN_PATH_MAX_SIZE] = {0};

        // The partition reads the amount from the previous tx and checks its txid.
        // A witness UTXO would only be our claim.
        // The fee needs every input, so an input without the previous tx is refused, not skipped.
        psbt_kv_t *prev_tx = psbt_find_kv(&psbt->inputs[i], PSBT_IN_NON_WITNESS_UTXO);
        if (!prev_tx || !prev_tx->value_data || prev_tx->value_data_len == 0) {
            LOG_ERR("Input %zu: missing non-witness UTXO", i);
            return PSBT_READ_ERROR;
        }

        // This gives the partition the network,
        // even when the transaction has no change output to take it from.
        bool own = map_own_path(&psbt->inputs[i], PSBT_IN_BIP32_DERIVATION, wallet_fingerprint,
                                path_str, sizeof(path_str)) == PSBT_OK;

        psa_status_t status = bitcoin_client_tx_input(svc, &tx->inputs[i], own ? path_str : NULL,
                                                      prev_tx->value_data, prev_tx->value_data_len);
        if (status != PSA_SUCCESS) {
            LOG_ERR("Input %zu rejected by secure partition: %d", i, (int)status);
            return PSBT_INVALID_STATE;
        }
    }
    return PSBT_OK;
}

// Waits until the user approves on the review screen, or rejects the tx.
// The partition reads the key and draws the screen, this loop only asks.
//
// The self-tests cannot press the secure-side key. They approve from `on_wait`,
// and only the test wallet takes that approval, so the loop is the same for everyone.
static psbt_result_t await_approval(void (*on_wait)(void), const bitcoin_service_t *svc)
{
    if (on_wait) {
        on_wait();
    }

    for (;;) {
        uint32_t result = BITCOIN_TX_PENDING;
        psa_status_t status = bitcoin_client_tx_poll(svc, &result);

        // A reject on the panel drops the transaction, so the poll fails.
        if (status != PSA_SUCCESS) {
            LOG_INF("Not approved: %d", (int)status);
            return PSBT_INVALID_STATE;
        }
        if (result == BITCOIN_TX_APPROVED) {
            return PSBT_OK;
        }

        k_msleep(50);
    }
}

static psbt_result_t append_partial_sig(psbt_map_t *input, const bitcoin_pubkey_t *pubkey,
                                        const uint8_t *signature, size_t sig_size,
                                        uint8_t sighash_type)
{
    psbt_kv_t *partial_sig = k_heap_alloc(&psbt_heap, sizeof(psbt_kv_t), K_NO_WAIT);
    if (!partial_sig) {
        return PSBT_OOB_WRITE;
    }

    partial_sig->key_type = PSBT_IN_PARTIAL_SIG;
    partial_sig->key_data = k_heap_alloc(&psbt_heap, sizeof(pubkey->bytes), K_NO_WAIT);
    if (!partial_sig->key_data) {
        k_heap_free(&psbt_heap, partial_sig);
        return PSBT_OOB_WRITE;
    }
    memcpy(partial_sig->key_data, pubkey->bytes, sizeof(pubkey->bytes));
    partial_sig->key_data_len = sizeof(pubkey->bytes);

    partial_sig->value_data = k_heap_alloc(&psbt_heap, sig_size + 1, K_NO_WAIT);
    if (!partial_sig->value_data) {
        k_heap_free(&psbt_heap, partial_sig->key_data);
        k_heap_free(&psbt_heap, partial_sig);
        return PSBT_OOB_WRITE;
    }
    memcpy(partial_sig->value_data, signature, sig_size);
    partial_sig->value_data[sig_size] = sighash_type;
    partial_sig->value_data_len = sig_size + 1;

    sys_slist_append(&input->kv_list, &partial_sig->node);
    return PSBT_OK;
}

static psbt_result_t sign_inputs(psbt_t *psbt, const psbt_tx_t *tx,
                                 const uint8_t *wallet_fingerprint, uint32_t sighash_type,
                                 size_t *signed_count, const bitcoin_service_t *svc)
{
    for (size_t i = 0; i < tx->num_inputs; i++) {
        char path_str[BITCOIN_PATH_MAX_SIZE] = {0};

        // Inputs that belong to someone else are still part of the transaction,
        // and we streamed them as such, but we have no key for them.
        if (map_own_path(&psbt->inputs[i], PSBT_IN_BIP32_DERIVATION, wallet_fingerprint, path_str,
                         sizeof(path_str)) != PSBT_OK) {
            LOG_INF("Input %zu: not ours, skipping", i);
            continue;
        }

        uint8_t signature[BITCOIN_SIGNATURE_MAX_SIZE];
        size_t sig_size = sizeof(signature);
        bitcoin_pubkey_t pubkey;

        psa_status_t status =
            bitcoin_client_tx_sign_input(svc, (uint32_t)i, path_str, signature, &sig_size, &pubkey);
        if (status != PSA_SUCCESS) {
            LOG_ERR("Input %zu: signing failed: %d", i, (int)status);
            return PSBT_INVALID_STATE;
        }

        psbt_result_t res = append_partial_sig(&psbt->inputs[i], &pubkey, signature, sig_size,
                                               (uint8_t)sighash_type);
        if (res != PSBT_OK) {
            return res;
        }
        (*signed_count)++;
    }
    return PSBT_OK;
}

psbt_result_t psbt_sign(psbt_t *psbt, const bitcoin_service_t *svc, void (*on_wait)(void))
{
    psbt_kv_t *unsigned_tx = psbt_find_kv(&psbt->global, PSBT_GLOBAL_UNSIGNED_TX);
    if (!unsigned_tx || !unsigned_tx->value_data) {
        return PSBT_READ_ERROR;
    }

    psbt_tx_t tx;
    psbt_result_t res =
        psbt_tx_create_from_bin(&tx, unsigned_tx->value_data, unsigned_tx->value_data_len);
    if (res != PSBT_OK) {
        return res;
    }

    bitcoin_fingerprint_t fp;
    uint32_t sighash_type = BITCOIN_SIGHASH_ALL;
    size_t signed_count = 0;

    // Also the "is the wallet open?" check:
    // every call that needs a key returns PSA_ERROR_BAD_STATE until the wallet is open.
    psa_status_t status = bitcoin_client_get_fingerprint(svc, &fp);
    if (status == PSA_ERROR_BAD_STATE) {
        LOG_ERR("Wallet is not open. Unlock it on the device.");
        res = PSBT_INVALID_STATE;
    } else if (status != PSA_SUCCESS) {
        LOG_ERR("Could not read wallet fingerprint: %d", (int)status);
        res = PSBT_INVALID_STATE;
    }
    if (res == PSBT_OK) {
        res = declared_sighash_type(psbt, &sighash_type);
    }
    if (res == PSBT_OK) {
        bitcoin_tx_begin_t begin = {
            .version = tx.version,
            .locktime = tx.lock_time,
            .num_inputs = (uint32_t)tx.num_inputs,
            .num_outputs = (uint32_t)tx.num_outputs,
            .sighash_type = sighash_type,
        };
        status = bitcoin_client_tx_begin(svc, &begin);
        if (status != PSA_SUCCESS) {
            LOG_ERR("Secure partition refused the transaction (%u inputs, %u outputs): %d",
                    begin.num_inputs, begin.num_outputs, (int)status);
            res = PSBT_INVALID_STATE;
        }
    }
    // Outputs before inputs.
    // The partition needs hashOutputs finished before it can commit to any input.
    if (res == PSBT_OK) {
        res = stream_outputs(psbt, &tx, fp.bytes, svc);
    }
    if (res == PSBT_OK) {
        res = stream_inputs(psbt, &tx, fp.bytes, svc);
    }
    if (res == PSBT_OK && bitcoin_client_tx_confirm(svc) != PSA_SUCCESS) {
        res = PSBT_INVALID_STATE;
    }
    if (res == PSBT_OK) {
        res = await_approval(on_wait, svc);
    }
    if (res == PSBT_OK) {
        res = sign_inputs(psbt, &tx, fp.bytes, sighash_type, &signed_count, svc);
    }
    // Signing nothing is a failure, not a success.
    if (res == PSBT_OK && signed_count == 0) {
        LOG_ERR("No inputs belonged to this wallet");
        res = PSBT_INVALID_STATE;
    }

    // The session is done whatever happened.
    bitcoin_client_tx_abort(svc);
    psbt_tx_free(&tx);
    return res;
}
