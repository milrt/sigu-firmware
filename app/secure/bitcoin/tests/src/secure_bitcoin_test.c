// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/secure_bitcoin_test.h"
#include "shared/shared_test.h"
#include "shared/test_util.h"
#include "test_wallet.h"
#include "tfm_log.h"

void bip32_test_run_all(void);
void bip39_test_run_all(void);
void get_key_test_run_all(void);
void key_storage_test_run_all(void);
void script_test_run_all(void);
void tx_session_test_run_all(void);

wallet_session_t *open_test_wallet(void)
{
    wallet_session_t *w = bitcoin_core_session_test();

    TEST_ASSERT_EQUAL(PSA_SUCCESS, bitcoin_core_open_ephemeral(w, TEST_MNEMONIC, ""));
    return w;
}

psa_status_t secure_bitcoin_test_run_all(void)
{
    test_assert_init();

    shared_test_run_all();
    bip39_test_run_all();
    bip32_test_run_all();
    key_storage_test_run_all();
    script_test_run_all();
    get_key_test_run_all();
    tx_session_test_run_all();

    test_assert_results_t *results = test_assert_get_results();

    INFO("Test Summary secure parition:\n");
    INFO("Total Tests Run: %u\n", results->total);
    INFO("Tests Passed:    %u\n", results->passed);
    INFO("Tests Failed:    %u\n", results->failure_count);

    if (results->failure_count > 0) {
        INFO("\nFailed Test Details:\n");
        for (uint32_t i = 0; i < results->failure_count; i++) {
            test_assert_failure_t *f = &results->failures[i];
            INFO("%u) %s:%u: %s\n", i + 1, f->file, f->line, f->message);
        }
    }

    return (results->failure_count == 0) ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}
