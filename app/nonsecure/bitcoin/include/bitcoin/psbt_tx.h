// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The unsigned tx of a PSBT (PSBT_GLOBAL_UNSIGNED_TX),
// parsed into the records NS streams to the partition.

#pragma once

#include "psbt_result.h"
#include "shared/tx_records.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t version;
    uint32_t lock_time;
    bitcoin_tx_input_t *inputs; // on psbt_heap
    size_t num_inputs;
    bitcoin_tx_output_t *outputs; // on psbt_heap
    size_t num_outputs;
} psbt_tx_t;

// Parses a tx in the form BIP174 requires: no witness and empty scriptSigs.
// It refuses a tx with no input, an output script over BITCOIN_TX_SCRIPT_MAX_SIZE,
// or bytes after the locktime.
// A refused tx leaves nothing to free.
psbt_result_t psbt_tx_create_from_bin(psbt_tx_t *tx, const uint8_t *data, size_t data_len);
void psbt_tx_free(psbt_tx_t *tx);
