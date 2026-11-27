// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// A BIP174 PSBT as key/value maps: one global map, then one map per input and per output.
// The maps hold every record, so a PSBT writes back with the records this code does not know.

#pragma once

#include "psbt_result.h"
#include <zephyr/kernel.h>
#include <zephyr/sys/slist.h>

// The key types this code reads or writes.
#define PSBT_GLOBAL_UNSIGNED_TX 0x00
#define PSBT_IN_NON_WITNESS_UTXO 0x00
#define PSBT_IN_PARTIAL_SIG 0x02
#define PSBT_IN_SIGHASH_TYPE 0x03
#define PSBT_IN_BIP32_DERIVATION 0x06
#define PSBT_OUT_BIP32_DERIVATION 0x02

// One record. `key_data` is the key after its type byte. All of it is on psbt_heap.
typedef struct psbt_kv {
    uint8_t key_type;
    uint8_t *key_data;
    size_t key_data_len;
    uint8_t *value_data;
    size_t value_data_len;
    sys_snode_t node;
} psbt_kv_t;

typedef struct psbt_map {
    sys_slist_t kv_list;
} psbt_map_t;

typedef struct psbt {
    psbt_map_t global;
    psbt_map_t *inputs;
    size_t num_inputs;
    psbt_map_t *outputs;
    size_t num_outputs;
} psbt_t;

// Parses a binary PSBT. The input and output counts come from the unsigned tx.
// A PSBT that is cut, has bytes after the last map, or does not fit in psbt_heap is refused,
// and leaves nothing to free.
psbt_result_t psbt_create_from_bin(psbt_t *psbt, const uint8_t *data, size_t data_len);

// The first record of `key_type` in `map`, or NULL.
psbt_kv_t *psbt_find_kv(psbt_map_t *map, uint8_t key_type);

void psbt_free(psbt_t *psbt);

// Writes the PSBT to `out_buf`. `out_len` is the buffer size in and the written size out.
psbt_result_t psbt_to_bin(psbt_t *psbt, uint8_t *out_buf, size_t *out_len);
