// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The tx records of the ABI as plain structs, and the code that packs them.
// Keep this file free of Zephyr headers: the partition builds it too, and has no sys_get_le32().

#pragma once

#include "bitcoin_service_defs.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t version;
    uint32_t locktime;
    uint32_t num_inputs;
    uint32_t num_outputs;
    uint32_t sighash_type;
} bitcoin_tx_begin_t;

typedef struct {
    uint64_t amount;
    uint8_t script_len;
    uint8_t script[BITCOIN_TX_SCRIPT_MAX_SIZE];
} bitcoin_tx_output_t;

typedef struct {
    uint8_t txid[BITCOIN_TXID_SIZE];
    uint32_t vout;
    uint32_t sequence;
} bitcoin_tx_input_t;

typedef struct {
    uint8_t kind;
    uint64_t amount;
    char address[BITCOIN_ADDRESS_MAX_SIZE]; // empty unless kind is OUTPUT
} bitcoin_tx_summary_t;

void bitcoin_tx_begin_pack(const bitcoin_tx_begin_t *in, bitcoin_tx_begin_rec_t *out);
void bitcoin_tx_begin_unpack(const bitcoin_tx_begin_rec_t *in, bitcoin_tx_begin_t *out);

// False if script_len is over BITCOIN_TX_SCRIPT_MAX_SIZE.
// Unpack is the side that matters: it runs on a record NS chose,
// so a bad length must be refused, never passed to a memcpy.
bool bitcoin_tx_output_pack(const bitcoin_tx_output_t *in, bitcoin_tx_output_rec_t *out);
bool bitcoin_tx_output_unpack(const bitcoin_tx_output_rec_t *in, bitcoin_tx_output_t *out);

void bitcoin_tx_input_pack(const bitcoin_tx_input_t *in, bitcoin_tx_input_rec_t *out);
void bitcoin_tx_input_unpack(const bitcoin_tx_input_rec_t *in, bitcoin_tx_input_t *out);

// Little-endian stores, for the commitment hashes, the tx_id and the key storage AAD.
void tx_put_le32(uint8_t *dst, uint32_t value);
void tx_put_le64(uint8_t *dst, uint64_t value);

// Satoshis as a fixed-point BTC string, e.g. 18922 -> "0.00018922".
// Always 8 decimals, so amounts line up under each other. False if the buffer is too small.
bool tx_format_btc(uint64_t sats, char *out, size_t out_size);
