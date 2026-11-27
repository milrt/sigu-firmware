// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/psbt_tx.h"
#include "psbt_compactsize.h"
#include "psbt_heap.h"
#include <string.h>
#include <zephyr/sys/byteorder.h>

// The smallest input and output on the wire: 32 + 4 + 1 + 4 bytes and 8 + 1 bytes.
#define TXIN_MIN_SIZE 41
#define TXOUT_MIN_SIZE 9

static bool read_bytes(const uint8_t **p, size_t *remaining, void *dest, size_t len)
{
    if (*remaining < len) {
        return false;
    }
    memcpy(dest, *p, len);
    *p += len;
    *remaining -= len;
    return true;
}

static bool read_le32(const uint8_t **p, size_t *remaining, uint32_t *val)
{
    uint8_t b[4];

    if (!read_bytes(p, remaining, b, sizeof(b))) {
        return false;
    }
    *val = sys_get_le32(b);
    return true;
}

static bool read_le64(const uint8_t **p, size_t *remaining, uint64_t *val)
{
    uint8_t b[8];

    if (!read_bytes(p, remaining, b, sizeof(b))) {
        return false;
    }
    *val = sys_get_le64(b);
    return true;
}

// Reads a count and allocates that many records of `size`.
// A count bigger than the bytes left cannot be real, and is refused before the alloc:
// k_heap_alloc truncates the 64-bit count * size, so a large count would give a small buffer.
static void *read_array(const uint8_t **p, size_t *remaining, size_t min_size, size_t size,
                        size_t *count)
{
    uint64_t n;

    if (!compactsize_read(p, remaining, &n) || n == 0 || n > *remaining / min_size) {
        return NULL;
    }
    void *array = k_heap_alloc(&psbt_heap, n * size, K_NO_WAIT);

    if (array) {
        memset(array, 0, n * size);
        *count = n;
    }
    return array;
}

static bool parse_inputs(psbt_tx_t *tx, const uint8_t **p, size_t *remaining)
{
    // BIP174 puts the unsigned tx without witnesses,
    // so a 0 here is the segwit marker, and read_array() refuses it.
    // A tx with no input signs nothing anyway.
    tx->inputs = read_array(p, remaining, TXIN_MIN_SIZE, sizeof(*tx->inputs), &tx->num_inputs);
    if (!tx->inputs) {
        return false;
    }
    for (size_t i = 0; i < tx->num_inputs; i++) {
        bitcoin_tx_input_t *in = &tx->inputs[i];
        uint64_t script_len;

        // BIP174: the scriptSigs of the unsigned tx are empty.
        if (!read_bytes(p, remaining, in->txid, sizeof(in->txid)) ||
            !read_le32(p, remaining, &in->vout) || !compactsize_read(p, remaining, &script_len) ||
            script_len != 0 || !read_le32(p, remaining, &in->sequence)) {
            return false;
        }
    }
    return true;
}

static bool parse_outputs(psbt_tx_t *tx, const uint8_t **p, size_t *remaining)
{
    tx->outputs = read_array(p, remaining, TXOUT_MIN_SIZE, sizeof(*tx->outputs), &tx->num_outputs);
    if (!tx->outputs) {
        return false;
    }
    for (size_t i = 0; i < tx->num_outputs; i++) {
        bitcoin_tx_output_t *out = &tx->outputs[i];
        uint64_t script_len;

        // A longer script is none the partition can show.
        if (!read_le64(p, remaining, &out->amount) ||
            !compactsize_read(p, remaining, &script_len) ||
            script_len > BITCOIN_TX_SCRIPT_MAX_SIZE ||
            !read_bytes(p, remaining, out->script, script_len)) {
            return false;
        }
        out->script_len = script_len;
    }
    return true;
}

psbt_result_t psbt_tx_create_from_bin(psbt_tx_t *tx, const uint8_t *data, size_t data_len)
{
    const uint8_t *p = data;
    size_t remaining = data_len;

    memset(tx, 0, sizeof(*tx));
    if (!read_le32(&p, &remaining, &tx->version) || !parse_inputs(tx, &p, &remaining) ||
        !parse_outputs(tx, &p, &remaining) || !read_le32(&p, &remaining, &tx->lock_time) ||
        remaining != 0) {
        psbt_tx_free(tx);
        return PSBT_READ_ERROR;
    }
    return PSBT_OK;
}

void psbt_tx_free(psbt_tx_t *tx)
{
    k_heap_free(&psbt_heap, tx->inputs);
    k_heap_free(&psbt_heap, tx->outputs);
    tx->inputs = NULL;
    tx->outputs = NULL;
}
