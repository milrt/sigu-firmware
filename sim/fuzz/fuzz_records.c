// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The tx_records unpack on records from the other image.
// The first byte picks the record, the rest fills it.
// A record that unpacks must pack and unpack again to the same struct.

#include "shared/tx_records.h"
#include <stdlib.h>
#include <string.h>

#define FILL(rec, data, size)                                                                      \
    do {                                                                                           \
        memset(&(rec), 0, sizeof(rec));                                                            \
        memcpy(&(rec), (data), (size) < sizeof(rec) ? (size) : sizeof(rec));                       \
    } while (0)

static void check(bool ok)
{
    if (!ok) {
        abort();
    }
}

static void begin(const uint8_t *data, size_t size)
{
    bitcoin_tx_begin_rec_t rec, rec2;
    bitcoin_tx_begin_t a, b;

    FILL(rec, data, size);
    bitcoin_tx_begin_unpack(&rec, &a);
    bitcoin_tx_begin_pack(&a, &rec2);
    bitcoin_tx_begin_unpack(&rec2, &b);
    check(!memcmp(&a, &b, sizeof(a)) && !memcmp(&rec, &rec2, sizeof(rec)));
}

static void output(const uint8_t *data, size_t size)
{
    bitcoin_tx_output_rec_t rec, rec2;
    bitcoin_tx_output_t a, b;

    FILL(rec, data, size);
    if (!bitcoin_tx_output_unpack(&rec, &a)) {
        return;
    }
    check(a.script_len <= BITCOIN_TX_SCRIPT_MAX_SIZE);
    check(bitcoin_tx_output_pack(&a, &rec2));
    check(bitcoin_tx_output_unpack(&rec2, &b));
    check(a.amount == b.amount && a.script_len == b.script_len &&
          !memcmp(a.script, b.script, sizeof(a.script)));
}

static void input(const uint8_t *data, size_t size)
{
    bitcoin_tx_input_rec_t rec, rec2;
    bitcoin_tx_input_t a, b;

    FILL(rec, data, size);
    bitcoin_tx_input_unpack(&rec, &a);
    bitcoin_tx_input_pack(&a, &rec2);
    bitcoin_tx_input_unpack(&rec2, &b);
    check(!memcmp(&a, &b, sizeof(a)) && !memcmp(&rec, &rec2, sizeof(rec)));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static void (*const fn[])(const uint8_t *, size_t) = {begin, output, input};

    if (size < 1) {
        return -1;
    }
    fn[data[0] % 3](data + 1, size - 1);
    return 0;
}
