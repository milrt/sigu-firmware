// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The PSBT parser on bytes from the card. A PSBT that parses must write back to the same bytes,
// and its unsigned tx goes through psbt_tx_create_from_bin() as psbt_sign() does it.
// After each free, psbt_heap must be empty again: a leak there would fill the 8 KiB device heap.

#include "bitcoin/psbt.h"
#include "bitcoin/psbt_tx.h"
#include "psbt_heap.h"
#include "shared/bitcoin_service_defs.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void check_heap_empty(void)
{
    if (psbt_heap.used != 0) {
        abort();
    }
}

static void check_tx(psbt_t *psbt)
{
    psbt_kv_t *kv = psbt_find_kv(&psbt->global, PSBT_GLOBAL_UNSIGNED_TX);
    psbt_tx_t tx;

    if (kv && kv->value_data &&
        psbt_tx_create_from_bin(&tx, kv->value_data, kv->value_data_len) == PSBT_OK) {
        psbt_tx_free(&tx);
    }
}

// The parser keeps every pair in order and takes only canonical compactsizes,
// so the writer gives back the same bytes.
// A second parse is no check: with the first PSBT still in the heap,
// a big one does not fit twice in the 8 KiB.
static void check_round_trip(psbt_t *psbt, const uint8_t *data, size_t size)
{
    static uint8_t out[BITCOIN_PSBT_FILE_MAX];
    size_t out_len = sizeof(out);

    if (psbt_to_bin(psbt, out, &out_len) != PSBT_OK || out_len != size ||
        memcmp(out, data, size) != 0) {
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    psbt_t psbt;

    // sdcard.c refuses a bigger file before it parses.
    if (size > BITCOIN_PSBT_FILE_MAX) {
        return -1;
    }
    if (psbt_create_from_bin(&psbt, data, size) == PSBT_OK) {
        check_tx(&psbt);
        check_round_trip(&psbt, data, size);
        psbt_free(&psbt);
    }
    check_heap_empty();
    return 0;
}
