// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// prev_tx_output() on a prev tx from NS.
// It is static, so the file is included here and app/ stays as it is.
// The first 4 bytes are vout, the rest is the tx.
// For a legacy tx the txid must be SHA-256d of all its bytes.

#include "tx_session.c"

#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t txid[BITCOIN_TXID_SIZE];
    uint8_t inner[32];
    uint8_t expect[BITCOIN_TXID_SIZE];
    uint64_t amount = 0;
    uint32_t vout;

    if (size < 4 || size - 4 > BITCOIN_PREV_TX_MAX_SIZE) {
        return -1;
    }
    vout = (uint32_t)data[0] | (uint32_t)data[1] << 8 | (uint32_t)data[2] << 16 |
           (uint32_t)data[3] << 24;
    data += 4;
    size -= 4;

    // A copy of the exact size, so ASan sees any read past the end.
    uint8_t *tx = malloc(size ? size : 1);
    if (!tx) {
        return 0;
    }
    memcpy(tx, data, size);
    if (prev_tx_output(tx, size, vout, txid, &amount) == PSA_SUCCESS &&
        !(size >= 6 && tx[4] == 0x00)) {
        if (hash_sha256(tx, size, inner, sizeof(inner)) != PSA_SUCCESS ||
            hash_sha256(inner, sizeof(inner), expect, sizeof(expect)) != PSA_SUCCESS ||
            memcmp(txid, expect, sizeof(txid)) != 0) {
            abort();
        }
    }
    free(tx);
    return 0;
}
