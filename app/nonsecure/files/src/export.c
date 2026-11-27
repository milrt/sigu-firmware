// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "export.h"
#include "bitcoin/bitcoin_client.h"
#include "shared/descriptor.h"
#include <stdio.h>

// The file is the descriptor from shared/descriptor.c and a newline.
// The panel shows the same descriptor as a QR code, built in the SP.

uint32_t export_build(char *text, size_t size, size_t *len, char name[EXPORT_NAME_SIZE])
{
    bitcoin_fingerprint_t fp;
    char xpub[BITCOIN_XPUB_MAX_SIZE];
    size_t xpub_size = sizeof(xpub);
    const uint8_t *b = fp.bytes;
    size_t n;

    if (bitcoin_client_get_fingerprint(&bitcoin_service, &fp) != PSA_SUCCESS ||
        bitcoin_client_get_xpub(&bitcoin_service, DESCRIPTOR_ACCOUNT_PATH, xpub, &xpub_size) !=
            PSA_SUCCESS ||
        xpub_size == 0 || xpub[xpub_size - 1] != '\0') {
        return BITCOIN_FILES_READ_FAILED;
    }

    n = descriptor_build(fp.bytes, xpub, text, size);
    if (n == 0 || n + 1 >= size) {
        return BITCOIN_FILES_WRITE_FAILED;
    }
    text[n++] = '\n';
    text[n] = '\0';
    *len = n;
    snprintf(name, EXPORT_NAME_SIZE, "wallet-%02x%02x%02x%02x.txt", b[0], b[1], b[2], b[3]);
    return BITCOIN_FILES_OK;
}
