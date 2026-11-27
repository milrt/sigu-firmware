// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// TFM_BITCOIN_FILES_SET as NS sends it, through the production handler.
// bitcoin_service.c is included so its static handler can be called, and app/ stays as it is.
// The first 8 bytes are the four invec sizes (u16 LE), the rest is cut into the invecs in order.
// Then the file list and the install records the panel will show are checked.

#include "bitcoin_service.c"

#include "ipc_stub.h"
#include <stdlib.h>

static void check(bool ok)
{
    if (!ok) {
        abort();
    }
}

static void check_files(void)
{
    check(files_count() <= BITCOIN_FILES_MAX);
    for (uint32_t i = 0; i < files_count(); i++) {
        const char *name = files_name(i);

        check(name && name[0] != '\0' && memchr(name, '\0', BITCOIN_FILE_NAME_MAX_SIZE));
    }
    check(files_card() <= BITCOIN_CARD_ERROR);
    check(files_fw_status() <= BITCOIN_FW_CONFIRMING);
    check(files_install_count() <= BITCOIN_INSTALLS_MAX);
    for (uint32_t i = 0; i < files_install_count(); i++) {
        const files_install_t *f = files_install(i);

        check(f && (f->kind == BITCOIN_INSTALL_BOOT || f->kind == BITCOIN_INSTALL_APP) &&
              f->state <= BITCOIN_INSTALL_STATE_INCOMPLETE);
    }
    // One record per kind.
    check(files_install_count() < 2 || files_install(0)->kind != files_install(1)->kind);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const uint8_t *in[PSA_MAX_IOVEC] = {0};
    size_t in_len[PSA_MAX_IOVEC] = {0};
    uint8_t *copy[PSA_MAX_IOVEC] = {0};

    if (size < 2 * PSA_MAX_IOVEC) {
        return -1;
    }
    const uint8_t *p = data + 2 * PSA_MAX_IOVEC;
    size_t left = size - 2 * PSA_MAX_IOVEC;

    for (size_t i = 0; i < PSA_MAX_IOVEC; i++) {
        size_t want = (size_t)data[2 * i] | (size_t)data[2 * i + 1] << 8;
        size_t n = want < left ? want : left;

        // Each invec in its own buffer of the exact size, so ASan sees any over-read.
        copy[i] = malloc(n ? n : 1);
        if (!copy[i]) {
            abort();
        }
        memcpy(copy[i], p, n);
        in[i] = copy[i];
        in_len[i] = n;
        p += n;
        left -= n;
    }

    handle_bitcoin_signal(ipc_stub_message(TFM_BITCOIN_FILES_SET, in, in_len));
    check(ipc_stub_replied());
    check_files();

    for (size_t i = 0; i < PSA_MAX_IOVEC; i++) {
        free(copy[i]);
    }
    return 0;
}
