// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The two parsers on the install path that read bytes NS or a power cut can shape:
// the image layout in slot1 (shared/fw_image.c, in the SP and in MCUboot),
// and the install record (shared/install_auth.c).
// The first byte picks one.
//   - image: the rest is slot1. Every read stays inside it.
//     The buffer has the exact size, so ASan sees the rest. A total that is accepted fits the slot.
//   - record: the rest is the 256-byte area.
//     A parse result must encode and parse back to the same state, floor and hashes,
//     and a record with no valid copy must read IDLE.

#include "shared/fw_image.h"
#include "shared/install_auth.h"
#include <stdlib.h>
#include <string.h>

struct slot {
    const uint8_t *p;
    size_t size;
};

static bool slot_read(void *ctx, uint32_t off, void *buf, size_t len)
{
    const struct slot *s = ctx;

    if (off > s->size || len > s->size - off) {
        return false;
    }
    memcpy(buf, s->p + off, len);
    return true;
}

static void image(const uint8_t *data, size_t size)
{
    struct slot s = {.p = data, .size = size};
    uint8_t hdr[FW_IMAGE_HEADER_SIZE];
    uint8_t info[FW_IMAGE_TLV_INFO_SIZE];
    fw_image_t img;
    uint32_t total = 0;
    uint32_t counter = 0;

    if (!slot_read(&s, 0, hdr, sizeof(hdr)) || !fw_image_parse(hdr, &img)) {
        return;
    }
    (void)fw_image_security(&img, slot_read, &s, &counter);
    if (!slot_read(&s, fw_image_tlv_offset(&img), info, sizeof(info)) ||
        !fw_image_total(&img, info, &total) || total > size) {
        return;
    }
    // What firmware.c and hooks.c hash: [0, total).
    // It must hold the header and the TLV info they parsed,
    // or the hash would not cover what the panel showed.
    if (total < FW_IMAGE_HEADER_SIZE ||
        (uint64_t)fw_image_tlv_offset(&img) + FW_IMAGE_TLV_INFO_SIZE > total) {
        abort();
    }
    if ((uint64_t)img.hdr_size + img.img_size + img.protect_tlv_size > total) {
        // The sum wrapped: the hash covers less than the header names.
        abort();
    }
}

static void record(const uint8_t *data, size_t size)
{
    uint8_t area[INSTALL_AUTH_AREA_SIZE];
    uint8_t copy[INSTALL_AUTH_COPY_SIZE];
    install_auth_t a;
    install_auth_t b;
    uint32_t off;

    memset(area, 0xff, sizeof(area));
    memcpy(area, data, size < sizeof(area) ? size : sizeof(area));
    install_auth_parse(area, &a);
    if (a.state > INSTALL_AUTH_TESTING || a.copy > 2) {
        abort();
    }
    if (a.copy == 2 && a.state != INSTALL_AUTH_IDLE) {
        abort();
    }
    b = a;
    off = install_auth_encode(&b, copy);
    if (off != 0 && off != INSTALL_AUTH_COPY_STRIDE) {
        abort();
    }
    memcpy(area + off, copy, sizeof(copy));
    install_auth_parse(area, &a);
    if (a.state != b.state || a.min_security != b.min_security || a.pending != b.pending ||
        a.seq != b.seq || a.copy != b.copy || memcmp(a.hash, b.hash, sizeof(a.hash)) ||
        memcmp(a.revert, b.revert, sizeof(a.revert))) {
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) {
        return -1;
    }
    if (data[0] & 1) {
        record(data + 1, size - 1);
    } else {
        image(data + 1, size - 1);
    }
    return 0;
}
