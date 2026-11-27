// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "files/firmware.h"
#include "shared/bitcoin_service_defs.h"
#include "shared/hash.h"
#include <string.h>

// SHA-256 over the whole signed image: header, body and TLVs, as in the file imgtool wrote.
// NS hashes the card file the same way, and MCUboot hashes slot1 the same way before it installs.

#define CHUNK 256

typedef bool (*read_fn)(uint32_t off, void *buf, size_t len);

static firmware_image_t now;
static bool done;

// Copies flash to RAM first. The crypto service gets a RAM buffer, never a flash pointer.
static bool hash_image(read_fn read, uint32_t total, uint8_t hash[32])
{
    hash_sha256_stream_t stream;
    uint8_t buf[CHUNK];
    bool ok = hash_sha256_stream_init(&stream) == PSA_SUCCESS;

    for (uint32_t off = 0; ok && off < total; off += CHUNK) {
        size_t n = total - off < CHUNK ? total - off : CHUNK;

        ok = read(off, buf, n) && hash_sha256_stream_update(&stream, buf, n) == PSA_SUCCESS;
    }
    if (!ok) {
        hash_sha256_stream_abort(&stream);
        return false;
    }
    return hash_sha256_stream_finish(&stream, hash, 32) == PSA_SUCCESS;
}

// fw_image_security() reads through a context pointer. Here it points to the read function.
static bool tlv_read(void *ctx, uint32_t off, void *buf, size_t len)
{
    return (*(read_fn *)ctx)(off, buf, len);
}

static bool load(read_fn read, uint32_t size, firmware_image_t *out)
{
    uint8_t hdr[FW_IMAGE_HEADER_SIZE];
    uint8_t info[FW_IMAGE_TLV_INFO_SIZE];
    fw_image_t img;
    uint32_t total;

    memset(out, 0, sizeof(*out));
    if (!read(0, hdr, sizeof(hdr)) || !fw_image_parse(hdr, &img) ||
        !read(fw_image_tlv_offset(&img), info, sizeof(info)) ||
        !fw_image_total(&img, info, &total) || total > size ||
        !fw_image_security(&img, tlv_read, &read, &out->security) ||
        !hash_image(read, total, out->sha256)) {
        return false;
    }
    out->major = img.major;
    out->minor = img.minor;
    out->revision = img.revision;
    out->is_boot = firmware_is_boot_addr(img.load_addr);
    fw_image_hash_text(out->sha256, out->hash);
    return true;
}

const firmware_image_t *firmware_now(void)
{
    if (!done) {
        now.ok = load(firmware_slot0_read, firmware_slot0_size(), &now);
        done = true;
    }
    return &now;
}

void firmware_staged(firmware_image_t *out)
{
    out->ok = load(firmware_slot1_read, firmware_slot1_size(), out);
    out->has_boot_version = out->ok && firmware_slot1_boot_version(&out->boot_version);
}

static void auth_load(install_auth_t *auth)
{
    uint8_t area[INSTALL_AUTH_AREA_SIZE];

    firmware_auth_read(area);
    install_auth_parse(area, auth);
}

uint32_t firmware_min_security(void)
{
    install_auth_t auth;

    auth_load(&auth);
    return auth.min_security;
}

// Over SWAPPING or TESTING, MCUboot would close slot0 on the next boot,
// and the test app would stay with no confirm.
// The floor is kept as it is: only MCUboot raises it.
uint32_t firmware_authorize(const uint8_t sha256[INSTALL_AUTH_HASH_SIZE])
{
    install_auth_t auth;
    _Alignas(4) uint8_t rec[INSTALL_AUTH_COPY_SIZE];
    uint32_t off;

    auth_load(&auth);
    if (auth.state == INSTALL_AUTH_SWAPPING || auth.state == INSTALL_AUTH_TESTING) {
        return BITCOIN_INSTALL_PENDING;
    }
    auth.state = INSTALL_AUTH_AUTHORIZED;
    auth.pending = 0;
    memcpy(auth.hash, sha256, sizeof(auth.hash));
    memset(auth.revert, 0, sizeof(auth.revert));
    off = install_auth_encode(&auth, rec);
    return firmware_auth_write(off, rec) ? BITCOIN_INSTALL_OK : BITCOIN_INSTALL_WRITE_FAILED;
}
