// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// A signed MCUboot image as imgtool writes it: the header, the body, the protected TLVs, the TLVs.
// The SP reads the running one in slot0, NS reads the one on the card.
// Both hash all of it with SHA-256, so the two hashes compare, and so does `shasum -a 256`.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FW_IMAGE_HEADER_SIZE 32
#define FW_IMAGE_TLV_INFO_SIZE 4
#define FW_IMAGE_F_ROM_FIXED 0x100U
// The first 16 hex characters of the hash, and the NUL.
// The panel shows 8 in a list and all 16 where the user confirms the install.
#define FW_IMAGE_HASH_TEXT_SIZE 17

typedef struct {
    uint32_t load_addr;
    uint32_t flags;
    uint32_t hdr_size;
    uint32_t protect_tlv_size;
    uint32_t img_size;
    uint8_t major;
    uint8_t minor;
    uint16_t revision;
} fw_image_t;

// False when `hdr` is not an MCUboot header.
bool fw_image_parse(const uint8_t hdr[FW_IMAGE_HEADER_SIZE], fw_image_t *img);

// Where the TLV info is. Read FW_IMAGE_TLV_INFO_SIZE bytes there for fw_image_total().
uint32_t fw_image_tlv_offset(const fw_image_t *img);

// The size of the whole image, up to the last TLV. False when `info` is not a TLV info.
bool fw_image_total(const fw_image_t *img, const uint8_t info[FW_IMAGE_TLV_INFO_SIZE],
                    uint32_t *total);

// Reads `len` bytes at `off` from the start of the image. False on an error or past the slot.
typedef bool (*fw_image_read_t)(void *ctx, uint32_t off, void *buf, size_t len);

// The security counter (imgtool --security-counter, TLV SEC_CNT) from the protected TLVs,
// which the signature covers.
// 0 when the image has none. False when the protected TLVs are broken.
bool fw_image_security(const fw_image_t *img, fw_image_read_t read, void *ctx, uint32_t *counter);

// The first 16 hex characters of a SHA-256, NUL terminated.
void fw_image_hash_text(const uint8_t hash[32], char out[FW_IMAGE_HASH_TEXT_SIZE]);
