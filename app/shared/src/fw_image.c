// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "shared/fw_image.h"
#include "shared/wire.h"

// struct image_header and struct image_tlv_info in MCUboot's image.h.
#define IMAGE_MAGIC 0x96f3b83dU
#define TLV_INFO_MAGIC 0x6907U
#define TLV_PROT_INFO_MAGIC 0x6908U
// struct image_tlv: type u8, a pad byte, len u16.
#define TLV_SIZE 4
#define TLV_SEC_CNT 0x50U

bool fw_image_parse(const uint8_t hdr[FW_IMAGE_HEADER_SIZE], fw_image_t *img)
{
    wire_r r = wire_reader(hdr, FW_IMAGE_HEADER_SIZE);
    uint32_t magic = wire_get_le32(&r);

    img->load_addr = wire_get_le32(&r);
    img->hdr_size = (uint32_t)wire_get_le(&r, 2);
    img->protect_tlv_size = (uint32_t)wire_get_le(&r, 2);
    img->img_size = wire_get_le32(&r);
    img->flags = wire_get_le32(&r);
    img->major = wire_get_u8(&r);
    img->minor = wire_get_u8(&r);
    img->revision = (uint16_t)wire_get_le(&r, 2);
    // The three sizes are added as u32 below.
    // A sum that wraps would put the TLVs, and the end of the hashed image,
    // before the end the header names.
    return r.ok && magic == IMAGE_MAGIC && img->hdr_size >= FW_IMAGE_HEADER_SIZE &&
           (uint64_t)img->hdr_size + img->img_size + img->protect_tlv_size <=
               UINT32_MAX - UINT16_MAX;
}

uint32_t fw_image_tlv_offset(const fw_image_t *img)
{
    return img->hdr_size + img->img_size + img->protect_tlv_size;
}

bool fw_image_total(const fw_image_t *img, const uint8_t info[FW_IMAGE_TLV_INFO_SIZE],
                    uint32_t *total)
{
    wire_r r = wire_reader(info, FW_IMAGE_TLV_INFO_SIZE);
    uint32_t magic = (uint32_t)wire_get_le(&r, 2);
    uint32_t len = (uint32_t)wire_get_le(&r, 2);

    if (!r.ok || magic != TLV_INFO_MAGIC || len < FW_IMAGE_TLV_INFO_SIZE) {
        return false;
    }
    *total = fw_image_tlv_offset(img) + len;
    return true;
}

bool fw_image_security(const fw_image_t *img, fw_image_read_t read, void *ctx, uint32_t *counter)
{
    uint32_t start = img->hdr_size + img->img_size;
    uint32_t end = start + img->protect_tlv_size;
    uint8_t buf[TLV_SIZE];
    wire_r r;

    *counter = 0;
    if (img->protect_tlv_size == 0) {
        return true;
    }
    if (!read(ctx, start, buf, sizeof(buf))) {
        return false;
    }
    r = wire_reader(buf, sizeof(buf));
    if (wire_get_le(&r, 2) != TLV_PROT_INFO_MAGIC || wire_get_le(&r, 2) != img->protect_tlv_size) {
        return false;
    }
    for (uint32_t off = start + TLV_SIZE; off < end;) {
        uint32_t type;
        uint32_t len;
        uint8_t value[4];

        if (end - off < TLV_SIZE || !read(ctx, off, buf, sizeof(buf))) {
            return false;
        }
        r = wire_reader(buf, sizeof(buf));
        type = wire_get_u8(&r);
        (void)wire_get_u8(&r);
        len = (uint32_t)wire_get_le(&r, 2);
        off += TLV_SIZE;
        if (len > end - off) {
            return false;
        }
        if (type == TLV_SEC_CNT) {
            if (len != sizeof(value) || !read(ctx, off, value, sizeof(value))) {
                return false;
            }
            r = wire_reader(value, sizeof(value));
            *counter = wire_get_le32(&r);
            return true;
        }
        off += len;
    }
    return true;
}

void fw_image_hash_text(const uint8_t hash[32], char out[FW_IMAGE_HASH_TEXT_SIZE])
{
    static const char hex[] = "0123456789abcdef";

    for (int i = 0; i < (FW_IMAGE_HASH_TEXT_SIZE - 1) / 2; i++) {
        out[2 * i] = hex[hash[i] >> 4];
        out[2 * i + 1] = hex[hash[i] & 0xf];
    }
    out[FW_IMAGE_HASH_TEXT_SIZE - 1] = '\0';
}
