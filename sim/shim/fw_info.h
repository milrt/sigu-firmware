// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// NCS fw_info, as NS reads it, with the nRF54L magic. sim/tests uses the same values.

#pragma once

#include <stdint.h>

#define FIRMWARE_INFO_MAGIC 0x281ee6de, 0x8fcebb4c, 0x00003602
#define CONFIG_FW_INFO_VALID_VAL 0x9102FFFF

struct __attribute__((packed)) fw_info {
    uint32_t magic[3];
    uint32_t total_size;
    uint32_t size;
    uint32_t version;
    uint32_t address;
    uint32_t boot_address;
    uint32_t valid;
    uint32_t reserved[4];
    uint32_t ext_api_num;
    uint32_t ext_api_request_num;
};
