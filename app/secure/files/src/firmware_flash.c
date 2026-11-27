// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "files/firmware.h"
#include "Driver_Flash.h"
#include "flash_layout.h"
#include <string.h>
#include <zephyr/autoconf.h>
// FIRMWARE_INFO_MAGIC comes from secure/CMakeLists.txt, as for TF-M's own fw_info service.
#include <fw_info_bare.h>

// slot0, slot1 and the install record in RRAM.
// At isolation level 1 the partition can read all flash and write through TF-M's flash driver,
// the one ITS uses.
// flash_layout.h (NCS tfm_boards) has the devicetree macros that work in a TF-M build.

#define SLOT0_ADDR TFM_DT_REG_ADDR(TFM_DT_NODELABEL(slot0_partition))
#define SLOT0_SIZE TFM_DT_REG_SIZE(TFM_DT_NODELABEL(slot0_partition))
#define SLOT1_ADDR TFM_DT_REG_ADDR(TFM_DT_NODELABEL(slot1_partition))
#define SLOT1_SIZE TFM_DT_REG_SIZE(TFM_DT_NODELABEL(slot1_partition))
#define AUTH_ADDR TFM_DT_REG_ADDR(TFM_DT_NODELABEL(sigu_install_partition))
#define S0_ADDR TFM_DT_REG_ADDR(TFM_DT_NODELABEL(s0_partition))
#define S1_ADDR TFM_DT_REG_ADDR(TFM_DT_NODELABEL(s1_partition))

extern ARM_DRIVER_FLASH Driver_FLASH0;

static bool slot_read(uint32_t base, uint32_t size, uint32_t off, void *buf, size_t len)
{
    if (off > size || len > size - off) {
        return false;
    }
    memcpy(buf, (const void *)(uintptr_t)(base + off), len);
    return true;
}

bool firmware_slot0_read(uint32_t off, void *buf, size_t len)
{
    return slot_read(SLOT0_ADDR, SLOT0_SIZE, off, buf, len);
}

uint32_t firmware_slot0_size(void)
{
    return SLOT0_SIZE;
}

// NS writes slot1. A read gives what is there now, so the caller hashes what it shows.
bool firmware_slot1_read(uint32_t off, void *buf, size_t len)
{
    return slot_read(SLOT1_ADDR, SLOT1_SIZE, off, buf, len);
}

uint32_t firmware_slot1_size(void)
{
    return SLOT1_SIZE;
}

bool firmware_is_boot_addr(uint32_t load_addr)
{
    return load_addr == S0_ADDR || load_addr == S1_ADDR;
}

bool firmware_slot1_boot_version(uint32_t *version)
{
    const struct fw_info *found = fw_info_find(SLOT1_ADDR);
    struct fw_info info;

    if (!found) {
        return false;
    }
    memcpy(&info, found, sizeof(info));
    if (info.valid != CONFIG_FW_INFO_VALID_VAL) {
        return false;
    }
    *version = info.version;
    return true;
}

void firmware_auth_read(uint8_t area[INSTALL_AUTH_AREA_SIZE])
{
    memcpy(area, (const void *)(uintptr_t)AUTH_ADDR, INSTALL_AUTH_AREA_SIZE);
}

// Word by word. A power loss in the middle tears this copy only, and the reader takes the other.
bool firmware_auth_write(uint32_t off, const uint8_t rec[INSTALL_AUTH_COPY_SIZE])
{
    uint32_t words = INSTALL_AUTH_COPY_SIZE / 4;

    if (off > INSTALL_AUTH_AREA_SIZE - INSTALL_AUTH_COPY_SIZE ||
        Driver_FLASH0.Initialize(NULL) != ARM_DRIVER_OK) {
        return false;
    }
    return Driver_FLASH0.ProgramData(AUTH_ADDR + off, rec, words) == (int32_t)words;
}
