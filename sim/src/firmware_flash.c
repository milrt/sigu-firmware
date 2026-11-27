// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The partition's flash access, as app/secure/files/src/firmware_flash.c on the device:
// slot0, slot1 and the install record, on the sim's flash map (sim/src/flash.c).

#include "files/firmware.h"
#include "sim.h"
#include <fw_info.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/devicetree.h>
#include <zephyr/storage/flash_map.h>

static bool area_read(uint8_t id, uint32_t off, void *buf, size_t len)
{
    const struct flash_area *fa;

    return flash_area_open(id, &fa) == 0 && off <= fa->fa_size && len <= fa->fa_size - off &&
           flash_area_read(fa, (off_t)off, buf, len) == 0;
}

bool firmware_slot0_read(uint32_t off, void *buf, size_t len)
{
    return area_read(PARTITION_ID(slot0_partition), off, buf, len);
}

uint32_t firmware_slot0_size(void)
{
    return PARTITION_SIZE(slot0_partition);
}

bool firmware_slot1_read(uint32_t off, void *buf, size_t len)
{
    return area_read(PARTITION_ID(slot1_partition), off, buf, len);
}

uint32_t firmware_slot1_size(void)
{
    return PARTITION_SIZE(slot1_partition);
}

bool firmware_is_boot_addr(uint32_t load_addr)
{
    return load_addr == DT_REG_ADDR(DT_NODELABEL(s0_partition)) ||
           load_addr == DT_REG_ADDR(DT_NODELABEL(s1_partition));
}

// fw_info_find() on the device.
bool firmware_slot1_boot_version(uint32_t *version)
{
    static const uint32_t offsets[] = {0x0, 0x200, 0x400, 0x600, 0x800, 0xe00, 0x1000};
    const uint32_t magic[] = {FIRMWARE_INFO_MAGIC};

    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        struct fw_info info;

        if (firmware_slot1_read(offsets[i], &info, sizeof(info)) &&
            memcmp(info.magic, magic, sizeof(magic)) == 0 &&
            info.valid == CONFIG_FW_INFO_VALID_VAL) {
            *version = info.version;
            return true;
        }
    }
    return false;
}

void firmware_auth_read(uint8_t area[INSTALL_AUTH_AREA_SIZE])
{
    if (!area_read(PARTITION_ID(sigu_install_partition), 0, area, INSTALL_AUTH_AREA_SIZE)) {
        memset(area, 0xff, INSTALL_AUTH_AREA_SIZE);
    }
}

bool firmware_auth_write(uint32_t off, const uint8_t rec[INSTALL_AUTH_COPY_SIZE])
{
    const struct flash_area *fa;
    uint8_t area[INSTALL_AUTH_AREA_SIZE];
    install_auth_t auth;
    uint32_t words;

    if (off > INSTALL_AUTH_AREA_SIZE - INSTALL_AUTH_COPY_SIZE ||
        flash_area_open(PARTITION_ID(sigu_install_partition), &fa) != 0) {
        return false;
    }
    // "forge authcut": the power fails after `words` words, as in the device's word loop.
    if (sim_auth_cut_take(&words)) {
        if (words > INSTALL_AUTH_COPY_SIZE / 4) {
            words = INSTALL_AUTH_COPY_SIZE / 4;
        }
        flash_area_write(fa, (off_t)off, rec, words * 4);
        fprintf(stderr, "[SIM] power cut in the SP record write after %u words\n",
                (unsigned int)words);
        return false;
    }
    if (flash_area_write(fa, (off_t)off, rec, INSTALL_AUTH_COPY_SIZE) != 0) {
        return false;
    }
    firmware_auth_read(area);
    install_auth_parse(area, &auth);
    fprintf(stderr, "[SIM] install record: state %d\n", (int)auth.state);
    return true;
}
