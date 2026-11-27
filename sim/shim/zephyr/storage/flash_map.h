// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The flash map on RAM areas, in sim/src/flash.c:
// the partitions MCUboot, NS and the SP use, at their offsets in app/boards/sigu_partitions.dtsi.
// Keep them in sync. NS and the real MCUboot (sim/mcuboot) both use this API, as on the device.

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define PARTITION_ID(label) SIM_ID_##label
#define PARTITION_OFFSET(label) SIM_OFF_##label
#define PARTITION_SIZE(label) SIM_SIZE_##label

#define SIM_ID_slot0_partition 0
#define SIM_ID_slot1_partition 1
#define SIM_ID_s0_partition 2
#define SIM_ID_s1_partition 3
#define SIM_ID_sigu_install_partition 4
#define SIM_AREAS 5

#define SIM_OFF_slot0_partition 0x34000
#define SIM_OFF_slot1_partition 0xd1000
#define SIM_OFF_s0_partition 0x8000
#define SIM_OFF_s1_partition 0x19000
#define SIM_OFF_sigu_install_partition 0x7800

#define SIM_SIZE_slot0_partition (628 * 1024)
#define SIM_SIZE_slot1_partition (624 * 1024)
#define SIM_SIZE_s0_partition (68 * 1024)
#define SIM_SIZE_s1_partition (68 * 1024)
#define SIM_SIZE_sigu_install_partition (2 * 1024)

// RRAM: 4 KB erase blocks for MCUboot's sector math, 16-byte writes.
#define SIM_SECTOR_SIZE 0x1000

struct flash_area {
    uint8_t fa_id;
    off_t fa_off;
    size_t fa_size;
};

struct flash_sector {
    off_t fs_off;
    size_t fs_size;
};

int flash_area_open(uint8_t id, const struct flash_area **fa);
void flash_area_close(const struct flash_area *fa);
int flash_area_read(const struct flash_area *fa, off_t off, void *dst, size_t len);
int flash_area_write(const struct flash_area *fa, off_t off, const void *src, size_t len);
int flash_area_erase(const struct flash_area *fa, off_t off, size_t len);
uint32_t flash_area_align(const struct flash_area *fa);
uint8_t flash_area_erased_val(const struct flash_area *fa);
int flash_area_get_sectors(int fa_id, uint32_t *count, struct flash_sector *sectors);
