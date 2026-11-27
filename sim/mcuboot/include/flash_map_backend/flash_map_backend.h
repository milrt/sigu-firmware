// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// MCUboot's flash API on the sim's RAM flash map,
// as boot/zephyr/include/flash_map_backend does it on Zephyr's flash map.
// sim/mcuboot/port.c has the functions.

#pragma once

#include <zephyr/storage/flash_map.h>

#define FLASH_DEVICE_ID 0

static inline uint32_t flash_area_get_off(const struct flash_area *fa)
{
    return (uint32_t)fa->fa_off;
}

static inline uint32_t flash_area_get_size(const struct flash_area *fa)
{
    return (uint32_t)fa->fa_size;
}

static inline uint8_t flash_area_get_id(const struct flash_area *fa)
{
    return fa->fa_id;
}

static inline uint8_t flash_area_get_device_id(const struct flash_area *fa)
{
    (void)fa;
    return FLASH_DEVICE_ID;
}

static inline uint32_t flash_sector_get_off(const struct flash_sector *fs)
{
    return (uint32_t)fs->fs_off;
}

static inline uint32_t flash_sector_get_size(const struct flash_sector *fs)
{
    return (uint32_t)fs->fs_size;
}

int flash_device_base(uint8_t fd_id, uintptr_t *ret);
int flash_area_id_from_multi_image_slot(int image_index, int slot);
int flash_area_id_from_image_slot(int slot);
int flash_area_id_to_multi_image_slot(int image_index, int area_id);
int flash_area_sector_from_off(off_t off, struct flash_sector *sector);
int flash_area_get_sector(const struct flash_area *fa, off_t off, struct flash_sector *sector);
