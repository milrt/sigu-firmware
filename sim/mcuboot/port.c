// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The part of MCUboot's Zephyr port the sim needs,
// boot/zephyr/flash_map_extended.c and the call in boot/zephyr/main.c,
// on the RAM flash map in sim/src/flash.c.
// The loader, the swap and the checks are MCUboot's own sources, built unchanged,
// with app/mcuboot_hooks/hooks.c.

#include "bootutil/boot_hooks.h"
#include "bootutil/bootutil.h"
#include "bootutil/fault_injection_hardening.h"
#include "flash_map_backend/flash_map_backend.h"
#include "sim_mcuboot.h"
#include "sysflash/sysflash.h"
#include <stdio.h>

bool sim_mcuboot_booting;

int flash_device_base(uint8_t fd_id, uintptr_t *ret)
{
    (void)fd_id;
    *ret = 0;
    return 0;
}

int flash_area_id_from_multi_image_slot(int image_index, int slot)
{
    switch (slot) {
    case 0:
        return FLASH_AREA_IMAGE_PRIMARY(image_index);
    case 1:
        return FLASH_AREA_IMAGE_SECONDARY(image_index);
    default:
        return -1;
    }
}

int flash_area_id_from_image_slot(int slot)
{
    return flash_area_id_from_multi_image_slot(0, slot);
}

int flash_area_id_to_multi_image_slot(int image_index, int area_id)
{
    if (area_id == FLASH_AREA_IMAGE_PRIMARY(image_index)) {
        return 0;
    }
    if (area_id == FLASH_AREA_IMAGE_SECONDARY(image_index)) {
        return 1;
    }
    return -1;
}

int flash_area_get_sectors(int fa_id, uint32_t *count, struct flash_sector *sectors)
{
    const struct flash_area *fa;
    uint32_t n;

    if (flash_area_open((uint8_t)fa_id, &fa) != 0) {
        return -1;
    }
    n = (uint32_t)(fa->fa_size / SIM_SECTOR_SIZE);
    flash_area_close(fa);
    if (n > *count) {
        return -1;
    }
    for (uint32_t i = 0; i < n; i++) {
        sectors[i].fs_off = (off_t)(i * SIM_SECTOR_SIZE);
        sectors[i].fs_size = SIM_SECTOR_SIZE;
    }
    *count = n;
    return 0;
}

int flash_area_sector_from_off(off_t off, struct flash_sector *sector)
{
    sector->fs_off = off - off % SIM_SECTOR_SIZE;
    sector->fs_size = SIM_SECTOR_SIZE;
    return 0;
}

int flash_area_get_sector(const struct flash_area *fa, off_t off, struct flash_sector *sector)
{
    if (off < 0 || (size_t)off >= fa->fa_size) {
        return -1;
    }
    return flash_area_sector_from_off(off, sector);
}

bool sim_mcuboot_boot(void)
{
    struct boot_rsp rsp;
    FIH_DECLARE(fih_rc, FIH_FAILURE);

    // As boot/zephyr/main.c: the hook runs boot_go() itself.
    sim_mcuboot_booting = true;
    BOOT_HOOK_GO_CALL_FIH(boot_go_hook, FIH_BOOT_HOOK_REGULAR, fih_rc, &rsp);
    if (FIH_EQ(fih_rc, FIH_BOOT_HOOK_REGULAR)) {
        FIH_CALL(boot_go, fih_rc, &rsp);
    }
    sim_mcuboot_booting = false;
    if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
        fprintf(stderr, "[MCUBOOT] E: Unable to find bootable image\n");
        return false;
    }
    fprintf(stderr, "[MCUBOOT] I: Jumping to the first image slot\n");
    return true;
}
