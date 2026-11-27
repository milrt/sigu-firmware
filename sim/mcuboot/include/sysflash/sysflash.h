// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The slots, as boot/zephyr/include/sysflash/sysflash.h maps them,
// for MCUboot as the NCS second stage running from s0:
// image 0 is the app (slot0, slot1), image 1 is MCUboot (the inactive s1, and slot1 as the source).

#pragma once

#include <mcuboot_config/mcuboot_config.h>
#include <zephyr/storage/flash_map.h>

#define SECOND_STAGE_ACTIVE_MCUBOOT_OFFSET PARTITION_OFFSET(s0_partition)
#define SECOND_STAGE_ACTIVE_MCUBOOT_SIZE PARTITION_SIZE(s0_partition)
#define SECOND_STAGE_ACTIVE_MCUBOOT_ID PARTITION_ID(s0_partition)
#define SECOND_STAGE_INACTIVE_MCUBOOT_OFFSET PARTITION_OFFSET(s1_partition)
#define SECOND_STAGE_INACTIVE_MCUBOOT_SIZE PARTITION_SIZE(s1_partition)
#define SECOND_STAGE_INACTIVE_MCUBOOT_ID PARTITION_ID(s1_partition)
#define MCUBOOT_NEEDED_SLOT_PAIRS (MCUBOOT_IMAGE_NUMBER - 1)

#define FLASH_AREA_IMAGE_PRIMARY(x)                                                                \
    ((x) == 0 ? PARTITION_ID(slot0_partition) : SECOND_STAGE_INACTIVE_MCUBOOT_ID)
#define FLASH_AREA_IMAGE_SECONDARY(x) ((void)(x), PARTITION_ID(slot1_partition))
