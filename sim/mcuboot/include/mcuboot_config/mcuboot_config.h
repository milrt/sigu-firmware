// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// MCUboot's configuration for the sim,
// as the device's .config sets it (sysbuild/mcuboot.conf and the NCS defaults):
// swap-using-move, two images (the app and MCUboot itself in s0/s1, the NCS second stage),
// slot0 checked on every boot, the header load address check, 16-byte writes, our hooks.
// Two differences. The image hash is SHA-256 with no signature (the device uses SHA-512, ed25519),
// so a bad hash TLV stands for a bad signature. And there is no FIH.

#pragma once

#define MCUBOOT_SWAP_USING_MOVE 1
#define MCUBOOT_IMAGE_NUMBER 2
#define MCUBOOT_IS_SECOND_STAGE 1
#define CONFIG_MCUBOOT_APPLICATION_IMAGE_NUMBER 0
#define CONFIG_MCUBOOT_MCUBOOT_IMAGE_NUMBER 1
#define CONFIG_MCUBOOT_NETWORK_CORE_IMAGE_NUMBER -1
#define CONFIG_NCS_MCUBOOT_IMG_VALIDATE_ATTEMPT_COUNT 1
#define MCUBOOT_VALIDATE_PRIMARY_SLOT
#define MCUBOOT_CHECK_HEADER_LOAD_ADDRESS
#define MCUBOOT_USE_FLASH_AREA_GET_SECTORS
#define MCUBOOT_SUPPORT_DEV_WITHOUT_ERASE
#define MCUBOOT_ERASE_PROGRESSIVELY
#define MCUBOOT_BOOT_MAX_ALIGN 16
// Sectors in slot0 (628 KB / 4 KB), as BOOT_MAX_IMG_SECTORS_AUTO sets it on the device.
#define MCUBOOT_MAX_IMG_SECTORS 157
#define MCUBOOT_USE_PSA_CRYPTO
#define MCUBOOT_SHA256
#define MCUBOOT_IMAGE_ACCESS_HOOKS
#define MCUBOOT_BOOT_GO_HOOKS
#define MCUBOOT_HAVE_LOGGING 1
#define MCUBOOT_HAVE_ASSERT_H 1
#define MCUBOOT_FIH_PROFILE_OFF

// Zephyr's sys/util.h has these. The second stage code uses them.
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define MCUBOOT_WATCHDOG_FEED()                                                                    \
    do {                                                                                           \
    } while (0)
#define MCUBOOT_CPU_IDLE()                                                                         \
    do {                                                                                           \
    } while (0)
