// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// Zephyr's MCUboot calls for NS, on MCUboot's own bootutil_public.c (sim/src/flash.c).

#pragma once

#include <bootutil/bootutil_public.h>

#define BOOT_UPGRADE_TEST 0
#define BOOT_UPGRADE_PERMANENT 1

int boot_request_upgrade_multi(int image_index, int permanent);
int mcuboot_swap_type_multi(int image_index);
int boot_write_img_confirmed_multi(int image_index);
