// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The TF-M platform calls that read the bootloader in s0/s1.
// sim/src/flash.c answers them from the "boot" control command.

#pragma once

#include "fw_info.h"
#include <stdbool.h>
#include <stdint.h>

int tfm_platform_firmware_info(uint32_t fw_address, struct fw_info *info);
int tfm_platform_s0_active(uint32_t s0_address, uint32_t s1_address, bool *s0_active);
