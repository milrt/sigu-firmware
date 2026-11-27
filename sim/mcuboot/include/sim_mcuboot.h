// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>

// One boot of MCUboot on the sim's flash, with our hooks.
// False when it found nothing to boot, as the device would halt.
bool sim_mcuboot_boot(void);
