// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

#define INPUT_DEL (1U << 0)
#define INPUT_NEXT (1U << 1)
#define INPUT_OK (1U << 2)

void input_init(void);

// INPUT_* bits of the keys pressed since the last call.
uint32_t input_poll(void);
