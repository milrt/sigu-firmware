// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

// Cell codes besides printable ASCII. WHEEL_DONE draws the check mark.
#define WHEEL_DONE '\0'
#define WHEEL_MODE '\x01'
#define WHEEL_DEL '\x02'
#define WHEEL_CANCEL '\x03'
#define WHEEL_LEFT '\x04'
#define WHEEL_RIGHT '\x05'

// Top of the wheel row, just above the soft-key rule.
#define WHEEL_Y 164

// Draws up to five cells of `choices` around `sel`, with `sel` on a tile.
void wheel_draw(const char *choices, uint8_t n, uint8_t sel);
