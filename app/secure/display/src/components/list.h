// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

// Rows start at LIST_Y, LIST_STEP apart, and LIST_ROWS fit above the soft keys.
#define LIST_Y 40
#define LIST_STEP 26
#define LIST_ROWS 6

// Draws `labels` with `sel` on a fill. Past LIST_ROWS it scrolls, so `sel` is always shown.
// An arrow on the left marks rows hidden above or below.
void list_draw(const char *const *labels, uint8_t n, uint8_t sel);
// As list_draw(), with `values[i]` right-aligned in row i. `values` and each entry may be NULL.
void list_draw_values(const char *const *labels, const char *const *values, uint8_t n, uint8_t sel);
