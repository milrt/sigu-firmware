// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stdint.h>

// Starts the backlight PWM with the light off, then resets the ST7789 and sends the init sequence.
// The panel stays blanked. The panel is write-only, so no failure can be seen.
void panel_hw_init(void);

// Sends w*h RGB565 pixels to the window at (x, y). They must already be in panel byte order.
void panel_hw_write_window(uint16_t x, uint16_t y, uint16_t w, uint16_t h, const uint16_t *pixels);

void panel_hw_blank(bool on);

// Backlight brightness from 0 to 100. A value above 100 is taken as 100.
void panel_hw_backlight(uint8_t percent);

// GAMSET curve 0-3: gamma 2.2, 1.8, 2.5 or 1.0.
void panel_hw_gamma(uint8_t curve);
