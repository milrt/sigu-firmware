// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The panel as the screens draw it.
// A frame is a list of draw calls from panel_clear() to panel_flush(),
// and the flush sends only the bands that changed.

#pragma once

#include "drivers/font.h"
#include <stdbool.h>
#include <stdint.h>

#define PANEL_W 240
#define PANEL_H 240

// RGB565 from 0xRRGGBB. The low bits are truncated, not rounded.
#define RGB565(hex)                                                                                \
    ((uint16_t)((((hex) >> 8) & 0xF800) | (((hex) >> 5) & 0x07E0) | (((hex) >> 3) & 0x001F)))

// The check mark glyph, the last one in every font.
#define PANEL_SYMBOL_OK "\x7f"

// Turns the panel on.
void panel_init(void);

// Starts a new frame on a `color` background. The draw calls after it make up the frame.
void panel_clear(uint16_t color);

void panel_fill_rect(int x, int y, int w, int h, uint16_t color);

// One line of text with its line box at (x, y). It blends onto what is already drawn.
void panel_draw_text(int x, int y, const char *s, const font_t *f, uint16_t fg);

// Text wrapped to `w` pixels. Returns the height it takes, one line for an empty string.
int panel_draw_text_wrapped(int x, int y, int w, const char *s, const font_t *f, uint16_t fg);

int panel_text_width(const char *s, const font_t *f);

// Bytes of 1-bit bitmaps one frame can hold. One 45x45 QR code (version 7) is 254 bytes.
#define PANEL_MONO_MAX 256

// A `w` x `h` bitmap, each bit a `scale` x `scale` square in `fg`.
// A clear bit leaves what is drawn.
// `bits` is row-major and LSB-first: bit i = row * w + col, the qrcodegen layout.
void panel_draw_mono(int x, int y, const uint8_t *bits, int w, int h, int scale, uint16_t fg);

void panel_flush(void);

// Backlight brightness from 0 to 100. A value above 100 is taken as 100.
void panel_backlight(uint8_t percent);
