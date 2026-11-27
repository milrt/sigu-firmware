// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

// ASCII 0x20 to 0x7E, then the check mark at 0x7F.
#define FONT_FIRST 0x20
#define FONT_GLYPHS 96

typedef struct {
    uint32_t bitmap;
    uint16_t adv;
    uint8_t w;
    uint8_t h;
    int8_t x;
    int8_t y;
} font_glyph_t;

// 4bpp alpha, high nibble first, packed across rows. adv and kern are in 1/16 px.
// kern is indexed [(left - 1) * kern_right_n + (right - 1)], class 0 means none.
typedef struct font {
    const uint8_t *bitmap;
    const font_glyph_t *glyph;
    const uint8_t *kern_left;
    const uint8_t *kern_right;
    const int8_t *kern;
    uint8_t kern_right_n;
    uint8_t line_height;
    uint8_t base_line;
} font_t;

extern const font_t font_16;
extern const font_t font_20;
extern const font_t font_24;
