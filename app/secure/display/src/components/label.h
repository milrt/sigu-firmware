// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "drivers/panel.h"

// The anchors the screens use. The offset moves the text away from the anchor.
typedef enum {
    LABEL_TOP_LEFT,
    LABEL_TOP_MID,
    LABEL_CENTER,
    LABEL_BOTTOM_LEFT,
    LABEL_BOTTOM_MID,
    LABEL_BOTTOM_RIGHT,
} label_align_t;

void label_draw(const char *text, const font_t *font, uint16_t color, label_align_t align, int x,
                int y);

// One line centered in a cell `w` px wide that starts at x.
void label_draw_centered_in(const char *text, const font_t *font, uint16_t color, int x, int w,
                            int y);
