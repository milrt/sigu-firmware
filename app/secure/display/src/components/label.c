// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "components/label.h"

// Aligns on the 240x240 screen with no padding. A label is as wide as its text and one line high.
// w / 2 and h / 2 round down, so odd-sized text sits half a pixel right or down.
void label_draw(const char *text, const font_t *font, uint16_t color, label_align_t align, int x,
                int y)
{
    int w = panel_text_width(text, font);
    int h = font->line_height;

    switch (align) {
    case LABEL_TOP_LEFT:
        break;
    case LABEL_TOP_MID:
        x += PANEL_W / 2 - w / 2;
        break;
    case LABEL_CENTER:
        x += PANEL_W / 2 - w / 2;
        y += PANEL_H / 2 - h / 2;
        break;
    case LABEL_BOTTOM_LEFT:
        y += PANEL_H - h;
        break;
    case LABEL_BOTTOM_MID:
        x += PANEL_W / 2 - w / 2;
        y += PANEL_H - h;
        break;
    case LABEL_BOTTOM_RIGHT:
        x += PANEL_W - w;
        y += PANEL_H - h;
        break;
    }
    panel_draw_text(x, y, text, font, color);
}

void label_draw_centered_in(const char *text, const font_t *font, uint16_t color, int x, int w,
                            int y)
{
    panel_draw_text(x + (w - panel_text_width(text, font)) / 2, y, text, font, color);
}
