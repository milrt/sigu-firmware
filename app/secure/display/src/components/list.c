// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "components/list.h"
#include "core/display_priv.h"
#include <stdbool.h>
#include <stddef.h>

#define TEXT_X 18
#define VALUE_R (PANEL_W - TEXT_X)
#define FILL_X 6
// The 22 px font_20 line sits in the middle of the 26 px row fill.
#define FILL_UP 2
// A 9x5 arrow, centered between FILL_X and TEXT_X and in the row fill.
#define MARK_W 9
#define MARK_H 5
#define MARK_X (FILL_X + (TEXT_X - FILL_X - MARK_W) / 2)
#define MARK_DY ((LIST_STEP - MARK_H) / 2 - FILL_UP)

static const uint8_t mark_up[] = {0x10, 0x70, 0xF0, 0xF1, 0xF7, 0x1F};
static const uint8_t mark_down[] = {0xFF, 0xFD, 0xF1, 0xC1, 0x01, 0x01};

static void draw_row(int r, const char *label, const char *value, bool on)
{
    int y = LIST_Y + r * LIST_STEP;
    uint16_t fg = on ? COL_INK : COL_MUTE;

    if (on) {
        panel_fill_rect(FILL_X, y - FILL_UP, PANEL_W - 2 * FILL_X, LIST_STEP, COL_SELECT);
    }
    panel_draw_text(TEXT_X, y, label, &font_20, fg);
    if (value) {
        panel_draw_text(VALUE_R - panel_text_width(value, &font_20), y, value, &font_20, fg);
    }
}

static void draw_mark(int r, const uint8_t *bits, bool on)
{
    panel_draw_mono(MARK_X, LIST_Y + r * LIST_STEP + MARK_DY, bits, MARK_W, MARK_H, 1,
                    on ? COL_INK : COL_MUTE);
}

void list_draw(const char *const *labels, uint8_t n, uint8_t sel)
{
    list_draw_values(labels, NULL, n, sel);
}

void list_draw_values(const char *const *labels, const char *const *values, uint8_t n, uint8_t sel)
{
    uint8_t first = sel < LIST_ROWS ? 0 : sel - LIST_ROWS + 1;

    for (uint8_t i = first; i < n && i < first + LIST_ROWS; i++) {
        draw_row(i - first, labels[i], values ? values[i] : NULL, i == sel);
    }
    if (first > 0) {
        draw_mark(0, mark_up, first == sel);
    }
    if (first + LIST_ROWS < n) {
        draw_mark(LIST_ROWS - 1, mark_down, first + LIST_ROWS - 1 == sel);
    }
}
