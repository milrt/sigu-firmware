// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "components/wheel.h"
#include "components/label.h"
#include "core/display_priv.h"
#include <stdbool.h>

// Montserrat 20 'W' and the check mark are about 20 px wide.
#define WHEEL_CELL 24
// The tile holds the 22 px line of the wheel with two rows to spare on each side.
#define TILE_UP 2
#define TILE_H 26
// Five cells around the current one, two on each side.
#define WHEEL_SIDE 2
#define WHEEL_SPAN (2 * WHEEL_SIDE + 1)

// Indices into choices[] for the window, left to right.
// With fewer than five choices the window would repeat cells, so then each choice shows once.
static uint8_t wheel_items(uint8_t n, uint8_t sel, uint8_t *out)
{
    uint8_t k = 0;

    if (n < WHEEL_SPAN) {
        for (uint8_t i = 0; i < n; i++) {
            out[k++] = i;
        }
        return k;
    }
    for (int d = -WHEEL_SIDE; d <= WHEEL_SIDE; d++) {
        out[k++] = (sel + n + d) % n;
    }
    return k;
}

// A space glyph is blank, so space is drawn as a small open box.
static void draw_space(int x, uint16_t color)
{
    int y = WHEEL_Y + 14;

    panel_fill_rect(x + 5, y, 2, 5, color);
    panel_fill_rect(x + 5, y + 4, 14, 2, color);
    panel_fill_rect(x + 17, y, 2, 5, color);
}

static void draw_mode(int x, uint16_t color)
{
    panel_fill_rect(x + 5, WHEEL_Y + 8, 14, 2, color);
    panel_fill_rect(x + 5, WHEEL_Y + 14, 14, 2, color);
}

// The panel records at most 40 ops per frame, and past that it paints the whole screen red.
// Each rect is one op, so these glyphs use only a few rects.
// The worst windows are "z ◄ ► ← ✕" and "◄ ► ← ✕ ✓", 16 ops each,
// and the rest of the passphrase frame takes 14.

// Solid triangles of three columns, 4, 8 and 12 px high.
static void draw_left(int x, uint16_t color)
{
    panel_fill_rect(x + 7, WHEEL_Y + 10, 3, 4, color);
    panel_fill_rect(x + 10, WHEEL_Y + 8, 3, 8, color);
    panel_fill_rect(x + 13, WHEEL_Y + 6, 3, 12, color);
}

static void draw_right(int x, uint16_t color)
{
    panel_fill_rect(x + 8, WHEEL_Y + 6, 3, 12, color);
    panel_fill_rect(x + 11, WHEEL_Y + 8, 3, 8, color);
    panel_fill_rect(x + 14, WHEEL_Y + 10, 3, 4, color);
}

// A left arrow: a shaft, and a head of three columns that grow toward it.
static void draw_del(int x, uint16_t color)
{
    panel_fill_rect(x + 8, WHEEL_Y + 11, 12, 2, color);
    panel_fill_rect(x + 4, WHEEL_Y + 11, 2, 2, color);
    panel_fill_rect(x + 6, WHEEL_Y + 9, 2, 6, color);
    panel_fill_rect(x + 8, WHEEL_Y + 7, 2, 10, color);
}

// A cross of five squares that touch at their corners.
static void draw_cancel(int x, uint16_t color)
{
    int x0 = x + 6;
    int y0 = WHEEL_Y + 6;

    panel_fill_rect(x0, y0, 4, 4, color);
    panel_fill_rect(x0 + 8, y0, 4, 4, color);
    panel_fill_rect(x0 + 4, y0 + 4, 4, 4, color);
    panel_fill_rect(x0, y0 + 8, 4, 4, color);
    panel_fill_rect(x0 + 8, y0 + 8, 4, 4, color);
}

static void draw_cell(char c, int x, uint16_t color)
{
    char text[2] = {c, '\0'};

    if (c == ' ') {
        draw_space(x, color);
    } else if (c == WHEEL_MODE) {
        draw_mode(x, color);
    } else if (c == WHEEL_DEL) {
        draw_del(x, color);
    } else if (c == WHEEL_CANCEL) {
        draw_cancel(x, color);
    } else if (c == WHEEL_LEFT) {
        draw_left(x, color);
    } else if (c == WHEEL_RIGHT) {
        draw_right(x, color);
    } else {
        label_draw_centered_in(c ? text : PANEL_SYMBOL_OK, &font_20, color, x, WHEEL_CELL, WHEEL_Y);
    }
}

// Each cell is centered on its own. One string would lay out proportionally,
// so the row would move with every letter.
// With five or more choices, the selected cell and its tile always sit in the center.
void wheel_draw(const char *choices, uint8_t n, uint8_t sel)
{
    uint8_t items[WHEEL_SPAN];
    uint8_t k = wheel_items(n, sel, items);
    int x0 = PANEL_W / 2 - k * WHEEL_CELL / 2;

    for (uint8_t i = 0; i < k; i++) {
        bool on = items[i] == sel;
        int x = x0 + i * WHEEL_CELL;

        if (on) {
            panel_fill_rect(x, WHEEL_Y - TILE_UP, WHEEL_CELL, TILE_H, COL_SELECT);
        }
        draw_cell(choices[items[i]], x, on ? COL_INK : COL_MUTE);
    }
}
