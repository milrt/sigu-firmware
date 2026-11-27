// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "components/softkeys.h"
#include "components/label.h"
#include "core/display_priv.h"
#include <stdbool.h>

#define BAR_Y (PANEL_H - 1 - SOFTKEYS_HEIGHT)
#define EDGE_X 12
#define LABEL_Y (-10)
#define TILE_PAD 6

// Drawn first, so it sits under the select label.
static void draw_sign_tile(const char *ok)
{
    int w = panel_text_width(ok, &font_20);

    panel_fill_rect(PANEL_W - EDGE_X - w - TILE_PAD, BAR_Y + TILE_PAD, w + 2 * TILE_PAD,
                    PANEL_H - BAR_Y - 2 * TILE_PAD, COL_ACCENT);
}

// The bar names the keys under it.
// The next key is muted because it only moves, and on review it holds the page counter.
static void draw(const char *del, const char *next, const char *ok, bool sign)
{
    panel_fill_rect(0, BAR_Y, PANEL_W, PANEL_H - BAR_Y, COL_SURFACE);
    if (sign && ok) {
        draw_sign_tile(ok);
    }
    label_draw(del ? del : "", &font_20, COL_INK, LABEL_BOTTOM_LEFT, EDGE_X, LABEL_Y);
    label_draw(next ? next : "", &font_20, COL_MUTE, LABEL_BOTTOM_MID, 0, LABEL_Y);
    label_draw(ok ? ok : "", &font_20, sign ? COL_ON_ACCENT : COL_INK, LABEL_BOTTOM_RIGHT, -EDGE_X,
               LABEL_Y);
}

void softkeys_set(const char *del, const char *next, const char *ok)
{
    draw(del, next, ok, false);
}

void softkeys_set_sign(const char *del, const char *next, const char *ok)
{
    draw(del, next, ok, true);
}
