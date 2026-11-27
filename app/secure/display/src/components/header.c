// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "components/header.h"

#define TEXT_X 12

void header_draw(const char *title, const font_t *font, uint16_t band, uint16_t fg)
{
    panel_fill_rect(0, 0, PANEL_W, HEADER_H, band);
    panel_draw_text(TEXT_X, (HEADER_H - font->line_height) / 2, title, font, fg);
}
