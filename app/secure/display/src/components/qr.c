// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "components/qr.h"
#include "core/display_priv.h"
#include "qrcodegen.h"

// The standard asks for a quiet zone of 4 modules on each side.
#define QR_QUIET 4
// Scanners want dark modules on a light background, so the colors do not follow the theme.
#define QR_DARK RGB565(0x000000)
#define QR_LIGHT RGB565(0xFFFFFF)

void qr_draw(const uint8_t qr[])
{
    int size = qrcodegen_getSize(qr);
    int scale = PANEL_W / (size + 2 * QR_QUIET);
    int x0 = (PANEL_W - size * scale) / 2;
    int y0 = (PANEL_H - size * scale) / 2;

    panel_clear(QR_LIGHT);
    panel_draw_mono(x0, y0, qr + 1, size, size, scale, QR_DARK);
}
