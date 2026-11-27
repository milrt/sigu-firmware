// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

// Draws a qrcodegen QR full screen and centered, black on white whatever the theme,
// with the quiet zone of 4 modules. Its bits must fit PANEL_MONO_MAX.
void qr_draw(const uint8_t qr[]);
