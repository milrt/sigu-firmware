// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "drivers/panel.h"
#include <stdint.h>

#define HEADER_H 32

// A full-width band of `band` with `title` on it, left aligned. Two ops.
void header_draw(const char *title, const font_t *font, uint16_t band, uint16_t fg);
