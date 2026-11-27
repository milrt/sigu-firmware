// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/display_priv.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define THEME(bk, sf, sl, ik, mu, gd, al, ac, oa)                                                  \
    {.bg = RGB565(bk),                                                                             \
     .surface = RGB565(sf),                                                                        \
     .select = RGB565(sl),                                                                         \
     .ink = RGB565(ik),                                                                            \
     .mute = RGB565(mu),                                                                           \
     .good = RGB565(gd),                                                                           \
     .alert = RGB565(al),                                                                          \
     .accent = RGB565(ac),                                                                         \
     .on_accent = RGB565(oa)}

// The ITS config record stores the saved theme as an index. Add new themes at the end only.
// The first is the default: black, the highest contrast.
// Then light, for daylight, and the rest by contrast.
static const theme_t themes[] = {
    THEME(0x000000, 0x1A1A1A, 0x333333, 0xFFFFFF, 0xB0B0B0, 0x00E676, 0xFF3B30, 0xFFB000, 0x000000),
    THEME(0xF6F8FA, 0xE7EBF0, 0xD0D7DE, 0x1F2328, 0x656D76, 0x1A7F37, 0xCF222E, 0xBC4C00, 0xFFFFFF),
    THEME(0x1A0B2E, 0x2D1B69, 0x5B2A86, 0xFFFFFF, 0x4DD0E1, 0x00F5A0, 0xFF2E63, 0xFF9F1C, 0x1A0B2E),
    THEME(0x282828, 0x3C3836, 0x504945, 0xEBDBB2, 0xA89984, 0xB8BB26, 0xFB4934, 0xFE8019, 0x282828),
    THEME(0x2E3440, 0x3B4252, 0x4C566A, 0xECEFF4, 0x8F9BB3, 0xA3BE8C, 0xBF616A, 0xD08770, 0x2E3440),
    THEME(0x002B36, 0x073642, 0x0E4B5A, 0xEEE8D5, 0x839496, 0x859900, 0xDC322F, 0xCB4B16, 0xFDF6E3),
};

#define N_THEMES (sizeof(themes) / sizeof(themes[0]))

const theme_t *display_theme = &themes[0];

bool theme_set(uint32_t i)
{
    if (i >= N_THEMES) {
        return false;
    }
    display_theme = &themes[i];
    return true;
}

uint32_t theme_get(void)
{
    return (uint32_t)(display_theme - themes);
}

uint32_t theme_count(void)
{
    return N_THEMES;
}
