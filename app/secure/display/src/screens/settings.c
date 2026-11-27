// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "display/display.h"
#include "core/display_priv.h"
#include "core/text.h"
#include "components/header.h"
#include "components/list.h"
#include "components/softkeys.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Theme and Save. A new theme shows at once.
// Only Save keeps it, and the back key restores the theme the screen opened with.
// The Theme row shows the index plus one.

#define ROW_THEME 0
#define ROW_SAVE 1
#define ROWS 2
#define LABEL_MAX 32

static uint32_t theme;
static uint32_t prev_theme;
static uint8_t sel;
static bool editing;

static void draw(void)
{
    char text[LABEL_MAX];
    const char *labels[ROWS] = {"Theme", "Save"};
    const char *values[ROWS] = {text, NULL};
    size_t len = 0;
    bool open = editing && sel == ROW_THEME;

    text[0] = '\0';
    if (open) {
        text_add(text, LABEL_MAX, &len, "< ");
    }
    text_add_u32(text, LABEL_MAX, &len, theme + 1);
    if (open) {
        text_add(text, LABEL_MAX, &len, " >");
    }

    panel_clear(COL_BG);
    header_draw("Settings", &font_16, COL_SURFACE, COL_MUTE);
    list_draw_values(labels, values, ROWS, sel);
    if (editing) {
        softkeys_set("done", "-", "+");
    } else {
        softkeys_set("back", "next", sel == ROW_SAVE ? "save" : "edit");
    }
}

static void edit(bool up)
{
    uint32_t n = theme_count();

    theme = up ? (theme + 1) % n : (theme + n - 1) % n;
    theme_set(theme);
    draw();
}

static void settings_enter(void *arg)
{
    (void)arg;

    theme = theme_get();
    prev_theme = theme;
    sel = 0;
    editing = false;
    draw();
}

static void settings_del(void)
{
    if (editing) {
        editing = false;
        draw();
        return;
    }
    theme_set(prev_theme);
    display_show(&menu_screen, NULL);
}

static void settings_next(void)
{
    if (editing) {
        edit(false);
        return;
    }
    sel = (sel + 1) % ROWS;
    draw();
}

static void settings_ok(void)
{
    if (editing) {
        edit(true);
        return;
    }
    if (sel == ROW_SAVE) {
        config_t c = *display_config();

        c.theme = theme;
        display_config_save(&c);
        display_show(&menu_screen, NULL);
        return;
    }
    editing = true;
    draw();
}

const display_screen_ops_t settings_screen = {
    .enter = settings_enter,
    .on_del = settings_del,
    .on_next = settings_next,
    .on_ok = settings_ok,
};
