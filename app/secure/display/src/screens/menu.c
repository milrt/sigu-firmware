// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/display_priv.h"
#include "components/header.h"
#include "components/list.h"
#include "components/softkeys.h"
#include <stddef.h>
#include <stdint.h>

// The back key always goes back, so the list has no "Back" row.
// The selection is kept, so returning from a screen lands on the same item.

typedef struct {
    const char *label;
    const display_screen_ops_t *screen;
    void (*action)(void);
} menu_item_t;

static const menu_item_t items[] = {
    {.label = "Sign from card", .screen = &files_screen},
    {.label = "Receive", .screen = &receive_screen},
    {.label = "Export wallet", .screen = &export_screen},
    {.label = "Temp wallet", .screen = &temp_wallet_screen},
    {.label = "Close wallet", .action = display_lock},
    {.label = "Settings", .screen = &settings_screen},
    {.label = "Firmware", .screen = &firmware_screen},
    {.label = "Factory reset", .screen = &reset_screen},
};

#define N_ITEMS (sizeof(items) / sizeof(items[0]))

static uint8_t sel;

static void draw(void)
{
    const char *labels[N_ITEMS];

    for (uint8_t i = 0; i < N_ITEMS; i++) {
        labels[i] = items[i].label;
    }

    panel_clear(COL_BG);
    header_draw("Menu", &font_16, COL_SURFACE, COL_MUTE);
    list_draw(labels, N_ITEMS, sel);
    softkeys_set("back", "next", "open");
}

void menu_show_main(void)
{
    sel = 0;
    display_show(&menu_screen, NULL);
}

static void menu_enter(void *arg)
{
    (void)arg;

    draw();
}

static void menu_del(void)
{
    display_show(&status_screen, NULL);
}

static void menu_next(void)
{
    sel = (sel + 1) % N_ITEMS;
    draw();
}

static void menu_ok(void)
{
    const menu_item_t *it = &items[sel];

    if (it->screen) {
        display_show(it->screen, NULL);
    } else {
        it->action();
    }
}

const display_screen_ops_t menu_screen = {
    .enter = menu_enter,
    .on_del = menu_del,
    .on_next = menu_next,
    .on_ok = menu_ok,
};
