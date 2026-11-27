// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "display/display.h"
#include "core/config.h"
#include "drivers/panel.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint16_t bg, surface, select, ink, mute, good, alert, accent, on_accent;
} theme_t;

// The active palette. The COL_* macros read it, so a switch shows on the next frame.
extern const theme_t *display_theme;

#define COL_BG (display_theme->bg)
#define COL_SURFACE (display_theme->surface)
#define COL_SELECT (display_theme->select)
#define COL_INK (display_theme->ink)
#define COL_MUTE (display_theme->mute)
#define COL_GOOD (display_theme->good)
#define COL_ALERT (display_theme->alert)
// The accent means money leaves. Only the review screen uses it, so the user learns what it means.
#define COL_ACCENT (display_theme->accent)
#define COL_ON_ACCENT (display_theme->on_accent)

#define TICK_MS 20

// One screen. Every member may be NULL.
// Each draw is a whole frame: panel_clear(), then every element.
// The coordinator flushes once per tick.
typedef struct {
    void (*enter)(void *arg);
    void (*exit)(void);
    void (*on_del)(void);
    void (*on_next)(void);
    void (*on_ok)(void);
    void (*tick)(void);
} display_screen_ops_t;

// Switches to `ops` once the current callback has returned. Safe from any screen callback.
void display_show(const display_screen_ops_t *ops, void *arg);

// Full backlight, and the idle count starts again.
void display_wake(void);

// Makes theme `i` the live one. False and no change for an index past the table.
bool theme_set(uint32_t i);

uint32_t theme_get(void);
uint32_t theme_count(void);

// The config record as ITS holds it. Change a copy and give it to display_config_save().
const config_t *display_config(void);

// Writes the whole record to ITS, only when it differs from the saved one.
// On a failure the saved record stays as it was.
void display_config_save(const config_t *c);

// Removes the record and applies the defaults live. False when ITS fails.
bool display_config_wipe(void);

// Closes the open production wallet and shows the status screen.
void display_lock(void);

extern const display_screen_ops_t status_screen;
extern const display_screen_ops_t review_screen;
extern const display_screen_ops_t menu_screen;
extern const display_screen_ops_t temp_wallet_screen;
extern const display_screen_ops_t wallet_setup_screen;
extern const display_screen_ops_t unlock_screen;
extern const display_screen_ops_t settings_screen;
extern const display_screen_ops_t files_screen;
extern const display_screen_ops_t sign_job_screen;
extern const display_screen_ops_t firmware_screen;
extern const display_screen_ops_t export_screen;
extern const display_screen_ops_t receive_screen;
extern const display_screen_ops_t reset_screen;

// True when a transaction waits for the user, so the review screen has one to show.
bool review_tx_waiting(void);

// Opens the main menu at its first item. display_show(&menu_screen) goes back to the open level.
void menu_show_main(void);
