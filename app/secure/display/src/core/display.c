// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "display/display.h"
#include "core/config.h"
#include "core/display_priv.h"
#include "bitcoin/bitcoin_core.h"
#include "drivers/input.h"
#include "drivers/panel.h"
#include "drivers/tick.h"
#include "tfm_log.h"
#include <stdbool.h>
#include <stddef.h>

// The screen coordinator:
// it switches screens, routes the keys, dims the light and locks the wallet.
// The screens call bitcoin_core_* directly.

// 5 min with no key press. Only a key counts: NS is not trusted to say a user is there.
#define LOCK_TICKS (5 * 60 * 1000 / TICK_MS)
// Backlight percent.
#define LIGHT_ON 100
#define LIGHT_DIM 10
// Seconds with no key press.
#define DIM_AFTER 10
#define DIM_TICKS (DIM_AFTER * 1000 / TICK_MS)

static const display_screen_ops_t *cur;
static const display_screen_ops_t *pending;
static void *pending_arg;
static int idle;
static int lock_idle;
// The record as ITS holds it, and the defaults the panel started with.
static config_t saved;
static config_t defaults;

void display_wake(void)
{
    idle = 0;
    panel_backlight(LIGHT_ON);
}

void display_show(const display_screen_ops_t *ops, void *arg)
{
    pending = ops;
    pending_arg = arg;
}

// A screen may ask for a switch from its own enter(), so this loops until no switch is left.
// Each pass clears what the last one drew.
static void apply_switch(void)
{
    while (pending) {
        const display_screen_ops_t *next = pending;
        void *arg = pending_arg;

        pending = NULL;
        if (cur && cur->exit) {
            cur->exit();
        }
        panel_clear(COL_BG);

        cur = next;
        if (cur->enter) {
            cur->enter(arg);
        }
    }
}

// Two keys can land in one tick.
// After the first one asked for a switch, the second must not reach the old screen.
static void route(void (*handler)(void))
{
    if (handler && !pending) {
        handler();
    }
}

static void route_keys(uint32_t keys)
{
    if (keys & INPUT_DEL) {
        route(cur->on_del);
    }
    if (keys & INPUT_NEXT) {
        route(cur->on_next);
    }
    if (keys & INPUT_OK) {
        route(cur->on_ok);
    }
}

// Adds `n` ticks with no key to `count`, up to `limit`. True once, on the tick after the limit.
// `n` is the time since the last tick: NS can keep this thread in IPC calls,
// and the idle time must follow the clock, not the ticks that ran.
static bool idle_for(int *count, bool any, int n, int limit)
{
    if (any) {
        *count = 0;
    } else if (*count < limit) {
        *count = *count + n < limit ? *count + n : limit;
    } else if (*count == limit) {
        (*count)++;
        return true;
    }
    return false;
}

// The switch runs the old screen's exit(), so a half-typed PIN, seed or passphrase is wiped too.
void display_lock(void)
{
    bitcoin_core_close(bitcoin_core_session_production()); // BAD_STATE: nothing was open
    display_show(&status_screen, NULL);
}

const config_t *display_config(void)
{
    return &saved;
}

static bool same(const config_t *a, const config_t *b)
{
    return a->theme == b->theme && a->fw_failed_seen == b->fw_failed_seen;
}

void display_config_save(const config_t *c)
{
    if (same(c, &saved)) {
        return;
    }
    if (!config_write(c)) {
        ERROR("cannot write the panel config\n");
        return;
    }
    saved = *c;
}

bool display_config_wipe(void)
{
    if (!config_remove()) {
        ERROR("cannot remove the panel config\n");
        return false;
    }
    saved = defaults;
    theme_set(saved.theme);
    return true;
}

// Any problem with the record gives the defaults for all of it, and never stops the boot.
// theme_set() changes nothing when it fails, so the theme stays the default.
static void load_config(void)
{
    defaults.theme = theme_get();
    if (!config_read(&saved) || !theme_set(saved.theme)) {
        saved = defaults;
    }
}

// The config is read before the first frame, so the light comes on with the stored theme.
void display_init(void)
{
    panel_init();
    input_init();
    load_config();

    display_show(&status_screen, NULL);
    apply_switch();
    panel_flush();
    display_wake();

    tick_start(TICK_MS);
}

void display_tick(void)
{
    uint32_t passed = tick_ack();
    int n = passed < LOCK_TICKS ? (int)passed : LOCK_TICKS;
    uint32_t keys = input_poll();

    if (keys) {
        route_keys(keys);
        apply_switch();
        display_wake();
    }
    if (idle_for(&idle, keys != 0, n, DIM_TICKS)) {
        panel_backlight(LIGHT_DIM);
    }
    if (idle_for(&lock_idle, keys != 0, n, LOCK_TICKS)) {
        display_lock();
        apply_switch();
    }

    if (cur->tick) {
        cur->tick();
        apply_switch();
    }

    panel_flush();
}
