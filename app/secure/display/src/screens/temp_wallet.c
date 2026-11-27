// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/display_priv.h"
#include "components/header.h"
#include "components/label.h"
#include "components/passphrase_entry.h"
#include "components/seed_entry.h"
#include "components/softkeys.h"
#include "bitcoin/bitcoin_core.h"
#include <stdbool.h>
#include <stddef.h>

// Seed entry -> passphrase question -> optional passphrase -> open. The wallet lives only in RAM.
// Menu "Close wallet", the idle lock or a power off closes it.

#define TITLE "Temporary wallet"

enum phase {
    PHASE_SEED,
    PHASE_PASS,
    PHASE_OPEN,
};

static enum phase phase;
static const char *msg;
static bool pending;

static void draw_open(void)
{
    header_draw(TITLE, &font_16, COL_SURFACE, COL_MUTE);
    label_draw(msg, &font_20, COL_INK, LABEL_CENTER, 0, 0);
    softkeys_set(pending ? NULL : "back", NULL, pending ? NULL : "ok");
}

static void draw(void)
{
    panel_clear(COL_BG);
    switch (phase) {
    case PHASE_SEED:
        seed_entry_draw();
        break;
    case PHASE_PASS:
        passphrase_entry_draw();
        break;
    case PHASE_OPEN:
        draw_open();
        break;
    }
}

// exit() wipes the words and the passphrase.
static void leave(void)
{
    display_show(&menu_screen, NULL);
}

static void seed_step(enum seed_entry_step s)
{
    if (s == SEED_ENTRY_CANCEL) {
        leave();
        return;
    }
    if (s == SEED_ENTRY_DONE) {
        phase = PHASE_PASS;
        passphrase_entry_start(TITLE);
    }
    draw();
}

// The open runs one tick later,
// so the "opening..." frame is on the panel before PBKDF2 blocks the thread.
static void pass_step(enum passphrase_entry_step s)
{
    if (s == PASSPHRASE_ENTRY_CANCEL) {
        leave();
        return;
    }
    if (s == PASSPHRASE_ENTRY_DONE) {
        phase = PHASE_OPEN;
        pending = true;
        msg = "opening...";
    }
    draw();
}

// A new wallet replaces the open one.
// It is closed only here, so a cancel on the way keeps the old wallet.
static void temp_tick(void)
{
    wallet_session_t *w = bitcoin_core_session_production();

    if (phase != PHASE_OPEN || !pending) {
        return;
    }
    pending = false;

    bitcoin_core_close(w); // BAD_STATE only means no wallet was open
    if (bitcoin_core_open_temporary(w, seed_entry_mnemonic(), passphrase_entered()) ==
        PSA_SUCCESS) {
        display_show(&status_screen, NULL);
        return;
    }

    msg = "open failed";
    draw();
}

static void open_back(void)
{
    if (!pending) {
        leave();
    }
}

static void temp_del(void)
{
    switch (phase) {
    case PHASE_SEED:
        seed_step(seed_entry_del());
        break;
    case PHASE_PASS:
        pass_step(passphrase_entry_del());
        break;
    case PHASE_OPEN:
        open_back();
        break;
    }
}

static void temp_next(void)
{
    switch (phase) {
    case PHASE_SEED:
        seed_step(seed_entry_next());
        break;
    case PHASE_PASS:
        pass_step(passphrase_entry_next());
        break;
    case PHASE_OPEN:
        break;
    }
}

static void temp_ok(void)
{
    switch (phase) {
    case PHASE_SEED:
        seed_step(seed_entry_ok());
        break;
    case PHASE_PASS:
        pass_step(passphrase_entry_ok());
        break;
    case PHASE_OPEN:
        open_back();
        break;
    }
}

static void temp_enter(void *arg)
{
    (void)arg;

    phase = PHASE_SEED;
    pending = false;
    seed_entry_start("Restore");
    draw();
}

// The words and the passphrase must not stay in RAM after the screen is gone.
static void temp_exit(void)
{
    seed_entry_clear();
    passphrase_clear();
}

const display_screen_ops_t temp_wallet_screen = {
    .enter = temp_enter,
    .exit = temp_exit,
    .on_del = temp_del,
    .on_next = temp_next,
    .on_ok = temp_ok,
    .tick = temp_tick,
};
