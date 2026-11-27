// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/display_priv.h"
#include "components/header.h"
#include "components/label.h"
#include "components/passphrase_entry.h"
#include "components/pin_entry.h"
#include "components/softkeys.h"
#include "bitcoin/bitcoin_core.h"
#include "core/text.h"
#include <stdbool.h>
#include <stddef.h>

// PIN -> passphrase question -> optional passphrase -> open the stored wallet.

#define TITLE "Unlock"

enum phase {
    PHASE_PIN,
    PHASE_PASS,
    PHASE_OPEN,
    PHASE_MSG,
};

static enum phase phase;
static const char *msg;
static bool pending;
static char note[32];
static uint16_t note_color;

// The tries left come from PS, so the note is never a guess.
static void set_note(const char *prefix)
{
    uint32_t state = BITCOIN_STATUS_NONE;
    uint32_t attempts = BITCOIN_ATTEMPTS_NA;
    size_t len = 0;

    note[0] = '\0';
    note_color = COL_MUTE;
    if (bitcoin_core_status(bitcoin_core_session_production(), &state, &attempts) != PSA_SUCCESS ||
        attempts == BITCOIN_ATTEMPTS_NA) {
        return;
    }
    // The red line says enough, and with the prefix it does not fit the panel.
    if (attempts == 1) {
        text_add(note, sizeof(note), &len, "last try, then wipe");
        note_color = COL_ALERT;
        return;
    }
    text_add(note, sizeof(note), &len, prefix);
    text_add_u32(note, sizeof(note), &len, attempts);
    text_add(note, sizeof(note), &len, " tries left");
}

static void start_pin(const char *prefix)
{
    set_note(prefix);
    phase = PHASE_PIN;
    pin_entry_start(TITLE, note, note_color);
}

static void draw_msg(void)
{
    header_draw(TITLE, &font_16, COL_SURFACE, COL_MUTE);
    label_draw(msg, &font_20, COL_INK, LABEL_CENTER, 0, 0);
    softkeys_set(pending ? NULL : "back", NULL, pending ? NULL : "ok");
}

static void draw(void)
{
    panel_clear(COL_BG);
    switch (phase) {
    case PHASE_PIN:
        pin_entry_draw();
        break;
    case PHASE_PASS:
        passphrase_entry_draw();
        break;
    case PHASE_OPEN:
    case PHASE_MSG:
        draw_msg();
        break;
    }
}

// exit() wipes the PIN and the passphrase.
static void leave(void)
{
    display_show(&status_screen, NULL);
}

static void show_msg(const char *text)
{
    phase = PHASE_MSG;
    msg = text;
    draw();
}

static void pin_step(enum pin_entry_step s)
{
    if (s == PIN_ENTRY_CANCEL) {
        leave();
        return;
    }
    if (s == PIN_ENTRY_DONE) {
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
        start_pin("");
    } else if (s == PASSPHRASE_ENTRY_DONE) {
        phase = PHASE_OPEN;
        pending = true;
        msg = "opening...";
    }
    draw();
}

// A wrong PIN is INVALID_SIGNATURE.
// The last wrong PIN also removes the record, so the status tells a retry apart from a wipe.
static void open_failed(psa_status_t status)
{
    uint32_t state = BITCOIN_STATUS_NONE;
    uint32_t attempts = BITCOIN_ATTEMPTS_NA;

    if (bitcoin_core_status(bitcoin_core_session_production(), &state, &attempts) == PSA_SUCCESS &&
        state == BITCOIN_STATUS_NONE) {
        show_msg("wallet wiped");
        return;
    }
    if (status == PSA_ERROR_INVALID_SIGNATURE) {
        start_pin("wrong PIN, ");
        draw();
        return;
    }
    show_msg("unlock failed");
}

static void unlock_tick(void)
{
    wallet_session_t *w = bitcoin_core_session_production();
    psa_status_t status;

    if (phase != PHASE_OPEN || !pending) {
        return;
    }
    pending = false;

    status = bitcoin_core_open(w, pin_entry_pin(), passphrase_entered());
    pin_entry_wipe();
    passphrase_clear();
    if (status == PSA_SUCCESS) {
        leave();
        return;
    }
    open_failed(status);
}

static void msg_back(void)
{
    if (!pending) {
        leave();
    }
}

static void unlock_del(void)
{
    switch (phase) {
    case PHASE_PIN:
        pin_step(pin_entry_del());
        break;
    case PHASE_PASS:
        pass_step(passphrase_entry_del());
        break;
    case PHASE_OPEN:
    case PHASE_MSG:
        msg_back();
        break;
    }
}

static void unlock_next(void)
{
    switch (phase) {
    case PHASE_PIN:
        pin_step(pin_entry_next());
        break;
    case PHASE_PASS:
        pass_step(passphrase_entry_next());
        break;
    case PHASE_OPEN:
    case PHASE_MSG:
        break;
    }
}

static void unlock_ok(void)
{
    switch (phase) {
    case PHASE_PIN:
        pin_step(pin_entry_ok());
        break;
    case PHASE_PASS:
        pass_step(passphrase_entry_ok());
        break;
    case PHASE_OPEN:
    case PHASE_MSG:
        msg_back();
        break;
    }
}

static void unlock_enter(void *arg)
{
    (void)arg;

    pending = false;
    start_pin("");
    draw();
}

// The PIN and the passphrase must not stay in RAM after the screen is gone.
static void unlock_exit(void)
{
    pin_entry_wipe();
    passphrase_clear();
}

const display_screen_ops_t unlock_screen = {
    .enter = unlock_enter,
    .exit = unlock_exit,
    .on_del = unlock_del,
    .on_next = unlock_next,
    .on_ok = unlock_ok,
    .tick = unlock_tick,
};
