// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/display_priv.h"
#include "core/text.h"
#include "components/header.h"
#include "components/label.h"
#include "components/list.h"
#include "components/pin_entry.h"
#include "components/softkeys.h"
#include "bitcoin/bitcoin_core.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Factory reset. Both wipes stay in this partition.
// The config wipe removes the ITS record and applies the defaults at once, with no restart.
// The wallet wipe needs the PIN.

#define TITLE "Factory reset"
#define TEXT_X 12
#define TEXT_W 216
#define TEXT_Y 44

enum option {
    OPT_CONFIG,
    OPT_WALLET,
    OPT_COUNT,
};

enum phase {
    PHASE_LIST,
    PHASE_CONFIRM,
    PHASE_PIN,
    PHASE_WIPE,
    PHASE_MSG,
};

static const char *const labels[OPT_COUNT] = {"Wipe configuration", "Wipe wallet"};

static const char *const warnings[OPT_COUNT] = {
    "Removes the theme and the other settings. The wallet stays.",
    "Removes the wallet from this device. Only the backup words can restore it.",
};

static const char *const unreadable_warning =
    "This app cannot read the stored wallet. A newer app may. Wiping removes it. Only the "
    "backup words can restore it.";

static enum phase phase;
static uint8_t sel;
static bool pending;
static bool wiped;
// The record is in a format this app cannot read.
// Its wipe asks no PIN, because none can be checked.
static bool unreadable;
static const char *msg;
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
    if (attempts == 1) {
        text_add(note, sizeof(note), &len, "last try, then wipe");
        note_color = COL_ALERT;
        return;
    }
    text_add(note, sizeof(note), &len, prefix);
    text_add_u32(note, sizeof(note), &len, attempts);
    text_add(note, sizeof(note), &len, " tries left");
}

static void draw(void)
{
    panel_clear(COL_BG);
    if (phase == PHASE_PIN) {
        pin_entry_draw();
        return;
    }
    header_draw(phase == PHASE_LIST ? TITLE : labels[sel], &font_16, COL_SURFACE, COL_MUTE);
    switch (phase) {
    case PHASE_LIST:
        list_draw(labels, OPT_COUNT, sel);
        softkeys_set("back", "next", "open");
        break;
    case PHASE_CONFIRM:
        panel_draw_text_wrapped(TEXT_X, TEXT_Y, TEXT_W,
                                sel == OPT_WALLET && unreadable ? unreadable_warning
                                                                : warnings[sel],
                                &font_16, COL_INK);
        softkeys_set("back", NULL, "wipe");
        break;
    case PHASE_WIPE:
    case PHASE_MSG:
        label_draw(msg, &font_20, COL_INK, LABEL_CENTER, 0, 0);
        softkeys_set(pending || wiped ? NULL : "back", NULL, pending ? NULL : "ok");
        break;
    case PHASE_PIN:
        break;
    }
}

static void show(enum phase p)
{
    phase = p;
    draw();
}

static void show_msg(const char *text)
{
    msg = text;
    show(PHASE_MSG);
}

static void start_pin(const char *prefix)
{
    set_note(prefix);
    pin_entry_start(labels[OPT_WALLET], note, note_color);
    show(PHASE_PIN);
}

static void pin_step(enum pin_entry_step s)
{
    if (s == PIN_ENTRY_CANCEL) {
        show(PHASE_CONFIRM);
        return;
    }
    if (s == PIN_ENTRY_DONE) {
        pending = true;
        msg = "wiping...";
        show(PHASE_WIPE);
        return;
    }
    draw();
}

// The last wrong PIN also removes the record, so the status tells a retry apart from a wipe.
static void wipe_done(psa_status_t status)
{
    uint32_t state = BITCOIN_STATUS_NONE;
    uint32_t attempts = BITCOIN_ATTEMPTS_NA;

    if (status == PSA_SUCCESS ||
        (bitcoin_core_status(bitcoin_core_session_production(), &state, &attempts) == PSA_SUCCESS &&
         state == BITCOIN_STATUS_NONE)) {
        wiped = true;
        show_msg("wallet wiped");
    } else if (status == PSA_ERROR_INVALID_SIGNATURE) {
        start_pin("wrong PIN, ");
    } else if (status == PSA_ERROR_DOES_NOT_EXIST) {
        show_msg("no stored wallet");
    } else {
        show_msg("wipe failed");
    }
}

// After a wipe the status screen goes on to wallet setup.
static void leave(void)
{
    display_show(wiped ? &status_screen : &menu_screen, NULL);
}

// No PIN for a wallet that is not there.
// After a wipe the menu is open only on a temporary wallet.
static void open_option(void)
{
    bool exists = false;
    psa_status_t status;

    unreadable = false;
    if (sel == OPT_CONFIG) {
        show(PHASE_CONFIRM);
        return;
    }
    status = bitcoin_core_stored(bitcoin_core_session_production(), &exists);
    if (status == PSA_ERROR_DATA_INVALID) {
        unreadable = true;
        show(PHASE_CONFIRM);
    } else if (status != PSA_SUCCESS) {
        show_msg("cannot read the wallet");
    } else if (!exists) {
        show_msg("no stored wallet");
    } else {
        show(PHASE_CONFIRM);
    }
}

static void confirm(void)
{
    if (sel == OPT_WALLET && unreadable) {
        pending = true;
        msg = "wiping...";
        show(PHASE_WIPE);
    } else if (sel == OPT_WALLET) {
        start_pin("");
    } else {
        show_msg(display_config_wipe() ? "configuration wiped" : "wipe failed");
    }
}

static void reset_del(void)
{
    switch (phase) {
    case PHASE_LIST:
        leave();
        break;
    case PHASE_CONFIRM:
        show(PHASE_LIST);
        break;
    case PHASE_PIN:
        pin_step(pin_entry_del());
        break;
    case PHASE_MSG:
        if (wiped) {
            leave();
        } else {
            show(PHASE_LIST);
        }
        break;
    case PHASE_WIPE:
        break;
    }
}

static void reset_next(void)
{
    if (phase == PHASE_LIST) {
        sel = (sel + 1) % OPT_COUNT;
        draw();
    } else if (phase == PHASE_PIN) {
        pin_step(pin_entry_next());
    }
}

static void reset_ok(void)
{
    switch (phase) {
    case PHASE_LIST:
        open_option();
        break;
    case PHASE_CONFIRM:
        confirm();
        break;
    case PHASE_PIN:
        pin_step(pin_entry_ok());
        break;
    case PHASE_MSG:
        leave();
        break;
    case PHASE_WIPE:
        break;
    }
}

// The wipe runs one tick later,
// so the "wiping..." frame is on the panel before PBKDF2 blocks the thread.
static void reset_tick(void)
{
    psa_status_t status;

    if (phase != PHASE_WIPE || !pending) {
        return;
    }
    pending = false;
    if (unreadable) {
        status = bitcoin_core_discard_unreadable(bitcoin_core_session_production());
    } else {
        status = bitcoin_core_destroy(bitcoin_core_session_production(), pin_entry_pin());
    }
    pin_entry_wipe();
    wipe_done(status);
}

static void reset_enter(void *arg)
{
    (void)arg;

    pending = false;
    wiped = false;
    unreadable = false;
    sel = OPT_CONFIG;
    show(PHASE_LIST);
}

// The PIN must not stay in RAM after the screen is gone.
static void reset_exit(void)
{
    pin_entry_wipe();
}

const display_screen_ops_t reset_screen = {
    .enter = reset_enter,
    .exit = reset_exit,
    .on_del = reset_del,
    .on_next = reset_next,
    .on_ok = reset_ok,
    .tick = reset_tick,
};
