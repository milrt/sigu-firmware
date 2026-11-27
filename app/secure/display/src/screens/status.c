// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/display_priv.h"
#include "components/header.h"
#include "components/label.h"
#include "components/softkeys.h"
#include "bitcoin/bitcoin_core.h"
#include "shared/bitcoin_service_defs.h"
#include "shared/tx_records.h"
#include "core/text.h"
#include "files/files.h"
#include <string.h>

// How fast a tx reaches the panel.
// The status word changes mostly on the panel itself, and it is read again on every return here.
// Reading it costs a PS lookup while the wallet is locked, so it is polled far less often.
#define TX_POLL_TICKS 10
#define STATUS_POLL_TICKS 50

#define EDGE_X 12
#define BADGE_PAD 6
#define DOT 6
#define DOT_GAP 8
#define CAPTION_Y 72
#define FP_Y 92
#define READY_Y 136
// Below the header, above the status word and the fingerprint caption.
#define FW_NEWS_Y 42

// Not a BITCOIN_STATUS_*. The select key then opens the menu.
#define STATE_UNKNOWN UINT32_MAX

static char status_word[32];
static char status_note[32];
static uint16_t note_color;
static char fp_text[12];
static int tx_ticks;
static int status_ticks;
// The state on the panel. The select key acts on what the user sees, not on a newer state.
static uint32_t shown_state = STATE_UNKNOWN;

// Short words for a 240 px panel.
// NULL for a value this build does not know, so the caller shows the number, never a guess.
// An open wallet has its own layout, see paint_open().
static const char *status_word_str(uint32_t s)
{
    switch (s) {
    case BITCOIN_STATUS_NONE:
        return "no wallet";
    case BITCOIN_STATUS_LOCKED:
        return "locked";
    case BITCOIN_STATUS_SETUP:
        return "setting up";
    case BITCOIN_STATUS_UNREADABLE:
        return "unreadable";
    default:
        return NULL;
    }
}

static void set_note(uint32_t state, uint32_t attempts)
{
    size_t len = 0;

    status_note[0] = '\0';
    note_color = COL_MUTE;
    if (state == BITCOIN_STATUS_NONE) {
        text_add(status_note, sizeof(status_note), &len, "press OK to set up");
    } else if (state == BITCOIN_STATUS_UNREADABLE) {
        // Maybe a wallet in a newer format. Never offer setup over it.
        text_add(status_note, sizeof(status_note), &len, "update app or reset");
        note_color = COL_ALERT;
    } else if (attempts == 1) {
        text_add(status_note, sizeof(status_note), &len, "last try, then wipe");
        note_color = COL_ALERT;
    } else if (attempts != BITCOIN_ATTEMPTS_NA) {
        text_add_u32(status_note, sizeof(status_note), &len, attempts);
        text_add(status_note, sizeof(status_note), &len, " PIN tries left");
    }
}

// The card as NS last reported it.
static void draw_card(void)
{
    uint32_t card = files_card();
    const char *text = card == BITCOIN_CARD_NONE      ? "no card"
                       : card == BITCOIN_CARD_MOUNTED ? "SD card mounted"
                                                      : "SD card error";

    label_draw(text, &font_16, card == BITCOIN_CARD_ERROR ? COL_ALERT : COL_MUTE, LABEL_BOTTOM_MID,
               0, -SOFTKEYS_HEIGHT - 8);
}

// MCUboot's REVERT stays in slot0's trailer until the next install,
// and NS reports it on every boot.
// The seen bit in the config record shows the line only on the first boot after a rollback,
// for that whole boot. The state is an NS claim.
// Each boot writes the bit at most once each way, so a lying NS cannot wear out ITS.
static bool fw_failed_shown;

void display_fw_state(uint8_t status)
{
    static bool cleared;
    config_t c = *display_config();

    if (status != BITCOIN_FW_FAILED && !cleared) {
        cleared = true;
        c.fw_failed_seen = false;
        display_config_save(&c);
    }
}

static bool show_fw_failed(void)
{
    config_t c = *display_config();

    if (!fw_failed_shown && c.fw_failed_seen) {
        return false;
    }
    if (!fw_failed_shown) {
        fw_failed_shown = true;
        c.fw_failed_seen = true;
        display_config_save(&c);
    }
    return true;
}

// A new app that waits for its confirm, or a failed one MCUboot swapped back.
// NS reads both from MCUboot's trailers.
static void draw_fw_news(void)
{
    uint32_t status = files_fw_status();

    if (status == BITCOIN_FW_FAILED && show_fw_failed()) {
        label_draw("firmware install failed", &font_16, COL_ALERT, LABEL_TOP_MID, 0, FW_NEWS_Y);
    } else if (status == BITCOIN_FW_CONFIRMING) {
        label_draw("Install confirming...", &font_16, COL_MUTE, LABEL_TOP_MID, 0, FW_NEWS_Y);
    }
}

static void paint_word(void)
{
    panel_clear(COL_BG);
    header_draw("sigu", &font_20, COL_SURFACE, COL_INK);
    label_draw(status_word, &font_24, COL_INK, LABEL_CENTER, 0, -8);
    label_draw(status_note, &font_16, note_color, LABEL_CENTER, 0, 26);
    draw_fw_news();
    draw_card();
    if (shown_state == BITCOIN_STATUS_NONE) {
        softkeys_set(NULL, "menu", "set up");
    } else if (shown_state == BITCOIN_STATUS_LOCKED) {
        softkeys_set(NULL, "menu", "unlock");
    } else {
        softkeys_set(NULL, NULL, "menu");
    }
}

// Inverse ink. COL_ALERT would read as an error, and amber belongs to the review.
static void draw_badge(const char *text)
{
    int w = panel_text_width(text, &font_16) + 2 * BADGE_PAD;
    int x = PANEL_W - EDGE_X - w;
    int y = (HEADER_H - font_16.line_height) / 2;

    panel_fill_rect(x, y, w, font_16.line_height, COL_INK);
    panel_draw_text(x + BADGE_PAD, y, text, &font_16, COL_BG);
}

// "xxxx xxxx". The fingerprint lets the user check the seed and the passphrase.
// A typo in either one gives a different wallet, and nothing else on the panel shows it.
static void set_fp_text(void)
{
    uint8_t fp[BITCOIN_FINGERPRINT_SIZE];
    size_t len = 0;

    fp_text[0] = '\0';
    if (bitcoin_core_get_fingerprint(bitcoin_core_session_production(), fp) != PSA_SUCCESS) {
        text_add(fp_text, sizeof(fp_text), &len, "????");
        return;
    }
    text_add_hex(fp_text, sizeof(fp_text), &len, fp, 2);
    text_add(fp_text, sizeof(fp_text), &len, " ");
    text_add_hex(fp_text, sizeof(fp_text), &len, fp + 2, 2);
}

// The dot and the text are centered as one.
static void draw_ready(void)
{
    const char *text = "ready to sign";
    int w = DOT + DOT_GAP + panel_text_width(text, &font_16);
    int x = PANEL_W / 2 - w / 2;

    panel_fill_rect(x, READY_Y + (font_16.line_height - DOT) / 2, DOT, DOT, COL_GOOD);
    panel_draw_text(x + DOT + DOT_GAP, READY_Y, text, &font_16, COL_MUTE);
}

static void paint_open(void)
{
    set_fp_text();

    panel_clear(COL_BG);
    header_draw("sigu", &font_20, COL_SURFACE, COL_INK);
    if (bitcoin_core_is_temporary(bitcoin_core_session_production())) {
        draw_badge("TEMPORARY");
    }
    label_draw("fingerprint", &font_16, COL_MUTE, LABEL_TOP_MID, 0, CAPTION_Y);
    label_draw(fp_text, &font_24, COL_INK, LABEL_TOP_MID, 0, FP_Y);
    draw_ready();
    draw_fw_news();
    draw_card();
    softkeys_set(NULL, NULL, "menu");
}

static void refresh(void)
{
    uint32_t state = BITCOIN_STATUS_NONE;
    uint32_t attempts = BITCOIN_ATTEMPTS_NA;

    if (bitcoin_core_status(bitcoin_core_session_production(), &state, &attempts) != PSA_SUCCESS) {
        shown_state = STATE_UNKNOWN;
        strcpy(status_word, "error");
        status_note[0] = '\0';
        paint_word();
        return;
    }

    shown_state = state;
    if (state == BITCOIN_STATUS_OPEN) {
        paint_open();
        return;
    }

    const char *word = status_word_str(state);

    if (word) {
        strcpy(status_word, word);
    } else {
        size_t len = 0;

        status_word[0] = '\0';
        text_add(status_word, sizeof(status_word), &len, "state ");
        text_add_u32(status_word, sizeof(status_word), &len, state);
    }

    set_note(state, attempts);
    paint_word();
}

// The review opens once the tx waits for the user.
// Before confirm() there is no tx_id to bind the press to.
static void poll_tx(void)
{
    if (review_tx_waiting()) {
        display_show(&review_screen, NULL);
    }
}

static void status_enter(void *arg)
{
    (void)arg;

    tx_ticks = 0;
    status_ticks = 0;
    refresh();
}

static void status_ok(void)
{
    if (shown_state == BITCOIN_STATUS_NONE) {
        display_show(&wallet_setup_screen, NULL);
    } else if (shown_state == BITCOIN_STATUS_LOCKED) {
        display_show(&unlock_screen, NULL);
    } else {
        menu_show_main();
    }
}

static void status_next(void)
{
    if (shown_state == BITCOIN_STATUS_NONE || shown_state == BITCOIN_STATUS_LOCKED) {
        menu_show_main();
    }
}

static void status_tick(void)
{
    if (++tx_ticks >= TX_POLL_TICKS) {
        tx_ticks = 0;
        poll_tx();
    }
    if (++status_ticks >= STATUS_POLL_TICKS) {
        status_ticks = 0;
        refresh();
    }
}

const display_screen_ops_t status_screen = {
    .enter = status_enter,
    .on_next = status_next,
    .on_ok = status_ok,
    .tick = status_tick,
};
