// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/display_priv.h"
#include "components/header.h"
#include "components/label.h"
#include "components/list.h"
#include "components/softkeys.h"
#include "bitcoin/bitcoin_core.h"
#include "files/files.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// The PSBTs at the top of the card as NS reported them.
// The list can change under this screen, so the tick reloads on a new generation.
// Open asks NS to sign the file by the name on screen, and sign_job.c takes over.

static const char *labels[BITCOIN_FILES_MAX];
static uint32_t shown_gen;
static uint8_t n;
static uint8_t sel;
static bool wallet_open;

// The fingerprint is in RAM. The status call would cost a PS lookup while the wallet is locked.
static void load(void)
{
    uint8_t fp[BITCOIN_FINGERPRINT_SIZE];

    shown_gen = files_generation();
    wallet_open =
        bitcoin_core_get_fingerprint(bitcoin_core_session_production(), fp) == PSA_SUCCESS;
    n = files_count();
    for (uint8_t i = 0; i < n; i++) {
        labels[i] = files_name(i);
    }
    if (sel >= n) {
        sel = 0;
    }
}

// NULL when there is a list to pick from.
static const char *empty_text(void)
{
    if (!wallet_open) {
        return "open a wallet first";
    }
    if (files_card() == BITCOIN_CARD_NONE) {
        return "insert SD card";
    }
    if (files_card() != BITCOIN_CARD_MOUNTED) {
        return "SD card error";
    }
    if (n == 0) {
        return "no .psbt files";
    }
    return NULL;
}

static void draw(void)
{
    const char *empty = empty_text();

    panel_clear(COL_BG);
    header_draw("SD card", &font_16, COL_SURFACE, COL_MUTE);
    if (empty) {
        label_draw(empty, &font_20, COL_MUTE, LABEL_CENTER, 0, 0);
        softkeys_set("back", NULL, NULL);
        return;
    }
    list_draw(labels, n, sel);
    softkeys_set("back", n > 1 ? "next" : NULL, "open");
}

static void files_enter(void *arg)
{
    (void)arg;

    sel = 0;
    load();
    draw();
}

static void files_del(void)
{
    display_show(&menu_screen, NULL);
}

static void files_next(void)
{
    if (!empty_text() && n > 1) {
        sel = (sel + 1) % n;
        draw();
    }
}

// A list that changed since the last draw is not what the user saw. The tick draws it first.
static void files_ok(void)
{
    if (files_generation() == shown_gen && !empty_text() && files_job_request_sign(labels[sel])) {
        display_show(&sign_job_screen, NULL);
    }
}

static void files_tick(void)
{
    if (files_generation() != shown_gen) {
        load();
        draw();
    }
}

const display_screen_ops_t files_screen = {
    .enter = files_enter,
    .on_del = files_del,
    .on_next = files_next,
    .on_ok = files_ok,
    .tick = files_tick,
};
