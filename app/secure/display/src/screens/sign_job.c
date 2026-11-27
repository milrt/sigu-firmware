// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/display_priv.h"
#include "components/header.h"
#include "components/label.h"
#include "components/softkeys.h"
#include "bitcoin/bitcoin_core.h"
#include "files/files.h"
#include <stdbool.h>
#include <stdint.h>

// One sign job from the card, from the pick to the result.
// NS reads the file, drives the tx session and writes the signed file.
// Only the numbers on the review screen come from the partition. "saved" is an NS claim.

#define TX_POLL_TICKS 10

#define TEXT_X 12
#define TEXT_W 216
#define TITLE_Y 56
#define NAME_Y 100

static files_job_state_t shown_state;
static bool reviewed;
static int tx_ticks;

static const char *reason(uint32_t code)
{
    switch (code) {
    case BITCOIN_FILES_OK:
        return "saved to card";
    case BITCOIN_FILES_NO_CARD:
        return "no card";
    case BITCOIN_FILES_READ_FAILED:
        return "cannot read the file";
    case BITCOIN_FILES_TOO_BIG:
        return "file too big";
    case BITCOIN_FILES_BAD_PSBT:
        return "not a valid PSBT";
    case BITCOIN_FILES_NOT_SIGNED:
        return "the wallet did not sign it";
    case BITCOIN_FILES_WRITE_FAILED:
        return "cannot write the card";
    case BITCOIN_FILES_REJECTED:
        return "rejected";
    default:
        return "failed";
    }
}

static void draw(void)
{
    // BITCOIN_FILES_OK is what NS says. "signed" also needs a signature the SP made in this job.
    bool card_ok = files_job_code() == BITCOIN_FILES_OK;
    bool ok = card_ok && files_job_signed();
    const char *why =
        card_ok && !ok ? "the card says saved, but nothing was signed" : reason(files_job_code());

    shown_state = files_job_state();
    panel_clear(COL_BG);
    header_draw("SD card", &font_16, COL_SURFACE, COL_MUTE);
    if (shown_state == FILES_JOB_DONE) {
        label_draw(ok ? "signed" : "not signed", &font_24, ok ? COL_GOOD : COL_ALERT, LABEL_TOP_MID,
                   0, TITLE_Y);
        panel_draw_text_wrapped(TEXT_X, NAME_Y, TEXT_W, why, &font_20, COL_INK);
        softkeys_set("back", NULL, "done");
        return;
    }
    label_draw(reviewed ? "saving..." : "reading card...", &font_20, COL_INK, LABEL_TOP_MID, 0,
               TITLE_Y);
    panel_draw_text_wrapped(TEXT_X, NAME_Y, TEXT_W, files_job_name(), &font_16, COL_MUTE);
    label_draw("keep the card in", &font_16, COL_MUTE, LABEL_BOTTOM_MID, 0, -SOFTKEYS_HEIGHT - 8);
    softkeys_set("cancel", NULL, NULL);
}

// The picker opens this screen with a fresh REQUESTED job.
// The review comes back with BUSY or DONE.
static void job_enter(void *arg)
{
    files_job_state_t state = files_job_state();

    (void)arg;

    if (state == FILES_JOB_IDLE) {
        display_show(&files_screen, NULL);
        return;
    }
    if (state == FILES_JOB_REQUESTED) {
        reviewed = false;
    }
    tx_ticks = 0;
    draw();
}

// Only a BUSY job aborts the tx. Before NS took the job, a tx in the session is not the job's.
static void job_leave(void)
{
    if (files_job_state() == FILES_JOB_BUSY) {
        bitcoin_core_tx_abort(bitcoin_core_session_production());
    }
    files_job_close();
    display_show(&files_screen, NULL);
}

static void job_ok(void)
{
    if (files_job_state() == FILES_JOB_DONE) {
        job_leave();
    }
}

// The review opens only for a BUSY job.
// Before NS took the request, a tx in the session came from another NS caller.
static void job_tick(void)
{
    if (files_job_state() == FILES_JOB_BUSY && !reviewed && ++tx_ticks >= TX_POLL_TICKS) {
        tx_ticks = 0;
        if (review_tx_waiting()) {
            reviewed = true;
            display_show(&review_screen, NULL);
            return;
        }
    }
    if (files_job_state() != shown_state) {
        draw();
    }
}

const display_screen_ops_t sign_job_screen = {
    .enter = job_enter,
    .on_del = job_leave,
    .on_ok = job_ok,
    .tick = job_tick,
};
