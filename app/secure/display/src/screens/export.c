// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/display_priv.h"
#include "core/text.h"
#include "components/header.h"
#include "components/label.h"
#include "components/qr.h"
#include "components/softkeys.h"
#include "bitcoin/bitcoin_core.h"
#include "files/files.h"
#include "shared/descriptor.h"
#include "qrcodegen.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Saves the open wallet to the card as a watch-only descriptor.
// NS gets the xpub and the fingerprint from the partition and writes the file,
// so the file is an NS claim.
// The qr key shows the same descriptor, built by the partition from its own key.
// The fingerprint and the first receive address come from the partition too,
// and the user compares them with the importing wallet.

#define FIRST_ADDRESS_PATH "m/84'/0'/0'/0/0"

#define TEXT_X 12
#define TEXT_W 216
#define TITLE_Y 56
#define INFO_Y 44
#define DONE_TITLE_Y 38
#define DONE_NAME_Y 72
#define DONE_INFO_Y 100
#define INFO_STEP 28
#define LINE_GAP 4

#define FP_HEX_SIZE (2 * BITCOIN_FINGERPRINT_SIZE + 1)

// The descriptor is always 154 bytes, the capacity of version 7 at ECC level L (45x45).
#define QR_VERSION_MAX 7
#define QR_BUF_SIZE qrcodegen_BUFFER_LEN_FOR_VERSION(QR_VERSION_MAX)

_Static_assert(QR_BUF_SIZE - 1 <= PANEL_MONO_MAX, "the QR does not fit the panel pool");

static bool have_wallet;
static char fp_line[sizeof("fingerprint ") + FP_HEX_SIZE];
static char name[sizeof("wallet-.txt") + FP_HEX_SIZE];
static char address[BITCOIN_ADDRESS_MAX_SIZE];
static files_job_state_t shown_state;
static uint8_t qr[QR_BUF_SIZE];
static uint8_t qr_tmp[QR_BUF_SIZE];
static bool qr_shown;

static bool our_job(void)
{
    return files_job_state() != FILES_JOB_IDLE && files_job_kind() == BITCOIN_JOB_EXPORT;
}

static const char *reason(uint32_t code)
{
    switch (code) {
    case BITCOIN_FILES_OK:
        return "saved to card";
    case BITCOIN_FILES_NO_CARD:
        return "no card";
    case BITCOIN_FILES_READ_FAILED:
        return "cannot read the wallet key";
    case BITCOIN_FILES_WRITE_FAILED:
        return "cannot write the card";
    default:
        return "failed";
    }
}

// NS names the file the same way.
static void load(void)
{
    wallet_session_t *w = bitcoin_core_session_production();
    uint8_t fp[BITCOIN_FINGERPRINT_SIZE];
    size_t len = 0;

    have_wallet =
        bitcoin_core_get_fingerprint(w, fp) == PSA_SUCCESS &&
        bitcoin_core_get_address(w, FIRST_ADDRESS_PATH, address, sizeof(address)) == PSA_SUCCESS;
    if (!have_wallet) {
        return;
    }
    fp_line[0] = '\0';
    text_add(fp_line, sizeof(fp_line), &len, "fingerprint ");
    text_add_hex(fp_line, sizeof(fp_line), &len, fp, sizeof(fp));
    len = 0;
    name[0] = '\0';
    text_add(name, sizeof(name), &len, "wallet-");
    text_add_hex(name, sizeof(name), &len, fp, sizeof(fp));
    text_add(name, sizeof(name), &len, ".txt");
}

static bool make_qr(void)
{
    wallet_session_t *w = bitcoin_core_session_production();
    uint8_t fp[BITCOIN_FINGERPRINT_SIZE];
    char xpub[BITCOIN_XPUB_MAX_SIZE];
    char desc[DESCRIPTOR_MAX_SIZE];

    return bitcoin_core_get_fingerprint(w, fp) == PSA_SUCCESS &&
           bitcoin_core_get_xpub(w, DESCRIPTOR_ACCOUNT_PATH, xpub, sizeof(xpub)) == PSA_SUCCESS &&
           descriptor_build(fp, xpub, desc, sizeof(desc)) != 0 &&
           qrcodegen_encodeText(desc, qr_tmp, qr, qrcodegen_Ecc_LOW, qrcodegen_VERSION_MIN,
                                QR_VERSION_MAX, qrcodegen_Mask_AUTO, true);
}

static void draw_info(int y)
{
    y += panel_draw_text_wrapped(TEXT_X, y, TEXT_W, fp_line, &font_16, COL_INK) + LINE_GAP;
    y += panel_draw_text_wrapped(TEXT_X, y, TEXT_W, "first address", &font_16, COL_MUTE);
    panel_draw_text_wrapped(TEXT_X, y, TEXT_W, address, &font_16, COL_INK);
}

static void draw_done(void)
{
    bool ok = files_job_code() == BITCOIN_FILES_OK;

    label_draw(ok ? "saved" : "not saved", &font_24, ok ? COL_GOOD : COL_ALERT, LABEL_TOP_MID, 0,
               DONE_TITLE_Y);
    if (ok) {
        panel_draw_text_wrapped(TEXT_X, DONE_NAME_Y, TEXT_W, name, &font_16, COL_INK);
        draw_info(DONE_INFO_Y);
    } else {
        panel_draw_text_wrapped(TEXT_X, DONE_NAME_Y, TEXT_W, reason(files_job_code()), &font_20,
                                COL_INK);
    }
    softkeys_set("back", NULL, "done");
}

static void draw(void)
{
    shown_state = files_job_state();
    if (qr_shown) {
        qr_draw(qr);
        return;
    }
    panel_clear(COL_BG);
    header_draw("Export wallet", &font_16, COL_SURFACE, COL_MUTE);
    if (!have_wallet) {
        label_draw("no wallet open", &font_20, COL_INK, LABEL_TOP_MID, 0, TITLE_Y);
        softkeys_set("back", NULL, NULL);
        return;
    }
    if (!our_job()) {
        label_draw("watch-only, BIP84", &font_16, COL_MUTE, LABEL_TOP_LEFT, TEXT_X, INFO_Y);
        draw_info(INFO_Y + INFO_STEP);
        softkeys_set("back", "qr", "save");
        return;
    }
    if (shown_state == FILES_JOB_DONE) {
        draw_done();
        return;
    }
    label_draw("saving...", &font_20, COL_INK, LABEL_TOP_MID, 0, TITLE_Y);
    label_draw("keep the card in", &font_16, COL_MUTE, LABEL_BOTTOM_MID, 0, -SOFTKEYS_HEIGHT - 8);
    softkeys_set("cancel", NULL, NULL);
}

static void export_enter(void *arg)
{
    (void)arg;

    qr_shown = false;
    load();
    draw();
}

// Any key on the QR goes back to the info and does nothing else.
static bool hide_qr(void)
{
    if (!qr_shown) {
        return false;
    }
    qr_shown = false;
    draw();
    return true;
}

// A job that is not ours is not ours to close.
static void export_leave(void)
{
    if (our_job()) {
        files_job_close();
    }
    display_show(&menu_screen, NULL);
}

static void export_del(void)
{
    if (!hide_qr()) {
        export_leave();
    }
}

static void export_next(void)
{
    if (hide_qr() || !have_wallet || our_job()) {
        return;
    }
    if (make_qr()) {
        qr_shown = true;
        draw();
    }
}

static void export_ok(void)
{
    if (hide_qr()) {
        return;
    }
    if (!our_job()) {
        if (have_wallet && files_job_request_export()) {
            draw();
        }
    } else if (files_job_state() == FILES_JOB_DONE) {
        export_leave();
    }
}

static void export_tick(void)
{
    if (files_job_state() != shown_state) {
        draw();
    }
}

const display_screen_ops_t export_screen = {
    .enter = export_enter,
    .on_del = export_del,
    .on_next = export_next,
    .on_ok = export_ok,
    .tick = export_tick,
};
