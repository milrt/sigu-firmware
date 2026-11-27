// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/display_priv.h"
#include "core/text.h"
#include "components/header.h"
#include "components/label.h"
#include "components/qr.h"
#include "components/softkeys.h"
#include "bitcoin/bitcoin_core.h"
#include "qrcodegen.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// A receive address of the open wallet. The partition derives it, so NS never sees it.
// An address a host shows is a claim, and the user checks it against this screen.
// The qr key shows the same address as a QR code for a phone wallet.

#define PATH_PREFIX "m/84'/0'/0'/0/"
// The same limit as for change, so every address shown here is one the review knows as ours.
#define INDEX_MAX 1000
#define GROUP 4

#define TEXT_X 12
#define TEXT_W 216
#define TITLE_Y 56
#define PATH_Y 44
#define ADDRESS_Y 72
#define FP_Y (-SOFTKEYS_HEIGHT - 8)

#define FP_HEX_SIZE (2 * BITCOIN_FINGERPRINT_SIZE + 1)

// A P2WPKH address in uppercase is 42 characters.
// Version 2 at ECC level L holds 47 in alphanumeric mode (25x25).
#define QR_VERSION_MAX 2
#define QR_BUF_SIZE qrcodegen_BUFFER_LEN_FOR_VERSION(QR_VERSION_MAX)

_Static_assert(QR_BUF_SIZE - 1 <= PANEL_MONO_MAX, "the QR does not fit the panel pool");

static uint16_t shown_index;
static bool have_wallet;
static char path[sizeof(PATH_PREFIX) + 4];
static char address[BITCOIN_ADDRESS_MAX_SIZE];
static char grouped[BITCOIN_ADDRESS_MAX_SIZE + BITCOIN_ADDRESS_MAX_SIZE / GROUP];
static char fp_line[sizeof("temp wallet ") + FP_HEX_SIZE];
static uint8_t qr[QR_BUF_SIZE];
static uint8_t qr_tmp[QR_BUF_SIZE];
static bool qr_shown;

// Groups of 4 are easier to compare. A space is also where a line may wrap, so no group is cut.
static void group_address(void)
{
    size_t n = 0;

    for (size_t i = 0; address[i] && n + 2 < sizeof(grouped); i++) {
        if (i && i % GROUP == 0) {
            grouped[n++] = ' ';
        }
        grouped[n++] = address[i];
    }
    grouped[n] = '\0';
}

static void load(void)
{
    wallet_session_t *w = bitcoin_core_session_production();
    uint8_t fp[BITCOIN_FINGERPRINT_SIZE];
    size_t len = 0;

    path[0] = '\0';
    text_add(path, sizeof(path), &len, PATH_PREFIX);
    text_add_u32(path, sizeof(path), &len, shown_index);

    have_wallet = bitcoin_core_get_fingerprint(w, fp) == PSA_SUCCESS &&
                  bitcoin_core_get_address(w, path, address, sizeof(address)) == PSA_SUCCESS;
    if (!have_wallet) {
        return;
    }
    group_address();
    len = 0;
    fp_line[0] = '\0';
    text_add(fp_line, sizeof(fp_line), &len,
             bitcoin_core_is_temporary(w) ? "temp wallet " : "fingerprint ");
    text_add_hex(fp_line, sizeof(fp_line), &len, fp, sizeof(fp));
}

// Bech32 ignores case. Uppercase lets the QR use alphanumeric mode, which BIP173 suggests.
static bool make_qr(void)
{
    char upper[BITCOIN_ADDRESS_MAX_SIZE];
    size_t i;

    for (i = 0; address[i]; i++) {
        char c = address[i];

        upper[i] = c >= 'a' && c <= 'z' ? (char)(c - 'a' + 'A') : c;
    }
    upper[i] = '\0';
    return qrcodegen_encodeText(upper, qr_tmp, qr, qrcodegen_Ecc_LOW, qrcodegen_VERSION_MIN,
                                QR_VERSION_MAX, qrcodegen_Mask_AUTO, true);
}

static void draw(void)
{
    if (qr_shown) {
        qr_draw(qr);
        return;
    }
    panel_clear(COL_BG);
    header_draw("Receive", &font_16, COL_SURFACE, COL_MUTE);
    if (!have_wallet) {
        label_draw("no wallet open", &font_20, COL_INK, LABEL_TOP_MID, 0, TITLE_Y);
        softkeys_set("back", NULL, NULL);
        return;
    }
    label_draw(path, &font_16, COL_MUTE, LABEL_TOP_LEFT, TEXT_X, PATH_Y);
    panel_draw_text_wrapped(TEXT_X, ADDRESS_Y, TEXT_W, grouped, &font_20, COL_INK);
    label_draw(fp_line, &font_16, COL_MUTE, LABEL_BOTTOM_LEFT, TEXT_X, FP_Y);
    softkeys_set("back", "next", "qr");
}

static void show(uint16_t i)
{
    shown_index = i % INDEX_MAX;
    load();
    draw();
}

// Each visit starts at index 0, the address the Export screen shows.
static void receive_enter(void *arg)
{
    (void)arg;

    qr_shown = false;
    show(0);
}

// Any key on the QR goes back to the address, and does nothing else.
static bool hide_qr(void)
{
    if (!qr_shown) {
        return false;
    }
    qr_shown = false;
    draw();
    return true;
}

static void receive_del(void)
{
    if (!hide_qr()) {
        display_show(&menu_screen, NULL);
    }
}

static void receive_next(void)
{
    if (!hide_qr() && have_wallet) {
        show(shown_index + 1);
    }
}

static void receive_ok(void)
{
    if (hide_qr() || !have_wallet) {
        return;
    }
    if (make_qr()) {
        qr_shown = true;
        draw();
    }
}

const display_screen_ops_t receive_screen = {
    .enter = receive_enter,
    .on_del = receive_del,
    .on_next = receive_next,
    .on_ok = receive_ok,
};
