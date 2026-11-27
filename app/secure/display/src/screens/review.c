// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/display_priv.h"
#include "components/header.h"
#include "components/softkeys.h"
#include "bitcoin/bitcoin_core.h"
#include "shared/bitcoin_service_defs.h"
#include "shared/tx_records.h"
#include "core/text.h"
#include "files/files.h"
#include <stdbool.h>
#include <string.h>

// The screen opens once the tx waits for the user, so it has a tx_id.
// Each page reads the tx_id and its rows in the same tick, with no IPC message in between,
// and a tx_id other than the one the review opened with drops the tx.
// Approve passes that tx_id back, so a press approves only the tx on screen.
// If NS swapped it in the meantime, the approval fails and drops the session.

// A total row, one row per shown output, a fee row. tx_session_get_summary() renders nothing else,
// and tx_session_confirm() refuses a tx whose external outputs did not all fit in `shown`.
#define SUMMARY_MAX_LINES (BITCOIN_TX_MAX_SHOWN_OUTPUTS + 2)

// The total page has four slots: Send, Fee, the lock line and the prompt.
// An output page uses three: what it is, the amount, the address.
#define BODY_SLOTS 4
#define BODY_X 12
#define BODY_Y 42
#define BODY_WIDTH 216
#define BODY_GAP 6
#define TEXT_MAX 40

// Nothing scrolls, so an address that does not fit would be cut off.
// A P2WSH or P2TR address is 62 characters, and that only fits the address slot at 16.
#define ADDRESS_BIG_MAX 48

#define TX_POLL_TICKS 10

// Approve does nothing for the first second,
// so a press meant for the screen before, made just as the tx arrived, cannot approve it.
// With no external output the total page is the first page, so this is the only guard there.
#define ARM_TICKS 50

// The slots, refilled per page, font and color included. An empty slot takes no space.
// An address is up to 62 characters, so the slots wrap.
// The end of an address is what makes it that address, so nothing is cut.
typedef struct {
    char text[BITCOIN_ADDRESS_MAX_SIZE];
    const font_t *font;
    uint16_t color;
} slot_t;

static slot_t slots[BODY_SLOTS];

// The tx_id the review opened with.
static uint8_t shown_tx_id[32];
static bool approved;
static int shown_ticks;

// The summary lines of that tx, and the page on screen.
// Nothing scrolls, so each output gets its own page, and the last page is the total and the fee.
static uint32_t row_count;
static uint32_t page;
static int tx_ticks;

// A card sign job goes back to its own screen, which shows how it ended.
// Anything else goes to status.
static void leave(void)
{
    bool card_job = files_job_state() != FILES_JOB_IDLE && files_job_kind() == BITCOIN_JOB_SIGN;

    display_show(card_job ? &sign_job_screen : &status_screen, NULL);
}

bool review_tx_waiting(void)
{
    uint8_t tx_id[32];

    return bitcoin_core_tx_get_tx_id(bitcoin_core_session_production(), tx_id) == PSA_SUCCESS;
}

// The slots stack one under the other.
// The amber band and the amber approve tile appear only here, so amber means a transaction waits.
static void paint(const char *counter, const char *ok)
{
    int y = BODY_Y;

    panel_clear(COL_BG);
    header_draw("Review", &font_24, COL_ACCENT, COL_ON_ACCENT);
    for (int i = 0; i < BODY_SLOTS; i++) {
        if (slots[i].text[0] == '\0') {
            continue;
        }
        y += panel_draw_text_wrapped(BODY_X, y, BODY_WIDTH, slots[i].text, slots[i].font,
                                     slots[i].color);
        y += BODY_GAP;
    }
    if (ok) {
        softkeys_set_sign("reject", counter, ok);
    } else {
        softkeys_set("reject", counter, NULL);
    }
}

static void set_slot(int i, const char *text, const font_t *font, uint16_t color)
{
    size_t len = 0;

    slots[i].text[0] = '\0';
    text_add(slots[i].text, sizeof(slots[i].text), &len, text);
    slots[i].font = font;
    slots[i].color = color;
}

// tx_format_btc() also formats the summary the partition logs on the secure UART,
// so both show the same string.
// A cut amount would name a different number, so the page fails instead.
static bool set_amount(int slot, const char *prefix, uint64_t sats, const font_t *font,
                       uint16_t color)
{
    char amount[32];
    char text[TEXT_MAX] = "";
    size_t len = 0;

    if (!tx_format_btc(sats, amount, sizeof(amount))) {
        return false;
    }

    if (!text_add(text, sizeof(text), &len, prefix) ||
        !text_add(text, sizeof(text), &len, amount) ||
        !text_add(text, sizeof(text), &len, " BTC")) {
        return false;
    }

    set_slot(slot, text, font, color);
    return true;
}

static bool read_row(uint32_t line, uint8_t kind, bitcoin_tx_summary_t *out)
{
    if (bitcoin_core_tx_get_summary(bitcoin_core_session_production(), line, out) != PSA_SUCCESS) {
        return false;
    }
    return out->kind == kind;
}

// One external destination, the whole address on one screen.
// The address is not grouped and never shortened.
static bool fill_output_page(uint32_t p)
{
    uint32_t outputs = row_count - 2;
    bitcoin_tx_summary_t row;
    char text[TEXT_MAX] = "";
    size_t len = 0;

    if (!read_row(p + 1, BITCOIN_TX_SUMMARY_KIND_OUTPUT, &row)) {
        return false;
    }

    text_add(text, sizeof(text), &len, "to ");
    text_add_u32(text, sizeof(text), &len, p + 1);
    text_add(text, sizeof(text), &len, " of ");
    text_add_u32(text, sizeof(text), &len, outputs);
    set_slot(0, text, &font_16, COL_MUTE);

    if (!set_amount(1, "", row.amount, &font_24, COL_INK)) {
        return false;
    }

    set_slot(2, row.address, strlen(row.address) <= ADDRESS_BIG_MAX ? &font_20 : &font_16, COL_INK);
    set_slot(3, "", &font_16, COL_MUTE);
    return true;
}

// The locks and RBF, as one line. Empty when the tx has none.
// A locktime below 500000000 is a block height, above it a unix time.
static void add_details(char *text, size_t size, const bitcoin_tx_details_t *d)
{
    size_t len = 0;

    if (d->locktime_active) {
        text_add(text, size, &len, "after ");
        if (d->locktime < 500000000u) {
            text_add(text, size, &len, "block ");
            text_add_u32(text, size, &len, d->locktime);
        } else {
            text_add_utc_date(text, size, &len, d->locktime);
            text_add(text, size, &len, " UTC");
        }
    }
    if (d->relative_lock) {
        text_add(text, size, &len, len ? ", relative lock" : "relative lock");
    }
    if (d->rbf) {
        text_add(text, size, &len, len ? ", RBF" : "RBF");
    }
}

// The last page. The total leaving the wallet is what the user checks before the press,
// so it is the largest thing here, and the fee is quieter unless it is high.
//
// Approve signs from this page only.
// The next key only moves forward, so this page comes after every output page.
static bool fill_total_page(void)
{
    bitcoin_tx_summary_t total;
    bitcoin_tx_summary_t fee;
    bitcoin_tx_details_t details;
    // The longest line, "after block 499999999, relative lock, RBF", fits.
    char text[64] = "";

    if (!read_row(0, BITCOIN_TX_SUMMARY_KIND_TOTAL, &total) ||
        !read_row(row_count - 1, BITCOIN_TX_SUMMARY_KIND_FEE, &fee) ||
        bitcoin_core_tx_get_details(bitcoin_core_session_production(), &details) != PSA_SUCCESS) {
        return false;
    }

    if (!set_amount(0, "Send ", total.amount, &font_24, COL_INK) ||
        !set_amount(1, "Fee ", fee.amount, &font_20, details.high_fee ? COL_ALERT : COL_MUTE)) {
        return false;
    }

    add_details(text, sizeof(text), &details);
    set_slot(2, text, &font_16, COL_MUTE);

    // The page has no room for a longer fee line,
    // so the warning goes in the prompt, next to the key that signs.
    if (approved) {
        set_slot(3, "signing", &font_20, COL_MUTE);
    } else if (details.high_fee) {
        set_slot(3, "high fee, OK to sign", &font_20, COL_ALERT);
    } else {
        set_slot(3, "press OK to sign", &font_20, COL_ACCENT);
    }
    return true;
}

// Draws the tx as tx_session accounts for it.
// These are the numbers the signature commits to, so the screen computes nothing.
// The page counter sits over the next key, so it shows the page count and which key turns pages.
//
// False if the tx is not the one the review opened with.
// The tx_id is read in the same tick as the rows,
// so NS cannot show the rows of another tx between two polls of review_tick().
static bool draw_page(uint32_t p)
{
    uint8_t tx_id[32];
    char text[TEXT_MAX] = "";
    size_t len = 0;
    bool total = p == row_count - 2;

    if (bitcoin_core_tx_get_tx_id(bitcoin_core_session_production(), tx_id) != PSA_SUCCESS ||
        memcmp(tx_id, shown_tx_id, sizeof(tx_id)) != 0) {
        return false;
    }
    if (!(total ? fill_total_page() : fill_output_page(p))) {
        return false;
    }

    text_add_u32(text, sizeof(text), &len, p + 1);
    text_add(text, sizeof(text), &len, "/");
    text_add_u32(text, sizeof(text), &len, row_count - 1);
    paint(text, total && !approved ? "sign" : NULL);
    return true;
}

// Counts the summary lines. Only DOES_NOT_EXIST means "that was the last row".
// Any other status drops the screen, never a short summary:
// a summary missing its end is one the user approves without seeing where the money goes.
static bool count_rows(void)
{
    bitcoin_tx_summary_t row;
    uint32_t count = 0;

    for (uint32_t i = 0; i < SUMMARY_MAX_LINES; i++) {
        psa_status_t status =
            bitcoin_core_tx_get_summary(bitcoin_core_session_production(), i, &row);

        if (status == PSA_ERROR_DOES_NOT_EXIST) {
            break;
        }
        if (status != PSA_SUCCESS) {
            return false;
        }
        count++;
    }

    // A transaction always has a total line and a fee line.
    if (count < 2) {
        return false;
    }

    row_count = count;
    return true;
}

static void review_enter(void *arg)
{
    (void)arg;

    tx_ticks = 0;
    shown_ticks = 0;
    page = 0;
    approved = false;

    if (bitcoin_core_tx_get_tx_id(bitcoin_core_session_production(), shown_tx_id) != PSA_SUCCESS ||
        !count_rows() || !draw_page(page)) {
        leave();
        return;
    }

    // A tx arriving while the panel is dimmed is the moment the user most needs to read it.
    display_wake();
}

// The only refusal the panel can make.
// The NS poll loop then gets PSA_ERROR_BAD_STATE and reports a failed signing.
// A card job ends here as REJECTED, so the later NS report cannot replace the reason.
static void review_del(void)
{
    bitcoin_core_tx_abort(bitcoin_core_session_production());
    files_job_reject();
    leave();
}

// A press that fails dropped the session or found it gone,
// so the tx on screen can no longer be signed.
static void review_ok(void)
{
    if (approved || page != row_count - 2 || shown_ticks < ARM_TICKS) {
        return;
    }
    if (bitcoin_core_tx_approve_user(bitcoin_core_session_production(), shown_tx_id) !=
        PSA_SUCCESS) {
        leave();
        return;
    }

    approved = true;
    if (!draw_page(page)) {
        leave();
    }
}

// Turns to the next page and wraps, so every output stays reachable with one key.
// A page that fails before approve drops the tx as reject does.
// After approve it only leaves: NS signs and then aborts the session.
static void review_next(void)
{
    page = (page + 1) % (row_count - 1);
    if (draw_page(page)) {
        return;
    }
    if (approved) {
        leave();
    } else {
        review_del();
    }
}

// NS sends one tx per review.
// A different tx_id under an open review is a swap,
// and a tx_id that is gone before approve is the start of one (a new BEGIN).
// The new tx is not shown as if nothing happened, or the user would page through it and sign.
// It is dropped as reject does, so a card job ends as rejected.
// After approve, NS signs and then aborts the session, and the screen only leaves.
static void review_tick(void)
{
    uint8_t tx_id[32];

    if (shown_ticks < ARM_TICKS) {
        shown_ticks++;
    }
    if (++tx_ticks < TX_POLL_TICKS) {
        return;
    }
    tx_ticks = 0;

    if (bitcoin_core_tx_get_tx_id(bitcoin_core_session_production(), tx_id) != PSA_SUCCESS) {
        if (approved) {
            leave();
        } else {
            review_del();
        }
    } else if (memcmp(tx_id, shown_tx_id, sizeof(tx_id)) != 0) {
        review_del();
    }
}

const display_screen_ops_t review_screen = {
    .enter = review_enter,
    .on_del = review_del,
    .on_next = review_next,
    .on_ok = review_ok,
    .tick = review_tick,
};
