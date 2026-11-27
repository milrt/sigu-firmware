// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/display_priv.h"
#include "components/header.h"
#include "components/label.h"
#include "components/list.h"
#include "components/passphrase_entry.h"
#include "components/pin_entry.h"
#include "components/seed_entry.h"
#include "components/softkeys.h"
#include "bitcoin/bitcoin_core.h"
#include "shared/bitcoin_service_defs.h"
#include "shared/mem_util.h"
#include "core/text.h"
#include "bip39_wordlist.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// New wallet: count -> create -> word pages -> quiz -> PIN twice -> save -> open.
// Restore: seed entry -> recover -> PIN twice -> save -> open.
//
// The seed never leaves the partition.
// bitcoin_core_create() writes the new words into this screen's buffer in the same call,
// and no call hands them out later.
// The partition has one thread, so no NS message comes in between.

#define WORDS_MAX 24
#define PAGE_WORDS 4
#define QUIZ_N 3
#define QUIZ_CHOICES 4
#define TEXT_X 18
#define HINT_X 12
#define HINT_Y (LIST_Y + PAGE_WORDS * LIST_STEP + 12)

enum phase {
    PHASE_CHOOSE,
    PHASE_COUNT,
    PHASE_CREATING,
    PHASE_SHOW,
    PHASE_QUIZ,
    PHASE_SEED,
    PHASE_PIN,
    PHASE_PIN_AGAIN,
    PHASE_SAVING,
    PHASE_PASS,
    PHASE_OPEN,
    PHASE_MSG,
};

static const char *const choose_labels[] = {"New wallet", "Restore wallet"};
static const char *const count_labels[] = {"12 words", "24 words"};

static enum phase phase;
static uint8_t sel;
static const char *msg;
// The busy phases run their call on the next tick.
static bool pending;
// Confirming the message goes to the status screen, else back to the word pages.
static bool msg_leaves;
// The session holds this screen's create or recover, so exit() must drop it.
static bool started;

static char mnemonic[BITCOIN_MNEMONIC_MAX_SIZE];
// A copy of the mnemonic, cut into words for the pages and the quiz.
static char words_buf[BITCOIN_MNEMONIC_MAX_SIZE];
static const char *word[WORDS_MAX];
static uint8_t total;
static uint8_t page;

static uint8_t quiz_pos[QUIZ_N];
static uint8_t q;
static const char *cand[QUIZ_CHOICES];
static uint8_t right_slot;

static char pin1[PIN_ENTRY_MAX + 1];

static void wipe_all(void)
{
    mem_zeroize(mnemonic, sizeof(mnemonic));
    mem_zeroize(words_buf, sizeof(words_buf));
    mem_zeroize(word, sizeof(word));
    mem_zeroize(quiz_pos, sizeof(quiz_pos));
    mem_zeroize(cand, sizeof(cand));
    mem_zeroize(pin1, sizeof(pin1));
    right_slot = 0;
    total = 0;
    seed_entry_clear();
    pin_entry_wipe();
    passphrase_clear();
}

static uint8_t split_words(void)
{
    char *p = words_buf;
    uint8_t n = 0;

    memcpy(words_buf, mnemonic, sizeof(words_buf));
    while (*p && n < WORDS_MAX) {
        word[n++] = p;
        while (*p && *p != ' ') {
            p++;
        }
        if (*p) {
            *p++ = '\0';
        }
    }
    return n;
}

static bool rand_u16(uint16_t *v)
{
    return psa_generate_random((uint8_t *)v, sizeof(*v)) == PSA_SUCCESS;
}

static bool cand_used(uint8_t k)
{
    for (uint8_t j = 0; j < k; j++) {
        if (cand[j] == cand[k]) {
            return true;
        }
    }
    return false;
}

// The right word and three other words from the list, in a random order.
static bool make_question(void)
{
    const char *right = word[quiz_pos[q]];
    uint16_t r;

    if (!rand_u16(&r)) {
        return false;
    }
    right_slot = r % QUIZ_CHOICES;
    for (uint8_t k = 0; k < QUIZ_CHOICES; k++) {
        if (k == right_slot) {
            cand[k] = right;
            continue;
        }
        do {
            if (!rand_u16(&r)) {
                return false;
            }
            cand[k] = bip39_wordlist_en[r % BIP39_WORDLIST_EN_SIZE];
        } while (strcmp(cand[k], right) == 0 || cand_used(k));
    }
    sel = 0;
    return true;
}

static bool pos_used(uint8_t i)
{
    for (uint8_t j = 0; j < i; j++) {
        if (quiz_pos[j] == quiz_pos[i]) {
            return true;
        }
    }
    return false;
}

// New positions each time, so a failed quiz does not ask the same words again.
static bool start_quiz(void)
{
    uint16_t r;

    for (uint8_t i = 0; i < QUIZ_N; i++) {
        do {
            if (!rand_u16(&r)) {
                return false;
            }
            quiz_pos[i] = r % total;
        } while (pos_used(i));
    }
    q = 0;
    return make_question();
}

static void draw_list(const char *title, const char *const *labels, uint8_t n)
{
    header_draw(title, &font_16, COL_SURFACE, COL_MUTE);
    list_draw(labels, n, sel);
    softkeys_set(phase == PHASE_CHOOSE ? "cancel" : "back", "next", "ok");
}

static void draw_show(void)
{
    char head[24] = "";
    size_t len = 0;
    uint8_t first = page * PAGE_WORDS;

    text_add(head, sizeof(head), &len, "Words ");
    text_add_u32(head, sizeof(head), &len, first + 1);
    text_add(head, sizeof(head), &len, "-");
    text_add_u32(head, sizeof(head), &len, first + PAGE_WORDS);
    text_add(head, sizeof(head), &len, " / ");
    text_add_u32(head, sizeof(head), &len, total);
    header_draw(head, &font_16, COL_SURFACE, COL_MUTE);

    for (uint8_t i = 0; i < PAGE_WORDS; i++) {
        char row[16] = "";

        len = 0;
        text_add_u32(row, sizeof(row), &len, first + i + 1);
        text_add(row, sizeof(row), &len, ". ");
        text_add(row, sizeof(row), &len, word[first + i]);
        panel_draw_text(TEXT_X, LIST_Y + i * LIST_STEP, row, &font_20, COL_INK);
        mem_zeroize(row, sizeof(row));
    }
    panel_draw_text(HINT_X, HINT_Y, "write them down in order", &font_16, COL_MUTE);
    softkeys_set(page ? "back" : "cancel", NULL, (page + 1) * PAGE_WORDS < total ? "next" : "done");
}

static void draw_quiz(void)
{
    char head[24] = "";
    size_t len = 0;

    text_add(head, sizeof(head), &len, "Check ");
    text_add_u32(head, sizeof(head), &len, q + 1);
    text_add(head, sizeof(head), &len, "/");
    text_add_u32(head, sizeof(head), &len, QUIZ_N);
    text_add(head, sizeof(head), &len, ": word #");
    text_add_u32(head, sizeof(head), &len, quiz_pos[q] + 1);
    header_draw(head, &font_16, COL_SURFACE, COL_MUTE);
    list_draw(cand, QUIZ_CHOICES, sel);
    softkeys_set("back", "next", "ok");
}

static void draw_msg(void)
{
    header_draw("Set up", &font_16, COL_SURFACE, COL_MUTE);
    label_draw(msg, &font_20, COL_INK, LABEL_CENTER, 0, 0);
    softkeys_set(NULL, NULL, pending ? NULL : "ok");
}

static void draw(void)
{
    panel_clear(COL_BG);
    switch (phase) {
    case PHASE_CHOOSE:
        draw_list("Set up", choose_labels, 2);
        break;
    case PHASE_COUNT:
        draw_list("New wallet", count_labels, 2);
        break;
    case PHASE_SHOW:
        draw_show();
        break;
    case PHASE_QUIZ:
        draw_quiz();
        break;
    case PHASE_SEED:
        seed_entry_draw();
        break;
    case PHASE_PIN:
    case PHASE_PIN_AGAIN:
        pin_entry_draw();
        break;
    case PHASE_PASS:
        passphrase_entry_draw();
        break;
    case PHASE_CREATING:
    case PHASE_SAVING:
    case PHASE_OPEN:
    case PHASE_MSG:
        draw_msg();
        break;
    }
}

// exit() drops the setup and wipes the seed and the PINs.
static void leave(void)
{
    display_show(&status_screen, NULL);
}

static void show_msg(const char *text, bool leaves)
{
    phase = PHASE_MSG;
    msg = text;
    msg_leaves = leaves;
    pending = false;
    draw();
}

static void busy(enum phase p, const char *text)
{
    phase = p;
    msg = text;
    pending = true;
    draw();
}

static void start_pin(const char *note, uint16_t color)
{
    phase = PHASE_PIN;
    mem_zeroize(pin1, sizeof(pin1));
    pin_entry_start("Set PIN", note, color);
    draw();
}

static void show_words(void)
{
    phase = PHASE_SHOW;
    page = 0;
    draw();
}

static void creating_tick(void)
{
    wallet_session_t *w = bitcoin_core_session_production();
    psa_status_t status = bitcoin_core_create(w, total == 24 ? 32 : 16, mnemonic, sizeof(mnemonic));

    if (status == PSA_SUCCESS) {
        started = true;
    }
    if (status != PSA_SUCCESS || split_words() != total) {
        show_msg("create failed", true);
        return;
    }
    show_words();
}

static void restore(void)
{
    psa_status_t status =
        bitcoin_core_recover(bitcoin_core_session_production(), seed_entry_mnemonic());

    seed_entry_clear();
    if (status != PSA_SUCCESS) {
        show_msg("restore failed", true);
        return;
    }
    started = true;
    start_pin("you need it to unlock", COL_MUTE);
}

// Confirm clears the session whatever the result, so the setup is no longer ours.
static void saving_tick(void)
{
    psa_status_t status = bitcoin_core_confirm(bitcoin_core_session_production(), pin1);

    started = false;
    mem_zeroize(mnemonic, sizeof(mnemonic));
    mem_zeroize(words_buf, sizeof(words_buf));
    mem_zeroize(word, sizeof(word));
    if (status != PSA_SUCCESS) {
        show_msg(status == PSA_ERROR_BAD_STATE ? "setup interrupted" : "save failed", true);
        return;
    }
    phase = PHASE_PASS;
    passphrase_entry_start("Wallet saved");
    draw();
}

static void open_tick(void)
{
    psa_status_t status =
        bitcoin_core_open(bitcoin_core_session_production(), pin1, passphrase_entered());

    mem_zeroize(pin1, sizeof(pin1));
    passphrase_clear();
    if (status != PSA_SUCCESS) {
        show_msg("saved, open failed", true);
        return;
    }
    leave();
}

static void setup_tick(void)
{
    if (!pending) {
        return;
    }
    pending = false;

    switch (phase) {
    case PHASE_CREATING:
        creating_tick();
        break;
    case PHASE_SAVING:
        saving_tick();
        break;
    case PHASE_OPEN:
        open_tick();
        break;
    default:
        break;
    }
}

static void quiz_ok(void)
{
    if (sel != right_slot) {
        show_msg("wrong word", false);
        return;
    }
    if (++q < QUIZ_N) {
        if (!make_question()) {
            show_msg("setup failed", true);
            return;
        }
        draw();
        return;
    }
    start_pin("you need it to unlock", COL_MUTE);
}

static void show_ok(void)
{
    if (++page * PAGE_WORDS < total) {
        draw();
        return;
    }
    page--;
    if (!start_quiz()) {
        show_msg("setup failed", true);
        return;
    }
    phase = PHASE_QUIZ;
    draw();
}

static void seed_step(enum seed_entry_step s)
{
    if (s == SEED_ENTRY_CANCEL) {
        phase = PHASE_CHOOSE;
        sel = 1;
    } else if (s == SEED_ENTRY_DONE) {
        restore();
        return;
    }
    draw();
}

static void pin_step(enum pin_entry_step s)
{
    if (s == PIN_ENTRY_CANCEL) {
        leave();
        return;
    }
    if (s == PIN_ENTRY_DONE) {
        memcpy(pin1, pin_entry_pin(), sizeof(pin1));
        phase = PHASE_PIN_AGAIN;
        pin_entry_start("Repeat PIN", NULL, COL_MUTE);
    }
    draw();
}

// Both buffers are PIN_ENTRY_MAX + 1 bytes and zero padded, so one memcmp is enough.
static void pin_again_step(enum pin_entry_step s)
{
    if (s == PIN_ENTRY_CANCEL) {
        start_pin(NULL, COL_MUTE);
        return;
    }
    if (s == PIN_ENTRY_DONE) {
        bool same = memcmp(pin1, pin_entry_pin(), sizeof(pin1)) == 0;

        pin_entry_wipe();
        if (!same) {
            start_pin("PINs differ, try again", COL_ALERT);
            return;
        }
        busy(PHASE_SAVING, "saving...");
        return;
    }
    draw();
}

// A cancel here leaves the saved wallet locked. The status screen offers unlock.
static void pass_step(enum passphrase_entry_step s)
{
    if (s == PASSPHRASE_ENTRY_CANCEL) {
        leave();
        return;
    }
    if (s == PASSPHRASE_ENTRY_DONE) {
        busy(PHASE_OPEN, "opening...");
        return;
    }
    draw();
}

static void msg_ok(void)
{
    if (pending) {
        return;
    }
    if (msg_leaves) {
        leave();
    } else {
        show_words();
    }
}

static void setup_del(void)
{
    switch (phase) {
    case PHASE_CHOOSE:
        leave();
        break;
    case PHASE_COUNT:
        phase = PHASE_CHOOSE;
        sel = 0;
        draw();
        break;
    case PHASE_SHOW:
        if (page == 0) {
            leave();
            return;
        }
        page--;
        draw();
        break;
    case PHASE_QUIZ:
        show_words();
        break;
    case PHASE_SEED:
        seed_step(seed_entry_del());
        break;
    case PHASE_PIN:
        pin_step(pin_entry_del());
        break;
    case PHASE_PIN_AGAIN:
        pin_again_step(pin_entry_del());
        break;
    case PHASE_PASS:
        pass_step(passphrase_entry_del());
        break;
    case PHASE_MSG:
        msg_ok();
        break;
    default:
        break;
    }
}

static void setup_next(void)
{
    switch (phase) {
    case PHASE_CHOOSE:
    case PHASE_COUNT:
        sel ^= 1;
        draw();
        break;
    case PHASE_QUIZ:
        sel = (sel + 1) % QUIZ_CHOICES;
        draw();
        break;
    case PHASE_SEED:
        seed_step(seed_entry_next());
        break;
    case PHASE_PIN:
        pin_step(pin_entry_next());
        break;
    case PHASE_PIN_AGAIN:
        pin_again_step(pin_entry_next());
        break;
    case PHASE_PASS:
        pass_step(passphrase_entry_next());
        break;
    default:
        break;
    }
}

static void setup_ok(void)
{
    switch (phase) {
    case PHASE_CHOOSE:
        if (sel == 0) {
            phase = PHASE_COUNT;
            draw();
        } else {
            phase = PHASE_SEED;
            seed_entry_start("Restore");
            draw();
        }
        break;
    case PHASE_COUNT:
        total = sel ? 24 : 12;
        busy(PHASE_CREATING, "creating...");
        break;
    case PHASE_SHOW:
        show_ok();
        break;
    case PHASE_QUIZ:
        quiz_ok();
        break;
    case PHASE_SEED:
        seed_step(seed_entry_ok());
        break;
    case PHASE_PIN:
        pin_step(pin_entry_ok());
        break;
    case PHASE_PIN_AGAIN:
        pin_again_step(pin_entry_ok());
        break;
    case PHASE_PASS:
        pass_step(passphrase_entry_ok());
        break;
    case PHASE_MSG:
        msg_ok();
        break;
    default:
        break;
    }
}

// The status screen opens this only with no wallet.
// Checked again, because the state may have changed since.
static void setup_enter(void *arg)
{
    uint32_t state = BITCOIN_STATUS_NONE;
    uint32_t attempts = BITCOIN_ATTEMPTS_NA;

    (void)arg;

    wipe_all();
    started = false;
    pending = false;
    phase = PHASE_CHOOSE;
    sel = 0;
    if (bitcoin_core_status(bitcoin_core_session_production(), &state, &attempts) != PSA_SUCCESS ||
        state != BITCOIN_STATUS_NONE) {
        show_msg("wallet not empty", true);
        return;
    }
    draw();
}

static void setup_exit(void)
{
    if (started) {
        bitcoin_core_abort_setup(bitcoin_core_session_production());
        started = false;
    }
    wipe_all();
}

const display_screen_ops_t wallet_setup_screen = {
    .enter = setup_enter,
    .exit = setup_exit,
    .on_del = setup_del,
    .on_next = setup_next,
    .on_ok = setup_ok,
    .tick = setup_tick,
};
