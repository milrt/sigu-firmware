// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "components/seed_entry.h"
#include "core/display_priv.h"
#include "components/header.h"
#include "components/list.h"
#include "components/softkeys.h"
#include "components/word_picker.h"
#include "shared/hash.h"
#include "shared/mem_util.h"
#include "core/text.h"
#include "bip39_wordlist.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define WORDS_MAX 24
#define WORD_LEN_MAX 8
#define TEXT_X 12
#define MAIN_Y 40
#define ROW_Y 72
#define ROW_STEP 24

enum phase {
    PHASE_COUNT,
    PHASE_WORD,
    PHASE_REVIEW,
};

static const char *title;
static enum phase phase;
static uint8_t total;
static uint8_t pos;
// WORD was entered from REVIEW. Accepting goes back to REVIEW at the same word.
static bool editing;
static bool bad_checksum;

static uint16_t idx[WORDS_MAX];
// Checksum-valid last words, one bit per word. It derives from the seed.
static uint8_t valid[BIP39_WORDLIST_EN_SIZE / 8];

static bool finished;
static char mnemonic[WORDS_MAX * (WORD_LEN_MAX + 1)];

const char *seed_entry_mnemonic(void)
{
    return finished ? mnemonic : NULL;
}

static void wipe_work(void)
{
    word_picker_wipe();
    mem_zeroize(idx, sizeof(idx));
    mem_zeroize(valid, sizeof(valid));
    pos = 0;
}

void seed_entry_clear(void)
{
    wipe_work();
    mem_zeroize(mnemonic, sizeof(mnemonic));
    finished = false;
}

// The last n/3 bits of the 11n bit stream are the checksum,
// and they are the low bits of the last index. The rest is the entropy that SHA-256 covers.
// The last word is `last`, not idx[], and its low bits do not change the result.
static bool checksum_of(uint16_t last, uint8_t *cs)
{
    uint8_t bits[WORDS_MAX * 11 / 8 + 1] = {0};
    uint8_t hash[32] = {0};
    size_t ent_bytes = (size_t)total * 4 / 3;
    unsigned int cs_bits = total / 3;
    bool ok;

    for (size_t i = 0; i < total; i++) {
        uint16_t v = i + 1 < total ? idx[i] : last;

        for (int b = 10; b >= 0; b--) {
            size_t at = i * 11 + (10 - b);

            if (v & (1U << b)) {
                bits[at / 8] |= 0x80 >> (at % 8);
            }
        }
    }

    ok = hash_sha256(bits, ent_bytes, hash, sizeof(hash)) == PSA_SUCCESS;
    *cs = hash[0] >> (8 - cs_bits);

    mem_zeroize(bits, sizeof(bits));
    mem_zeroize(hash, sizeof(hash));
    return ok;
}

static bool checksum_ok(void)
{
    uint16_t last = idx[total - 1];
    uint8_t cs;

    return checksum_of(last, &cs) && cs == (last & ((1U << (total / 3)) - 1));
}

// Each value of the high entropy bits of the last word gives exactly one valid word.
// That is 128 of 2048 words for 12 words, and 8 for 24.
static void build_valid(void)
{
    unsigned int cs_bits = total / 3;

    mem_zeroize(valid, sizeof(valid));
    for (uint16_t w = 0; w < BIP39_WORDLIST_EN_SIZE; w += 1U << cs_bits) {
        uint8_t cs;

        if (checksum_of(w, &cs)) {
            valid[(w | cs) / 8] |= 1U << ((w | cs) % 8);
        }
    }
}

// The last word offers only checksum-valid words.
static void start_word(const char *w)
{
    word_picker_start(w, pos + 1 == total ? valid : NULL);
}

static void set_row(int i, const char *text, const font_t *font, uint16_t color)
{
    panel_draw_text(TEXT_X, ROW_Y + i * ROW_STEP, text, font, color);
}

static void set_main(const char *text)
{
    panel_draw_text(TEXT_X, MAIN_Y, text, &font_24, COL_INK);
}

static void set_header(const char *what, uint8_t n)
{
    char text[24] = "";
    size_t len = 0;

    text_add(text, sizeof(text), &len, what);
    text_add(text, sizeof(text), &len, " ");
    text_add_u32(text, sizeof(text), &len, n);
    text_add(text, sizeof(text), &len, " / ");
    text_add_u32(text, sizeof(text), &len, total);
    header_draw(text, &font_16, COL_SURFACE, COL_MUTE);
}

static void draw_count(void)
{
    static const char *const counts[] = {"12 words", "24 words"};

    header_draw(title, &font_16, COL_SURFACE, COL_MUTE);
    list_draw(counts, 2, total == 24);
    softkeys_set("cancel", "next", "ok");
}

static void draw_word(void)
{
    set_header("Word", pos + 1);
    word_picker_draw();
}

static void draw_review(void)
{
    set_header("Check", pos + 1);
    set_main(bip39_wordlist_en[idx[pos]]);
    if (bad_checksum) {
        set_row(0, "checksum wrong", &font_20, COL_ALERT);
        set_row(1, "edit the wrong word", &font_16, COL_MUTE);
    } else {
        set_row(0, "same as on paper?", &font_16, COL_MUTE);
    }
    softkeys_set("edit", NULL, pos + 1 == total ? "done" : "ok");
}

void seed_entry_draw(void)
{
    switch (phase) {
    case PHASE_COUNT:
        draw_count();
        break;
    case PHASE_WORD:
        draw_word();
        break;
    case PHASE_REVIEW:
        draw_review();
        break;
    }
}

static void load_word(uint8_t i)
{
    const char *w = bip39_wordlist_en[idx[i]];

    pos = i;
    if (pos + 1 == total) {
        build_valid();
    }
    start_word(w);
}

static void build_mnemonic(void)
{
    size_t at = 0;

    for (uint8_t i = 0; i < total; i++) {
        const char *w = bip39_wordlist_en[idx[i]];
        size_t n = strlen(w);

        if (i) {
            mnemonic[at++] = ' ';
        }
        memcpy(&mnemonic[at], w, n);
        at += n;
    }
    mnemonic[at] = '\0';
}

static enum seed_entry_step finish(void)
{
    if (!checksum_ok()) {
        bad_checksum = true;
        pos = 0;
        return SEED_ENTRY_MORE;
    }

    build_mnemonic();
    wipe_work();
    finished = true;
    return SEED_ENTRY_DONE;
}

static enum seed_entry_step cancel(void)
{
    seed_entry_clear();
    return SEED_ENTRY_CANCEL;
}

// The check and the count page draw no picker, so its letters are wiped there.
static void accept(uint16_t word)
{
    idx[pos] = word;
    if (editing) {
        editing = false;
        bad_checksum = false;
        phase = PHASE_REVIEW;
        word_picker_wipe();
    } else if (++pos == total) {
        pos = 0;
        phase = PHASE_REVIEW;
        word_picker_wipe();
    } else {
        // start_word() sets the filter from pos, so pos moves first.
        if (pos + 1 == total) {
            build_valid();
        }
        start_word("");
    }
}

static void leave_word(void)
{
    if (editing) {
        editing = false;
        phase = PHASE_REVIEW;
        word_picker_wipe();
    } else if (pos > 0) {
        load_word(pos - 1);
    } else {
        phase = PHASE_COUNT;
        word_picker_wipe();
    }
}

static enum seed_entry_step word_ok(void)
{
    uint16_t w;

    switch (word_picker_ok(&w)) {
    case WORD_PICKER_WORD:
        accept(w);
        break;
    case WORD_PICKER_LEAVE:
        return cancel();
    case WORD_PICKER_MORE:
        break;
    }
    return SEED_ENTRY_MORE;
}

enum seed_entry_step seed_entry_del(void)
{
    switch (phase) {
    case PHASE_COUNT:
        return cancel();
    case PHASE_WORD:
        if (!word_picker_del()) {
            leave_word();
        }
        break;
    case PHASE_REVIEW:
        editing = true;
        phase = PHASE_WORD;
        load_word(pos);
        break;
    }
    return SEED_ENTRY_MORE;
}

enum seed_entry_step seed_entry_next(void)
{
    switch (phase) {
    case PHASE_COUNT:
        total = total == 12 ? 24 : 12;
        break;
    case PHASE_WORD:
        word_picker_next();
        break;
    case PHASE_REVIEW:
        break;
    }
    return SEED_ENTRY_MORE;
}

enum seed_entry_step seed_entry_ok(void)
{
    switch (phase) {
    case PHASE_COUNT:
        phase = PHASE_WORD;
        pos = 0;
        start_word("");
        break;
    case PHASE_WORD:
        return word_ok();
    case PHASE_REVIEW:
        if (pos + 1 < total) {
            pos++;
            bad_checksum = false;
        } else {
            return finish();
        }
        break;
    }
    return SEED_ENTRY_MORE;
}

void seed_entry_start(const char *t)
{
    seed_entry_clear();
    title = t;
    phase = PHASE_COUNT;
    total = 12;
    editing = false;
    bad_checksum = false;
}
