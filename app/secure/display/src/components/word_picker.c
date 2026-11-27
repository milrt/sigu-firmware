// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "components/word_picker.h"
#include "components/softkeys.h"
#include "components/wheel.h"
#include "core/display_priv.h"
#include "shared/mem_util.h"
#include "bip39_wordlist.h"
#include <stddef.h>
#include <string.h>

#define WORD_LEN_MAX 8
#define PICK_MAX 4
#define ROWS PICK_MAX
#define TEXT_X 12
#define MAIN_Y 40
#define ROW_Y 72
#define ROW_STEP 24
// Pick rows look like list rows: a fill on the selected one, and the text indented.
#define PICK_X 18
#define FILL_X 6
#define FILL_UP 1
// A choice is a letter, '\0' for the prefix as a word, WHEEL_DEL or WHEEL_CANCEL.
#define CHOICES_MAX 29

static char prefix[WORD_LEN_MAX + 1];
static size_t plen;
static uint16_t lo;
static uint16_t hi;
static char choices[CHOICES_MAX];
static uint8_t nchoices;
static uint8_t sel;
static const uint8_t *valid;
// valid[] limits [lo, hi). nwords counts the words offered there.
static bool filter;
static uint16_t nwords;

void word_picker_wipe(void)
{
    mem_zeroize(prefix, sizeof(prefix));
    mem_zeroize(choices, sizeof(choices));
    valid = NULL;
    filter = false;
    nwords = 0;
    plen = 0;
    lo = 0;
    hi = 0;
    nchoices = 0;
    sel = 0;
}

// [lo, hi) of the words that start with the first n chars of p.
// The list is sorted, so two lower-bound searches are enough.
static uint16_t bound(const char *p, size_t n, bool upper)
{
    uint16_t l = 0;
    uint16_t h = BIP39_WORDLIST_EN_SIZE;

    while (l < h) {
        uint16_t mid = l + (h - l) / 2;
        int cmp = strncmp(bip39_wordlist_en[mid], p, n);

        if (cmp < 0 || (upper && cmp == 0)) {
            l = mid + 1;
        } else {
            h = mid;
        }
    }
    return l;
}

static void find_range(const char *p, size_t n, uint16_t *l, uint16_t *h)
{
    *l = bound(p, n, false);
    *h = bound(p, n, true);
}

static bool offered(uint16_t w)
{
    return !filter || (valid[w / 8] >> (w % 8)) & 1U;
}

static uint16_t nth_word(uint16_t k)
{
    for (uint16_t w = lo; w < hi; w++) {
        if (offered(w) && k-- == 0) {
            return w;
        }
    }
    return lo;
}

static uint16_t count_offered(void)
{
    uint16_t n = 0;

    for (uint16_t w = lo; w < hi; w++) {
        n += offered(w);
    }
    return n;
}

static bool picking(void)
{
    return nwords <= PICK_MAX;
}

// A word equal to the prefix sorts first and yields '\0'.
// Sorting also keeps equal letters next to each other, so comparing with the last one is enough.
static void collect_choices(void)
{
    nchoices = 0;
    for (uint16_t i = lo; i < hi; i++) {
        char c = bip39_wordlist_en[i][plen];

        if (!offered(i)) {
            continue;
        }
        if (nchoices == 0 || choices[nchoices - 1] != c) {
            choices[nchoices++] = c;
        }
    }
    if (plen > 0) {
        choices[nchoices++] = WHEEL_DEL;
    }
    choices[nchoices++] = WHEEL_CANCEL;
}

// `p` may be `prefix` itself, so this uses memmove.
static void set_prefix(const char *p, size_t n)
{
    memmove(prefix, p, n);
    prefix[n] = '\0';
    plen = n;
    find_range(prefix, plen, &lo, &hi);
    filter = valid != NULL;
    nwords = count_offered();
    // No valid word in range: a hash error, or an old invalid last word loaded for editing.
    // Show the full list so the screen cannot dead-end.
    if (filter && nwords == 0) {
        filter = false;
        nwords = hi - lo;
    }
    collect_choices();
    sel = 0;
}

void word_picker_start(const char *word, const uint8_t *v)
{
    valid = v;
    set_prefix(word, strlen(word));
}

static void set_row(int i, const char *text, const font_t *font, uint16_t color)
{
    panel_draw_text(TEXT_X, ROW_Y + i * ROW_STEP, text, font, color);
}

// The words the select key would lead to: the next prefix with the chosen letter,
// or only the word when the choice is the prefix itself.
static void draw_preview(char c)
{
    char next[WORD_LEN_MAX + 1];
    uint16_t l;
    uint16_t h;
    int i = 0;

    if (c == '\0') {
        set_row(0, prefix, &font_20, COL_INK);
        return;
    }

    memcpy(next, prefix, plen);
    next[plen] = c;
    find_range(next, plen + 1, &l, &h);

    for (uint16_t w = l; w < h && i < ROWS; w++) {
        if (offered(w)) {
            set_row(i++, bip39_wordlist_en[w], &font_16, COL_MUTE);
        }
    }
    mem_zeroize(next, sizeof(next));
}

static const char *ok_label(char c)
{
    switch (c) {
    case '\0':
        return "ok";
    case WHEEL_DEL:
        return "del";
    case WHEEL_CANCEL:
        return "cancel";
    default:
        return "add";
    }
}

static void draw_letters(void)
{
    char c = choices[sel];

    wheel_draw(choices, nchoices, sel);
    if (c != WHEEL_DEL && c != WHEEL_CANCEL) {
        draw_preview(c);
    }
    softkeys_set("back", "next", ok_label(c));
}

static void draw_pick(void)
{
    for (uint16_t i = 0; i < nwords; i++) {
        bool on = i == sel;
        int y = ROW_Y + i * ROW_STEP;

        if (on) {
            panel_fill_rect(FILL_X, y - FILL_UP, PANEL_W - 2 * FILL_X, ROW_STEP, COL_SELECT);
        }
        panel_draw_text(PICK_X, y, bip39_wordlist_en[nth_word(i)], on ? &font_20 : &font_16,
                        on ? COL_INK : COL_MUTE);
    }
    softkeys_set("del", nwords > 1 ? "next" : NULL, "ok");
}

void word_picker_draw(void)
{
    panel_draw_text(TEXT_X, MAIN_Y, prefix, &font_24, COL_INK);
    if (picking()) {
        draw_pick();
    } else {
        draw_letters();
    }
}

bool word_picker_del(void)
{
    if (!picking()) {
        sel = (sel + nchoices - 1) % nchoices;
        return true;
    }
    if (plen == 0) {
        return false;
    }
    set_prefix(prefix, plen - 1);
    return true;
}

void word_picker_next(void)
{
    if (picking()) {
        sel = (sel + 1) % nwords;
    } else {
        sel = (sel + 1) % nchoices;
    }
}

enum word_picker_step word_picker_ok(uint16_t *word)
{
    char c = choices[sel];

    if (picking()) {
        *word = nth_word(sel);
        return WORD_PICKER_WORD;
    }
    switch (c) {
    case '\0':
        *word = lo;
        return WORD_PICKER_WORD;
    case WHEEL_DEL:
        // Stay on backspace while it is there, so more presses delete more letters.
        set_prefix(prefix, plen - 1);
        if (plen > 0) {
            sel = nchoices - 2;
        }
        return WORD_PICKER_MORE;
    case WHEEL_CANCEL:
        return WORD_PICKER_LEAVE;
    default:
        prefix[plen] = c;
        set_prefix(prefix, plen + 1);
        return WORD_PICKER_MORE;
    }
}
