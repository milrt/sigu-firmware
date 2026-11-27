// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "components/passphrase_entry.h"
#include "core/display_priv.h"
#include "components/header.h"
#include "components/list.h"
#include "components/softkeys.h"
#include "components/wheel.h"
#include "components/word_picker.h"
#include "shared/bitcoin_service_defs.h"
#include "shared/mem_util.h"
#include "bip39_wordlist.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TEXT_X 12
#define MAIN_Y 40
#define HINT_Y 100
#define ASK_HINT_Y (LIST_Y + 2 * LIST_STEP + 8)
#define MODE_Y 136
#define MODE_GAP 12
#define CARET_W 2
#define TEXT_W (PANEL_W - 2 * TEXT_X - CARET_W - 1)
// The edit cells, then space and the 32 ASCII punctuation chars.
#define CELLS_MAX 39

enum mode {
    MODE_LOWER,
    MODE_UPPER,
    MODE_DIGIT,
    MODE_SYMBOL,
    MODE_WORD,
    MODE_COUNT,
};

static const char *const mode_name[MODE_COUNT] = {"abc", "ABC", "123", "!@#", "word"};

static const char *const mode_set[MODE_WORD] = {
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
    " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
};

// The wheel opens on the mode cell.
// So the select key first reads "mode", and each press moves to the next mode.
// The cursor and edit cells sit to its left.
static const char edit_cells[] = {WHEEL_LEFT,   WHEEL_RIGHT, WHEEL_DEL,
                                  WHEEL_CANCEL, WHEEL_DONE,  WHEEL_MODE};

static const char *const ask_labels[] = {"No passphrase", "Add passphrase"};

static const char *title;
// The question is on screen, not the editor.
static bool asking;
static uint8_t ask_sel;

static char text[BITCOIN_PASSPHRASE_MAX_SIZE];
static size_t len;
// Chars go in at text[cursor], 0 to len.
static size_t cursor;
static enum mode mode;
static char cells[CELLS_MAX];
static uint8_t ncells;
static uint8_t sel;
// The word picker has the keys.
static bool picking;

static bool finished;
static char entered[BITCOIN_PASSPHRASE_MAX_SIZE];

const char *passphrase_entered(void)
{
    return finished ? entered : NULL;
}

static void wipe_work(void)
{
    word_picker_wipe();
    mem_zeroize(text, sizeof(text));
    len = 0;
    cursor = 0;
    sel = 0;
    picking = false;
}

void passphrase_clear(void)
{
    wipe_work();
    mem_zeroize(entered, sizeof(entered));
    finished = false;
}

static void set_mode(enum mode m)
{
    size_t n;

    mode = m;
    sel = 0;
    ncells = 0;
    if (m == MODE_WORD) {
        return;
    }
    n = strlen(mode_set[m]);
    memcpy(cells, edit_cells, sizeof(edit_cells));
    memcpy(&cells[sizeof(edit_cells)], mode_set[m], n);
    ncells = sizeof(edit_cells) + n;
    sel = sizeof(edit_cells) - 1;
}

// Fills `view` with text[from, to) and returns its width.
static int span(char *view, size_t from, size_t to)
{
    memcpy(view, &text[from], to - from);
    view[to - from] = '\0';
    return panel_text_width(view, &font_24);
}

// Two more ops. With the worst wheel window the frame is 32 of the panel's 40.
static void draw_scroll_hint(size_t start, size_t end)
{
    int y = MAIN_Y + font_24.line_height;

    if (start > 0) {
        panel_draw_text(TEXT_X, y, "<", &font_16, COL_MUTE);
    }
    if (end < len) {
        panel_draw_text(PANEL_W - TEXT_X - panel_text_width(">", &font_16), y, ">", &font_16,
                        COL_MUTE);
    }
}

// The window always holds the cursor.
// It starts as far left as the text before the cursor allows,
// and it ends at TEXT_W, so text never reaches the edge.
static void draw_text(void)
{
    char view[sizeof(text)];
    size_t start = 0;
    size_t end = cursor;
    int caret;

    while (span(view, start, cursor) > TEXT_W) {
        start++;
    }
    caret = span(view, start, cursor);
    while (end < len && span(view, start, end + 1) <= TEXT_W) {
        end++;
    }
    span(view, start, end);
    panel_draw_text(TEXT_X, MAIN_Y, view, &font_24, COL_INK);
    panel_fill_rect(TEXT_X + caret + 1, MAIN_Y + 2, CARET_W, font_24.line_height - 4, COL_INK);
    mem_zeroize(view, sizeof(view));
    draw_scroll_hint(start, end);
}

static void draw_modes(void)
{
    int x = TEXT_X;

    for (enum mode m = 0; m < MODE_COUNT; m++) {
        panel_draw_text(x, MODE_Y, mode_name[m], &font_16, m == mode ? COL_INK : COL_MUTE);
        x += panel_text_width(mode_name[m], &font_16) + MODE_GAP;
    }
}

static const char *ok_label(void)
{
    if (mode == MODE_WORD) {
        return "pick";
    }
    switch (cells[sel]) {
    case WHEEL_LEFT:
        return "left";
    case WHEEL_RIGHT:
        return "right";
    case WHEEL_DEL:
        return "del";
    case WHEEL_CANCEL:
        return "cancel";
    case WHEEL_DONE:
        return "done";
    case WHEEL_MODE:
        return "mode";
    default:
        return "add";
    }
}

static void draw_ask(void)
{
    header_draw(title, &font_16, COL_SURFACE, COL_MUTE);
    list_draw(ask_labels, 2, ask_sel);
    panel_draw_text(TEXT_X, ASK_HINT_Y, "it changes the wallet", &font_16, COL_MUTE);
    softkeys_set("cancel", "next", "ok");
}

static void draw_typing(void)
{
    header_draw("Passphrase", &font_16, COL_SURFACE, COL_MUTE);
    draw_text();
    draw_modes();
    if (mode == MODE_WORD) {
        panel_draw_text(TEXT_X, HINT_Y, "pick a BIP39 word", &font_16, COL_MUTE);
    } else {
        wheel_draw(cells, ncells, sel);
    }
    softkeys_set(mode == MODE_WORD && len > 0 ? "del" : "back", "next", ok_label());
}

void passphrase_entry_draw(void)
{
    if (asking) {
        draw_ask();
    } else if (picking) {
        header_draw("Passphrase word", &font_16, COL_SURFACE, COL_MUTE);
        word_picker_draw();
    } else {
        draw_typing();
    }
}

// Inserts all of `s` or nothing, so a word is never cut. The memmove carries the NUL along.
static void insert(const char *s)
{
    size_t n = strlen(s);

    if (len + n >= sizeof(text)) {
        return;
    }
    memmove(&text[cursor + n], &text[cursor], len - cursor + 1);
    memcpy(&text[cursor], s, n);
    len += n;
    cursor += n;
}

// The moved NUL also clears the old last byte.
static void backspace(void)
{
    if (cursor == 0) {
        return;
    }
    memmove(&text[cursor - 1], &text[cursor], len - cursor + 1);
    len--;
    cursor--;
}

static enum passphrase_entry_step finish(void)
{
    memcpy(entered, text, sizeof(entered));
    finished = true;
    wipe_work();
    return PASSPHRASE_ENTRY_DONE;
}

// Back to the question. No passphrase is chosen yet.
static void ask(void)
{
    passphrase_clear();
    asking = true;
    ask_sel = 0;
}

static void pick_ok(void)
{
    uint16_t w;
    enum word_picker_step step = word_picker_ok(&w);

    if (step == WORD_PICKER_MORE) {
        return;
    }
    if (step == WORD_PICKER_WORD) {
        insert(bip39_wordlist_en[w]);
        set_mode(MODE_LOWER);
    }
    word_picker_wipe();
    picking = false;
}

enum passphrase_entry_step passphrase_entry_del(void)
{
    if (asking) {
        passphrase_clear();
        return PASSPHRASE_ENTRY_CANCEL;
    }
    if (picking) {
        if (!word_picker_del()) {
            word_picker_wipe();
            picking = false;
        }
    } else if (mode != MODE_WORD) {
        sel = (sel + ncells - 1) % ncells;
    } else if (len > 0) {
        backspace();
    } else {
        ask();
    }
    return PASSPHRASE_ENTRY_MORE;
}

enum passphrase_entry_step passphrase_entry_next(void)
{
    if (asking) {
        ask_sel ^= 1;
    } else if (picking) {
        word_picker_next();
    } else if (mode == MODE_WORD) {
        set_mode(MODE_LOWER);
    } else {
        sel = (sel + 1) % ncells;
    }
    return PASSPHRASE_ENTRY_MORE;
}

static enum passphrase_entry_step ask_ok(void)
{
    if (ask_sel == 0) {
        return finish();
    }
    asking = false;
    wipe_work();
    set_mode(MODE_LOWER);
    return PASSPHRASE_ENTRY_MORE;
}

enum passphrase_entry_step passphrase_entry_ok(void)
{
    char c[2] = {cells[sel], '\0'};

    if (asking) {
        return ask_ok();
    }
    if (picking) {
        pick_ok();
    } else if (mode == MODE_WORD) {
        picking = true;
        word_picker_start("", NULL);
    } else if (c[0] == WHEEL_LEFT) {
        if (cursor > 0) {
            cursor--;
        }
    } else if (c[0] == WHEEL_RIGHT) {
        if (cursor < len) {
            cursor++;
        }
    } else if (c[0] == WHEEL_DEL) {
        backspace();
    } else if (c[0] == WHEEL_CANCEL) {
        ask();
    } else if (c[0] == WHEEL_MODE) {
        set_mode(mode + 1);
    } else if (c[0] == WHEEL_DONE) {
        return finish();
    } else {
        insert(c);
    }
    return PASSPHRASE_ENTRY_MORE;
}

void passphrase_entry_start(const char *t)
{
    title = t;
    ask();
}
