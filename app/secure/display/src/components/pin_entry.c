// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "components/pin_entry.h"
#include "core/display_priv.h"
#include "components/header.h"
#include "components/softkeys.h"
#include "shared/mem_util.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TEXT_X 12
#define MAIN_Y 44
#define NOTE_Y 84
#define HINT_Y 108
#define SLOT_BLANK (-1)

static const char *title;
static const char *note;
static uint16_t note_color;

static char digits[PIN_ENTRY_MAX + 1];
static size_t len;
// The digit in the slot, 0 to 9, or SLOT_BLANK.
static int8_t cur;
static bool finished;

const char *pin_entry_pin(void)
{
    return finished ? digits : NULL;
}

void pin_entry_wipe(void)
{
    mem_zeroize(digits, sizeof(digits));
    len = 0;
    cur = SLOT_BLANK;
    finished = false;
}

static bool can_finish(void)
{
    return cur == SLOT_BLANK && len >= PIN_ENTRY_MIN;
}

// "* * * 7" or "* * * _". A single text op, so the frame stays small.
static void draw_line(void)
{
    char line[2 * PIN_ENTRY_MAX + 2] = "";
    size_t at = 0;

    for (size_t i = 0; i < len; i++) {
        line[at++] = '*';
        line[at++] = ' ';
    }
    if (len < PIN_ENTRY_MAX || cur != SLOT_BLANK) {
        line[at++] = cur == SLOT_BLANK ? '_' : (char)('0' + cur);
    }
    line[at] = '\0';
    panel_draw_text(TEXT_X, MAIN_Y, line, &font_24, COL_INK);
    mem_zeroize(line, sizeof(line));
}

static const char *hint(void)
{
    if (cur != SLOT_BLANK) {
        return "OK adds it";
    }
    if (len >= PIN_ENTRY_MIN) {
        return "OK to confirm";
    }
    return len ? "at least 4 digits" : "NEXT picks a digit";
}

static const char *del_label(void)
{
    if (cur != SLOT_BLANK) {
        return "clear";
    }
    return len ? "del" : "cancel";
}

static const char *ok_label(void)
{
    if (cur != SLOT_BLANK) {
        return "add";
    }
    return can_finish() ? "done" : NULL;
}

void pin_entry_draw(void)
{
    header_draw(title, &font_16, COL_SURFACE, COL_MUTE);
    draw_line();
    if (note) {
        panel_draw_text(TEXT_X, NOTE_Y, note, &font_16, note_color);
    }
    panel_draw_text(TEXT_X, HINT_Y, hint(), &font_16, COL_MUTE);
    softkeys_set(del_label(), len < PIN_ENTRY_MAX ? "digit" : NULL, ok_label());
}

enum pin_entry_step pin_entry_del(void)
{
    if (cur != SLOT_BLANK) {
        cur = SLOT_BLANK;
    } else if (len > 0) {
        digits[--len] = '\0';
    } else {
        pin_entry_wipe();
        return PIN_ENTRY_CANCEL;
    }
    return PIN_ENTRY_MORE;
}

enum pin_entry_step pin_entry_next(void)
{
    if (len < PIN_ENTRY_MAX) {
        cur = cur == SLOT_BLANK ? 0 : (cur + 1) % 10;
    }
    return PIN_ENTRY_MORE;
}

enum pin_entry_step pin_entry_ok(void)
{
    if (cur != SLOT_BLANK && len < PIN_ENTRY_MAX) {
        digits[len++] = (char)('0' + cur);
        cur = SLOT_BLANK;
        return PIN_ENTRY_MORE;
    }
    if (can_finish()) {
        finished = true;
        return PIN_ENTRY_DONE;
    }
    return PIN_ENTRY_MORE;
}

void pin_entry_start(const char *t, const char *n, uint16_t color)
{
    pin_entry_wipe();
    title = t;
    note = n;
    note_color = color;
}
