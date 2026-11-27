// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

// PIN entry with three keys. One slot sits after the digits, which show as stars.
// The next key puts a digit in the slot, then counts it up.
// The select key adds the digit, and with a blank slot it confirms.
// The back key clears the slot, then removes digits, then cancels.
// The labels come from the same state as the actions, so each key says what it does.
//
// The caller owns the screen, clears the frame and calls pin_entry_draw().

#define PIN_ENTRY_MIN 4
#define PIN_ENTRY_MAX 12

enum pin_entry_step {
    PIN_ENTRY_MORE,   // redraw
    PIN_ENTRY_DONE,   // pin_entry_pin() is set
    PIN_ENTRY_CANCEL, // cancel with nothing typed, and the digits are wiped
};

// `note` is one line under the stars, or NULL. Both strings must live until the next start.
void pin_entry_start(const char *title, const char *note, uint16_t note_color);

void pin_entry_draw(void);

enum pin_entry_step pin_entry_del(void);
enum pin_entry_step pin_entry_next(void);
enum pin_entry_step pin_entry_ok(void);

// The PIN from the last finished entry, or NULL.
const char *pin_entry_pin(void);

void pin_entry_wipe(void);
