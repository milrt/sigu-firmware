// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// A BIP39 word from three keys and 2048 words.
// The next key offers only letters that still lead to a word, so no dead prefix can be typed.
// With four words or fewer left, the next key moves through the words instead.
// BIP39 words are unique in their first four letters, so this takes at most four letters.
//
// A word like "can" also starts eight others,
// so the letter cycle holds the word itself as a choice, shown as a check mark.
// After the letters come a backspace cell, only with a prefix, and a cancel cell.
// The back key moves back and wraps,
// so from the first letter one press reaches cancel and two reach backspace.
// In pick mode the back key removes a letter.

#pragma once

#include <stdbool.h>
#include <stdint.h>

// Starts at `word`, "" for none. `valid` has one bit per word to offer, NULL offers all.
void word_picker_start(const char *word, const uint8_t *valid);

// Draws the prefix, the wheel or the pick rows, and the soft keys.
// The caller clears the frame and draws the header.
void word_picker_draw(void);

// One step back. False if the prefix was already empty, so the caller decides what back does.
bool word_picker_del(void);

void word_picker_next(void);

enum word_picker_step {
    WORD_PICKER_MORE,  // a letter was added or removed
    WORD_PICKER_WORD,  // *word is set
    WORD_PICKER_LEAVE, // the cancel cell, the caller leaves the word
};

enum word_picker_step word_picker_ok(uint16_t *word);

void word_picker_wipe(void);
