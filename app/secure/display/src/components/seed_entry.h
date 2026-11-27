// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

// BIP39 seed entry: the word count, each word, then a check of every word.
// The caller owns the screen, clears the frame and calls seed_entry_draw().
//
// The last word offers only words with a valid checksum, built when the last word starts.
// If none matches the prefix, the full list shows, and the check still tests the checksum.

enum seed_entry_step {
    SEED_ENTRY_MORE,   // redraw
    SEED_ENTRY_DONE,   // seed_entry_mnemonic() is set
    SEED_ENTRY_CANCEL, // the user left, and the words are wiped
};

// Starts at the word count. `title` is the header of that first page.
void seed_entry_start(const char *title);

void seed_entry_draw(void);

enum seed_entry_step seed_entry_del(void);
enum seed_entry_step seed_entry_next(void);
enum seed_entry_step seed_entry_ok(void);

// The mnemonic from the last finished entry, words joined by one space, or NULL.
const char *seed_entry_mnemonic(void);

// Wipes the entered words and the mnemonic.
void seed_entry_clear(void);
