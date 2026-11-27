// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

// BIP39 passphrase entry: the "No passphrase / Add passphrase" question, then the editor if needed.
// The caller owns the screen, clears the frame and calls passphrase_entry_draw().

enum passphrase_entry_step {
    PASSPHRASE_ENTRY_MORE,   // redraw
    PASSPHRASE_ENTRY_DONE,   // passphrase_entered() is set, "" for no passphrase
    PASSPHRASE_ENTRY_CANCEL, // the back key on the question
};

// Starts at the question. `title` is the header of the question.
void passphrase_entry_start(const char *title);

void passphrase_entry_draw(void);

enum passphrase_entry_step passphrase_entry_del(void);
enum passphrase_entry_step passphrase_entry_next(void);
enum passphrase_entry_step passphrase_entry_ok(void);

// The passphrase from the last finished entry, or NULL.
const char *passphrase_entered(void);

// Wipes the typed text and the passphrase.
void passphrase_clear(void);
