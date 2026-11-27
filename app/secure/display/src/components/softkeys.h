// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

// Without the bar's top row.
#define SOFTKEYS_HEIGHT 42

// Draws the bar and the labels of the back, next and select keys. NULL or "" leaves a key blank.
// Every frame with a bar calls it once.
void softkeys_set(const char *del, const char *next, const char *ok);

// The same, with the select key on an amber tile.
// Only the review screen uses it, for the press that signs.
void softkeys_set_sign(const char *del, const char *next, const char *ok);
