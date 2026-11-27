// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The firmware's panel.c, unchanged, plus one reader for the tests:
// the text of the frame the panel shows now.
// It includes the .c to reach the static frame, as the fuzz targets do.

#include "../../app/secure/drivers/src/panel.c"
#include "sim.h"
#include <stdio.h>

// Each text op of the frame on the panel, in draw order, joined with " | ".
// A wrapped line is one op.
// "!overflow" stands for a frame that did not fit, which the panel shows all red.
void sim_panel_text(char *out, size_t size)
{
    size_t len = 0;

    out[0] = '\0';
    if (!sent_valid) {
        return;
    }
    if (sent.overflow) {
        snprintf(out, size, "!overflow");
        return;
    }
    for (size_t i = 0; i < sent.nops && len + 1 < size; i++) {
        if (sent.ops[i].kind == OP_TEXT) {
            len += (size_t)snprintf(out + len, size - len, "%s%s", len ? " | " : "",
                                    &sent.text[sent.ops[i].text]);
        }
    }
}
