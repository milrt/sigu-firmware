// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The panel, as the partition's main loop sees it.
// The screens and the coordinator are in display/src.

#pragma once

#include <stdint.h>

// Turns on the panel and the keys, shows the status screen and starts the TIMER22 tick.
void display_init(void);

// One 20 ms step: clears the tick event, reads the keys, runs the screen, flushes the panel.
void display_tick(void);

// NS reported the firmware state (BITCOIN_FW_*).
// A state that is not FAILED clears the seen bit of the failed install line,
// so the next rollback shows it again.
void display_fw_state(uint8_t status);
