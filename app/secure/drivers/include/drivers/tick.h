// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

// Starts TIMER22. It raises TFM_TIMER22_IRQ_SIGNAL every `ms`.
void tick_start(uint32_t ms);

// Clears the tick event, so the IRQ does not fire again at once.
// Returns how many periods passed since the last call, at least 1.
// A tick that came late, because a long IPC call kept the thread, counts for all the time it took.
uint32_t tick_ack(void);
