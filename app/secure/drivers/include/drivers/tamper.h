// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>

// Keeps the glitch detector on and locks the TAMPC detectors and the tamper reset until reset.
void tamper_init(void);

// True when the glitch detector is on and every detector tamper_init() locks is on and locked.
bool tamper_ok(void);
