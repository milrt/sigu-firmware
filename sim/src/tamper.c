// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The host has no glitch detector and no TAMPC.

#include "drivers/tamper.h"

void tamper_init(void)
{
}

bool tamper_ok(void)
{
    return true;
}
