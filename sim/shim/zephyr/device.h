// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The one device NS gets from the devicetree: the watchdog, in sim/src/wdt.c.

#pragma once

#include <stdbool.h>

struct device {
    const char *name;
};

extern const struct device sim_wdt;

#define DEVICE_DT_GET(node) (&sim_wdt)

static inline bool device_is_ready(const struct device *dev)
{
    return dev != NULL;
}
