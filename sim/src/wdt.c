// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// WDT31 in the sim. NS sets it up and feeds it.
// It never resets, and the first feed is logged once,
// so a test can see that the health thread runs.

#include <stdbool.h>
#include <stdio.h>
#include <zephyr/drivers/watchdog.h>

const struct device sim_wdt = {.name = "wdt31"};

static bool fed;

int wdt_install_timeout(const struct device *dev, const struct wdt_timeout_cfg *cfg)
{
    (void)dev;
    return cfg->window.max > 0 ? 0 : -1;
}

int wdt_setup(const struct device *dev, uint8_t options)
{
    (void)dev;
    (void)options;
    return 0;
}

int wdt_feed(const struct device *dev, int channel_id)
{
    (void)dev;
    (void)channel_id;
    if (!fed) {
        fed = true;
        fprintf(stderr, "[SIM] watchdog fed\n");
    }
    return 0;
}
