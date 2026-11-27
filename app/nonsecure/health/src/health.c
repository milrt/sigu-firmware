// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/bitcoin_client.h"
#include <stdbool.h>
#include <stdint.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/drivers/watchdog.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(health);

// The watchdog and the install confirm.
// This thread runs at the lowest priority and feeds WDT31 after each status call to the partition.
// A spinning NS thread starves it, and so does a hung partition, which runs above NS.
// Then WDT31 resets the chip.
//
// MCUboot boots a new app as a test.
// This thread confirms it after CONFIRM_ROUNDS, once a status call has read PS.
// A reset before that, from a fault or from WDT31, makes MCUboot swap the old app back.
//
// The feed does not need a good status. Otherwise a PS error would reset the chip on every boot.
// SIGU_WATCHDOG_TIMEOUT_MS must be longer than the longest partition call.

#define FEED_MS 1000
#define CONFIRM_ROUNDS 10

#define STACK_SIZE 2048
#define PRIORITY K_LOWEST_APPLICATION_THREAD_PRIO

static const struct device *const wdt = DEVICE_DT_GET(DT_ALIAS(watchdog0));

// The channel, or -1 without a watchdog.
static int wdt_start(void)
{
    struct wdt_timeout_cfg cfg = {
        .window = {.min = 0, .max = CONFIG_SIGU_WATCHDOG_TIMEOUT_MS},
        .flags = WDT_FLAG_RESET_SOC,
    };
    int channel;

    if (!device_is_ready(wdt)) {
        LOG_ERR("watchdog not ready");
        return -1;
    }
    channel = wdt_install_timeout(wdt, &cfg);
    if (channel < 0 || wdt_setup(wdt, WDT_OPT_PAUSE_HALTED_BY_DBG) != 0) {
        LOG_ERR("watchdog setup failed");
        return -1;
    }
    return channel;
}

// Confirms the running app if MCUboot booted it as a test.
// Not boot_write_img_confirmed():
// it opens zephyr,code-partition, which is slot0_ns here, not slot0.
static bool confirm(void)
{
    if (mcuboot_swap_type_multi(0) != BOOT_SWAP_TYPE_REVERT) {
        return true;
    }
    if (boot_write_img_confirmed_multi(0) != 0 ||
        mcuboot_swap_type_multi(0) == BOOT_SWAP_TYPE_REVERT) {
        LOG_ERR("cannot confirm the install");
        return false;
    }
    LOG_INF("install confirmed");
    return true;
}

static void health_thread(void *a, void *b, void *c)
{
    int channel = wdt_start();
    uint32_t rounds = 0;
    bool confirmed = false;

    ARG_UNUSED(a);
    ARG_UNUSED(b);
    ARG_UNUSED(c);

    for (;;) {
        uint32_t state;
        uint32_t attempts;
        psa_status_t status = bitcoin_client_status(&state, &attempts);

        if (channel >= 0) {
            wdt_feed(wdt, channel);
        }
        if (!confirmed && ++rounds >= CONFIRM_ROUNDS && status == PSA_SUCCESS) {
            confirmed = confirm();
        }
        k_msleep(FEED_MS);
    }
}

K_THREAD_DEFINE(health, STACK_SIZE, health_thread, NULL, NULL, NULL, PRIORITY, 0, 0);
