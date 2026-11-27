// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// TIMER22 is a thread that raises TFM_TIMER22_IRQ_SIGNAL every `ms`.

#include "drivers/tick.h"
#include "sched.h"
#include "sim.h"
#include <psa_manifest/tfm_bitcoin_partition.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

static uint32_t period_ms;
// Set while "ticks <n>" runs. The control thread writes it, the SP thread reads it.
static atomic_bool in_burst;

static void tick_task(void *arg)
{
    (void)arg;
    for (;;) {
        sched_sleep_ms(period_ms);
        sim_ipc_irq(TFM_TIMER22_IRQ_SIGNAL);
    }
}

void tick_start(uint32_t ms)
{
    period_ms = ms;
    sched_start("tick", tick_task, NULL);
}

// The periods since the last call, by the host clock, at least 1.
// In a burst ("ticks <n>") each tick counts as one.
// A burst tick can take longer than a period (ASan), and the clock would then count it twice.
uint32_t tick_ack(void)
{
    static uint64_t last_ms;
    struct timespec ts;
    uint64_t now_ms;
    uint32_t n = 1;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    now_ms = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
    if (!atomic_load(&in_burst) && last_ms && period_ms && now_ms - last_ms >= 2 * period_ms) {
        n = (uint32_t)((now_ms - last_ms) / period_ms);
    }
    last_ms = now_ms;
    return n;
}

// The idle lock waits minutes.
// This runs `n` ticks back to back, each one handled before the next is raised,
// so a test does not wait that long. The tick thread keeps running too.
void sim_tick_burst(uint32_t n)
{
    atomic_store(&in_burst, true);
    while (n--) {
        sim_ipc_irq(TFM_TIMER22_IRQ_SIGNAL);
        sim_ipc_wait_ticks(1);
    }
    atomic_store(&in_burst, false);
}
