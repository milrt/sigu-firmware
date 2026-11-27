// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// sigu-sim in a web page. The SP, the tick, the NS card thread and the control loop are fibers.
// main() runs them, draws a frame, and gives the browser a turn with emscripten_sleep().
// The page keeps /sigu (the wallet and the card) in IndexedDB.
// Without a canvas (node), it runs headless, for tests.

#include "sched.h"
#include "sim.h"
#include <SDL.h>
#include <emscripten.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define QUEUE_MAX 32
#define LINE_MAX_LEN 512
#define FRAME_MS 16
#define RUN_BUDGET_MS 12

static char queue[QUEUE_MAX][LINE_MAX_LEN];
static unsigned q_head;
static unsigned q_tail;

// Called by the page. The control fiber runs the command, so it may wait.
EMSCRIPTEN_KEEPALIVE int sim_web_command(const char *line)
{
    if (q_tail - q_head == QUEUE_MAX) {
        return 0;
    }
    snprintf(queue[q_tail++ % QUEUE_MAX], LINE_MAX_LEN, "%s", line);
    sched_wake();
    return 1;
}

static void control_task(void *arg)
{
    char line[LINE_MAX_LEN];

    (void)arg;
    for (;;) {
        sched_lock();
        while (q_head == q_tail) {
            sched_wait();
        }
        memcpy(line, queue[q_head++ % QUEUE_MAX], sizeof(line));
        sched_unlock();
        if (!sim_control_line(line)) {
            printf("ok\n");
        }
    }
}

int main(void)
{
    bool window;

    mkdir("/sigu", 0700);
    mkdir("/sigu/card", 0700);
    if (!sim_ps_init("/sigu/ps") || !sim_card_init("/sigu/card", true)) {
        fprintf(stderr, "[SIM] cannot open /sigu\n");
        return 1;
    }
    fprintf(stderr, "[SIM] SIMULATOR. The wallet is stored in this browser. "
                    "Do not use it for real funds.\n");
    if (psa_crypto_init() != PSA_SUCCESS) {
        fprintf(stderr, "[SIM] psa_crypto_init failed\n");
        return 1;
    }

    sim_start();
    sched_start("control", control_task, NULL);

    window = EM_ASM_INT({ return typeof document != 'undefined'; }) && sim_window_open(1);
    // The page reads stdout. Commands sent before this line are kept anyway.
    printf("ready\n");
    fflush(stdout);
    for (;;) {
        sched_run(RUN_BUDGET_MS);
        if (window) {
            sim_window_frame();
        }
        emscripten_sleep(window ? FRAME_MS - RUN_BUDGET_MS : 1);
    }
}
