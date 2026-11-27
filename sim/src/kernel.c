// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The Zephyr kernel calls NS makes: sleep and the threads K_THREAD_DEFINE declares.
// Also the boot order of the SP and NS. The PSBT heap is in heap.c.

#include "sched.h"
#include "sim.h"
#include <zephyr/kernel.h>

#define THREADS_MAX 4

struct thread {
    const char *name;
    k_thread_entry_t entry;
    void *p[3];
};

static struct thread threads[THREADS_MAX];
static int nthreads;

static bool frozen;

void sim_ns_freeze(bool on)
{
    sched_lock();
    frozen = on;
    sched_wake();
    sched_unlock();
}

// Only the NS threads sleep here, so a freeze parks them and not the sim's own threads.
int32_t k_msleep(int32_t ms)
{
    sched_sleep_ms(ms);
    sched_lock();
    while (frozen) {
        sched_wait();
    }
    sched_unlock();
    return 0;
}

void sim_k_thread_register(const char *name, k_thread_entry_t entry, void *p1, void *p2, void *p3)
{
    if (nthreads < THREADS_MAX) {
        threads[nthreads++] = (struct thread){name, entry, {p1, p2, p3}};
    }
}

static void run(void *arg)
{
    struct thread *t = arg;

    t->entry(t->p[0], t->p[1], t->p[2]);
}

static void sp_task(void *arg)
{
    (void)arg;
    tfm_bitcoin_init();
}

// NS starts only after the SP waits in psa_wait(), as on TF-M.
static void boot_task(void *arg)
{
    (void)arg;
    sched_start("sp", sp_task, NULL);
    sim_ipc_wait_ready();
    for (int i = 0; i < nthreads; i++) {
        sched_start(threads[i].name, run, &threads[i]);
    }
}

void sim_start(void)
{
    sched_start("boot", boot_task, NULL);
}
