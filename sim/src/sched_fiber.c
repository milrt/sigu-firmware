// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// Fibers on the one JS thread (Asyncify).
// Only one fiber runs at a time, and it runs until it waits or sleeps,
// so the lock has nothing to do.
// The page's main loop calls sched_run().

#include "sched.h"
#include <emscripten.h>
#include <emscripten/fiber.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define TASKS_MAX 6
#define C_STACK (512 * 1024)
#define ASYNC_STACK (128 * 1024)

struct task {
    emscripten_fiber_t fiber;
    const char *name;
    void (*fn)(void *arg);
    void *arg;
    double wake_at;
    uint32_t wait_gen;
    bool waiting;
    bool done;
};

static struct task tasks[TASKS_MAX];
static int ntasks;
static struct task *cur;
static uint32_t wake_gen;
static emscripten_fiber_t main_fiber;
static char main_async_stack[ASYNC_STACK];
static bool main_ready;

static void yield(void)
{
    if (!cur) {
        fprintf(stderr, "[SIM] the page itself cannot block\n");
        abort();
    }
    emscripten_fiber_swap(&cur->fiber, &main_fiber);
}

static void entry(void *arg)
{
    struct task *t = arg;

    t->fn(t->arg);
    t->done = true;
    for (;;) {
        yield();
    }
}

void sched_start(const char *name, void (*fn)(void *arg), void *arg)
{
    struct task *t;

    if (!main_ready) {
        emscripten_fiber_init_from_current_context(&main_fiber, main_async_stack,
                                                   sizeof(main_async_stack));
        main_ready = true;
    }
    if (ntasks == TASKS_MAX) {
        fprintf(stderr, "[SIM] too many tasks\n");
        abort();
    }
    t = &tasks[ntasks++];
    t->name = name;
    t->fn = fn;
    t->arg = arg;
    // The stacks must be 16-byte aligned. malloc() gives 8 on wasm32,
    // and with that the frames of nested calls overlap: BIP-39 seeds came out wrong.
    emscripten_fiber_init(&t->fiber, entry, t, aligned_alloc(16, C_STACK), C_STACK,
                          aligned_alloc(16, ASYNC_STACK), ASYNC_STACK);
}

void sched_lock(void)
{
}

void sched_unlock(void)
{
}

void sched_wait(void)
{
    cur->waiting = true;
    cur->wait_gen = wake_gen;
    yield();
}

void sched_wake(void)
{
    wake_gen++;
}

void sched_sleep_ms(uint32_t ms)
{
    cur->wake_at = emscripten_get_now() + ms;
    yield();
}

static bool runnable(const struct task *t, double now)
{
    if (t->done) {
        return false;
    }
    if (t->waiting) {
        return t->wait_gen != wake_gen;
    }
    return now >= t->wake_at;
}

void sched_run(double budget_ms)
{
    double end = emscripten_get_now() + budget_ms;
    bool ran = true;

    while (ran && emscripten_get_now() < end) {
        ran = false;
        for (int i = 0; i < ntasks; i++) {
            struct task *t = &tasks[i];

            if (!runnable(t, emscripten_get_now())) {
                continue;
            }
            t->waiting = false;
            cur = t;
            emscripten_fiber_swap(&main_fiber, &t->fiber);
            cur = NULL;
            ran = true;
        }
    }
}
