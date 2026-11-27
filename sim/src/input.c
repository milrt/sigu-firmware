// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The keys. The window, the page and the control commands queue presses,
// and the SP tick reads one per tick.
// On the device two presses never land in one 20 ms tick.
// Here a slow frame or a script can send several, and a mask would merge them into one.

#include "drivers/input.h"
#include "sched.h"
#include "sim.h"

#define QUEUE_MAX 64

static uint32_t queue[QUEUE_MAX];
static unsigned head;
static unsigned tail;

void input_init(void)
{
}

uint32_t input_poll(void)
{
    uint32_t keys = 0;

    sched_lock();
    if (head != tail) {
        keys = queue[head++ % QUEUE_MAX];
    }
    sched_unlock();
    return keys;
}

// A full queue drops the press, as a key pressed too fast would be missed.
void sim_input_press(uint32_t keys)
{
    sched_lock();
    if (tail - head < QUEUE_MAX) {
        queue[tail++ % QUEUE_MAX] = keys;
    }
    sched_unlock();
}
