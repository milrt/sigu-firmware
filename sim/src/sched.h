// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The sim's threads: the SP, the tick, the NS card thread and the control loop.
// They block only through these calls. On the desktop they are pthreads.
// On the web they are fibers on the one JS thread,
// and they switch only inside sched_wait() and sched_sleep_ms().

#pragma once

#include <stdint.h>

void sched_start(const char *name, void (*fn)(void *arg), void *arg);

// One lock for all the state that threads wait on.
void sched_lock(void);
void sched_unlock(void);

// With the lock held. Gives the lock up until some thread calls sched_wake(), then takes it again.
// A caller loops on its own condition, as with a condition variable.
void sched_wait(void);
void sched_wake(void);

void sched_sleep_ms(uint32_t ms);

#ifdef __EMSCRIPTEN__
// Runs the fibers that can run, for at most `budget_ms`. The page calls it once per frame.
void sched_run(double budget_ms);
#endif
