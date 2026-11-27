// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "sched.h"
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

struct start {
    void (*fn)(void *arg);
    void *arg;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static void *run(void *p)
{
    struct start s = *(struct start *)p;

    free(p);
    s.fn(s.arg);
    return NULL;
}

void sched_start(const char *name, void (*fn)(void *arg), void *arg)
{
    struct start *s = malloc(sizeof(*s));
    pthread_t t;

    (void)name;
    s->fn = fn;
    s->arg = arg;
    pthread_create(&t, NULL, run, s);
    pthread_detach(t);
}

void sched_lock(void)
{
    pthread_mutex_lock(&lock);
}

void sched_unlock(void)
{
    pthread_mutex_unlock(&lock);
}

void sched_wait(void)
{
    pthread_cond_wait(&cond, &lock);
}

void sched_wake(void)
{
    pthread_cond_broadcast(&cond);
}

void sched_sleep_ms(uint32_t ms)
{
    struct timespec d = {ms / 1000, (long)(ms % 1000) * 1000000L};

    nanosleep(&d, NULL);
}
