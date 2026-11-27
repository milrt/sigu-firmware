// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The part of the Zephyr kernel API that NS uses, on the host.

#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <zephyr/sys/util.h>

typedef struct {
    int32_t ms;
} k_timeout_t;

#define K_NO_WAIT ((k_timeout_t){0})

// A heap with the same budget as K_HEAP_DEFINE gives on the device,
// so a PSBT that does not fit there does not fit here.
// Zephyr's own block overhead is not counted.
struct k_heap {
    size_t limit;
    size_t used;
};

#define K_HEAP_DEFINE(name, bytes) struct k_heap name = {.limit = (bytes)}

void *k_heap_alloc(struct k_heap *h, size_t bytes, k_timeout_t timeout);
void k_heap_free(struct k_heap *h, void *mem);

int32_t k_msleep(int32_t ms);

// Priorities only order threads on the device. The sim runs them all the same.
#define K_LOWEST_APPLICATION_THREAD_PRIO 14

typedef void (*k_thread_entry_t)(void *p1, void *p2, void *p3);

// NS threads start after the SP waits in psa_wait(), as on TF-M. See sim_ns_start().
void sim_k_thread_register(const char *name, k_thread_entry_t entry, void *p1, void *p2, void *p3);

#define K_THREAD_DEFINE(name, stack, entry, p1, p2, p3, prio, options, delay)                      \
    __attribute__((constructor)) static void name##_register(void)                                 \
    {                                                                                              \
        sim_k_thread_register(#name, entry, p1, p2, p3);                                           \
    }
