// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// k_heap for the PSBT heap. Apart from kernel.c, so the fuzz targets can link it alone.

#include "sched.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/kernel.h>

// Each block starts with its size, so k_heap_free() knows how much to give back.
struct block {
    size_t size;
    max_align_t data[];
};

void *k_heap_alloc(struct k_heap *h, size_t bytes, k_timeout_t timeout)
{
    struct block *b = NULL;

    (void)timeout;
    sched_lock();
    if (bytes <= h->limit - h->used) {
        b = malloc(sizeof(*b) + bytes);
        if (b) {
            b->size = bytes;
            h->used += bytes;
        }
    }
    sched_unlock();
    return b ? b->data : NULL;
}

void k_heap_free(struct k_heap *h, void *mem)
{
    struct block *b;

    if (!mem) {
        return;
    }
    b = (struct block *)((char *)mem - offsetof(struct block, data));
    sched_lock();
    h->used -= b->size;
    sched_unlock();
    memset(b, 0, sizeof(*b) + b->size);
    free(b);
}
