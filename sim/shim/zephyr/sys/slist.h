// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// Zephyr's singly linked list, the calls NS uses.

#pragma once

#include <stddef.h>
#include <zephyr/sys/util.h>

typedef struct _snode {
    struct _snode *next;
} sys_snode_t;

typedef struct {
    sys_snode_t *head;
    sys_snode_t *tail;
} sys_slist_t;

static inline void sys_slist_init(sys_slist_t *l)
{
    l->head = NULL;
    l->tail = NULL;
}

static inline void sys_slist_append(sys_slist_t *l, sys_snode_t *n)
{
    n->next = NULL;
    if (l->tail) {
        l->tail->next = n;
    } else {
        l->head = n;
    }
    l->tail = n;
}

// `prev` is the node before `n`, or NULL when `n` is the head.
static inline void sys_slist_remove(sys_slist_t *l, sys_snode_t *prev, sys_snode_t *n)
{
    if (prev) {
        prev->next = n->next;
    } else {
        l->head = n->next;
    }
    if (l->tail == n) {
        l->tail = prev;
    }
    n->next = NULL;
}

#define SYS_SLIST_CONTAINER(n, cn, field) ((n) ? CONTAINER_OF(n, __typeof__(*(cn)), field) : NULL)

#define SYS_SLIST_FOR_EACH_CONTAINER(l, cn, field)                                                 \
    for (cn = SYS_SLIST_CONTAINER((l)->head, cn, field); cn;                                       \
         cn = SYS_SLIST_CONTAINER((cn)->field.next, cn, field))

#define SYS_SLIST_FOR_EACH_CONTAINER_SAFE(l, cn, cns, field)                                       \
    for (cn = SYS_SLIST_CONTAINER((l)->head, cn, field),                                           \
        cns = cn ? SYS_SLIST_CONTAINER((cn)->field.next, cn, field) : NULL;                        \
         cn; cn = cns, cns = cn ? SYS_SLIST_CONTAINER((cn)->field.next, cn, field) : NULL)
