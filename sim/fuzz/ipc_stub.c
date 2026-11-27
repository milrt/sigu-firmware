// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The SP side of TF-M's IPC for one message, with no threads.
// Like sim/src/ipc.c, a bad index or a write past an outvec stops the run:
// TF-M panics the partition for it.

#include "ipc_stub.h"
#include "sim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MSG_HANDLE ((psa_handle_t)0x40000001)

static psa_msg_t msg;
static const uint8_t *in_buf[PSA_MAX_IOVEC];
static size_t in_off[PSA_MAX_IOVEC];
static int replies;

_Noreturn void psa_panic(void)
{
    fprintf(stderr, "psa_panic()\n");
    abort();
}

psa_msg_t *ipc_stub_message(int32_t type, const uint8_t *const in[PSA_MAX_IOVEC],
                            const size_t in_len[PSA_MAX_IOVEC])
{
    memset(&msg, 0, sizeof(msg));
    msg.type = type;
    msg.handle = MSG_HANDLE;
    msg.client_id = -1;
    for (size_t i = 0; i < PSA_MAX_IOVEC; i++) {
        in_buf[i] = in[i];
        in_off[i] = 0;
        msg.in_size[i] = in_len[i];
    }
    replies = 0;
    return &msg;
}

int ipc_stub_replied(void)
{
    return replies == 1;
}

static void check_handle(psa_handle_t h)
{
    if (h != MSG_HANDLE || replies != 0) {
        psa_panic();
    }
}

size_t psa_read(psa_handle_t msg_handle, uint32_t invec_idx, void *buffer, size_t num_bytes)
{
    size_t n;

    check_handle(msg_handle);
    if (invec_idx >= PSA_MAX_IOVEC) {
        psa_panic();
    }
    n = msg.in_size[invec_idx] - in_off[invec_idx];
    if (n > num_bytes) {
        n = num_bytes;
    }
    memcpy(buffer, in_buf[invec_idx] + in_off[invec_idx], n);
    in_off[invec_idx] += n;
    return n;
}

void psa_write(psa_handle_t msg_handle, uint32_t outvec_idx, const void *buffer, size_t num_bytes)
{
    (void)buffer;
    check_handle(msg_handle);
    // No outvecs, so any write is past the end.
    if (outvec_idx >= PSA_MAX_IOVEC || num_bytes > msg.out_size[outvec_idx]) {
        psa_panic();
    }
}

void psa_reply(psa_handle_t msg_handle, psa_status_t status)
{
    (void)status;
    check_handle(msg_handle);
    replies++;
}

// The main loop is never run here. These only satisfy the link.
psa_signal_t psa_wait(psa_signal_t signal_mask, uint32_t timeout)
{
    (void)signal_mask;
    (void)timeout;
    psa_panic();
}

psa_status_t psa_get(psa_signal_t signal, psa_msg_t *m)
{
    (void)signal;
    (void)m;
    psa_panic();
}

void psa_irq_enable(psa_signal_t irq_signal)
{
    (void)irq_signal;
}

void psa_eoi(psa_signal_t irq_signal)
{
    (void)irq_signal;
}

void sim_ipc_irq(uint32_t signal)
{
    (void)signal;
}

void sim_ipc_wait_ticks(uint32_t n)
{
    (void)n;
}
