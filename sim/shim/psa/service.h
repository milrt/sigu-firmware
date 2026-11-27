// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The PSA Firmware Framework partition API, as TF-M gives it to an IPC partition.
// sim/src/ipc.c implements it.

#pragma once

#include <psa/client.h>

#define PSA_WAIT_ANY 0xFFFFFFFFU
#define PSA_BLOCK 0x80000000U
#define PSA_POLL 0x00000000U

#define PSA_IPC_CONNECT (-1)
#define PSA_IPC_DISCONNECT (-2)

typedef uint32_t psa_signal_t;

typedef struct psa_msg_t {
    int32_t type;
    psa_handle_t handle;
    int32_t client_id;
    void *rhandle;
    size_t in_size[PSA_MAX_IOVEC];
    size_t out_size[PSA_MAX_IOVEC];
} psa_msg_t;

psa_signal_t psa_wait(psa_signal_t signal_mask, uint32_t timeout);
psa_status_t psa_get(psa_signal_t signal, psa_msg_t *msg);
size_t psa_read(psa_handle_t msg_handle, uint32_t invec_idx, void *buffer, size_t num_bytes);
void psa_write(psa_handle_t msg_handle, uint32_t outvec_idx, const void *buffer, size_t num_bytes);
void psa_reply(psa_handle_t msg_handle, psa_status_t status);
void psa_irq_enable(psa_signal_t irq_signal);
void psa_eoi(psa_signal_t irq_signal);
_Noreturn void psa_panic(void);
