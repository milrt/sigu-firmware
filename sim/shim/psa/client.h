// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The PSA Firmware Framework client API, as TF-M gives it to NS. sim/src/ipc.c implements it.

#pragma once

#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

#define PSA_MAX_IOVEC 4
#define PSA_IPC_CALL 0
#define PSA_NULL_HANDLE ((psa_handle_t)0)
#define PSA_ERROR_CONNECTION_REFUSED ((psa_status_t) - 150)
#define PSA_ERROR_CONNECTION_BUSY ((psa_status_t) - 151)
#define IOVEC_LEN(arr) ((uint32_t)(sizeof(arr) / sizeof((arr)[0])))
#define PSA_HANDLE_IS_VALID(h) ((psa_handle_t)(h) > 0)

typedef int32_t psa_handle_t;

typedef struct {
    const void *base;
    size_t len;
} psa_invec;

typedef struct {
    void *base;
    size_t len;
} psa_outvec;

psa_handle_t psa_connect(uint32_t sid, uint32_t version);
psa_status_t psa_call(psa_handle_t handle, int32_t type, const psa_invec *in_vec, size_t in_len,
                      psa_outvec *out_vec, size_t out_len);
void psa_close(psa_handle_t handle);
