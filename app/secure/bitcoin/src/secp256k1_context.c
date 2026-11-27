// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "secp256k1_context.h"
#include "psa/crypto.h"
#include "shared/mem_util.h"
#include <secp256k1_preallocated.h>
#include "tfm_log.h"
#include "secp256k1.h"

void secp256k1_default_illegal_callback_fn(const char *message, void *data)
{
    (void)message;
    (void)data;

    ERROR("secp256k1 illegal argument\n");
    while (1) {
    }
}

void secp256k1_default_error_callback_fn(const char *message, void *data)
{
    (void)message;
    (void)data;

    ERROR("secp256k1 internal error\n");
    while (1) {
    }
}

size_t secp256k1_get_context_size()
{
    return secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE);
}

secp256k1_context *secp256k1_create_randomized_context(uint8_t *context_memory)
{
    secp256k1_context *ctx = NULL;
    uint8_t randomize[32];

    if (psa_generate_random(randomize, sizeof(randomize)) != PSA_SUCCESS) {
        goto cleanup;
    }

    ctx = secp256k1_context_preallocated_create(context_memory, SECP256K1_CONTEXT_NONE);
    if (ctx == NULL) {
        goto cleanup;
    }
    if (!secp256k1_context_randomize(ctx, randomize)) {
        ctx = NULL;
        goto cleanup;
    }

cleanup:
    mem_zeroize(randomize, sizeof(randomize));
    return ctx;
}
