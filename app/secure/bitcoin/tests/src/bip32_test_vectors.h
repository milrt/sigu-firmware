// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#define BIP32_TEST_VECTOR_COUNT 17

typedef struct {
    const uint8_t *seed;
    size_t seed_size;
    const char *path;
    const char *xpub;
} bip32_test_vector_t;

extern const bip32_test_vector_t bip32_test_vectors[BIP32_TEST_VECTOR_COUNT];
