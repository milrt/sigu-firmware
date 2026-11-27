// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

typedef uint64_t psa_storage_uid_t;
typedef uint32_t psa_storage_create_flags_t;

struct psa_storage_info_t {
    size_t capacity;
    size_t size;
    psa_storage_create_flags_t flags;
};

#define PSA_STORAGE_FLAG_NONE 0U
#define PSA_STORAGE_FLAG_WRITE_ONCE (1U << 0)
#define PSA_STORAGE_FLAG_NO_CONFIDENTIALITY (1U << 1)
#define PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION (1U << 2)
