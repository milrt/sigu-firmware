// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// PSA Internal Trusted Storage. sim/src/ps.c keeps each UID in a file next to the PS ones.

#pragma once

#include <psa/storage_common.h>

psa_status_t psa_its_set(psa_storage_uid_t uid, size_t data_length, const void *p_data,
                         psa_storage_create_flags_t create_flags);
psa_status_t psa_its_get(psa_storage_uid_t uid, size_t data_offset, size_t data_length,
                         void *p_data, size_t *p_data_length);
psa_status_t psa_its_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info);
psa_status_t psa_its_remove(psa_storage_uid_t uid);
