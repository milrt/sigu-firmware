// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stdint.h>

// The panel config, one ITS record that only this partition writes.
typedef struct {
    uint32_t theme;
    bool fw_failed_seen;
} config_t;

// False for a missing record, a wrong size, an unknown version or a bad seen byte.
// The caller checks the range of the theme.
bool config_read(config_t *c);

// Writes the whole record. False if a value does not fit its field or ITS fails.
bool config_write(const config_t *c);

// Removes the record. True also when there was none.
bool config_remove(void);
