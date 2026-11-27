// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The install files on the card.
// NS checks them, writes the one the user picked to slot1, and asks MCUboot to install it.
// These checks only keep a wrong file from costing a restart.
// The real checks are the install record, which only the partition writes after the user confirms,
// and the signature, which MCUboot or b0 checks.
//
// install_run() installs only what install_scan() found and the panel showed:
// the same app bytes (by SHA-256) or the same bootloader version.
// Only the sd_job thread calls these.

#pragma once

#include "shared/bitcoin_service_defs.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define INSTALL_RECORDS_SIZE (BITCOIN_INSTALLS_MAX * BITCOIN_INSTALL_RECORD_SIZE)

// The install records for TFM_BITCOIN_FILES_SET in3. Returns how many: none without `mounted`.
size_t install_scan(bool mounted, uint8_t records[INSTALL_RECORDS_SIZE]);

// The firmware state for TFM_BITCOIN_FILES_SET in2.
void install_fw_state(uint8_t out[BITCOIN_FW_STATE_SIZE]);

// Writes the file of `job` (BITCOIN_JOB_INSTALL_BOOT or _APP) to slot1.
// Returns BITCOIN_INSTALL_STAGED, or the failure.
uint32_t install_run(uint32_t job);

// Asks MCUboot to install slot1. Returns BITCOIN_INSTALL_OK, and the caller then restarts.
uint32_t install_commit(void);
