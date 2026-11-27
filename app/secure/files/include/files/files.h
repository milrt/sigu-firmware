// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The card as NS reported it, RAM only:
// the PSBT list, the install files, the firmware state and the one card job.
// NS owns the card, so these are claims to show, not facts the partition checked.
// The IPC handler fills a whole list before the next tick runs, so a screen never sees half a list.

#pragma once

#include "shared/bitcoin_service_defs.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Empties the PSBT list and the install files, and starts a new generation.
// The boot version stays.
void files_clear(void);

// Appends a copy of `name`, cut to BITCOIN_FILE_NAME_MAX_SIZE - 1 bytes,
// with every byte outside printable ASCII replaced by '?'. False when full.
bool files_add(const char *name);

uint32_t files_count(void);

// NULL past the end.
const char *files_name(uint32_t i);

// Changes on every files_clear(). A screen redraws when it sees a new value.
uint32_t files_generation(void);

// The card as NS reported it, one of BITCOIN_CARD_*.
void files_set_card(uint32_t card);
uint32_t files_card(void);

// An install file NS found on the card. NS claims, shown only.
typedef struct {
    uint8_t kind;  // BITCOIN_INSTALL_BOOT or _APP
    uint8_t state; // BITCOIN_INSTALL_STATE_*
    uint8_t major;
    uint8_t minor;
    uint16_t revision;
    uint32_t boot_version;
    uint8_t hash[BITCOIN_INSTALL_HASH_SIZE];
} files_install_t;

// Sets the install records (`len` bytes, see bitcoin_service_defs.h).
// False on a bad record, and then the list is empty.
bool files_set_installs(const uint8_t *records, size_t len);

// The firmware state NS read:
// the running bootloader's b0 version (0 when unknown), and a BITCOIN_FW_* status.
void files_set_fw(uint32_t boot_version, uint32_t status);
uint32_t files_boot_version(void);
uint32_t files_fw_status(void);
uint32_t files_install_count(void);
// NULL past the end.
const files_install_t *files_install(uint32_t i);

// The one card job: a sign, an install, an install commit or an export. Each edge has one owner:
//   IDLE or DONE -> REQUESTED   the picker (open on a file), the firmware or the export screen
//   REQUESTED -> BUSY           NS, FILES_POLL
//   BUSY -> DONE                NS with FILES_RESULT, or reject on the review with REJECTED
//   any -> IDLE                 the sign job, firmware or export screen, when it closes
typedef enum {
    FILES_JOB_IDLE,
    FILES_JOB_REQUESTED,
    FILES_JOB_BUSY,
    FILES_JOB_DONE,
} files_job_state_t;

files_job_state_t files_job_state(void);
const char *files_job_name(void);

// One of BITCOIN_JOB_*.
uint32_t files_job_kind(void);
// An install job or an install commit job.
bool files_job_is_install(void);

// How a DONE job ended, one of BITCOIN_FILES_* or BITCOIN_INSTALL_*, by the kind.
uint32_t files_job_code(void);

// The requests are false while a job is REQUESTED or BUSY.
bool files_job_request_sign(const char *name);
// `kind` is BITCOIN_JOB_INSTALL_BOOT or _APP. NS writes the file to slot1 and ends with STAGED.
bool files_job_request_install(uint32_t kind);
// NS asks MCUboot to install what it staged, after the partition wrote the install record.
bool files_job_request_commit(void);
bool files_job_request_export(void);

// The name of a REQUESTED job, which is now BUSY, and its kind in `kind`.
// Only a sign job has a name. NULL when there is no job.
const char *files_job_take(uint32_t *kind);

// False unless BUSY, or for a code NS may not send.
bool files_job_finish(uint32_t code);

// The SP signed an input of the production session while a sign job was BUSY.
// The panel says "signed" only then: BITCOIN_FILES_OK is an NS claim.
void files_job_note_signed(void);
bool files_job_signed(void);

// Ends a BUSY sign job with BITCOIN_FILES_REJECTED, so a late FILES_RESULT is refused.
void files_job_reject(void);

// Back to IDLE, so a late FILES_RESULT is refused.
void files_job_close(void);
