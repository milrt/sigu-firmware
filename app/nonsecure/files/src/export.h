// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

// Room for the export file name, "wallet-<fingerprint>.txt".
#define EXPORT_NAME_SIZE sizeof("wallet-00000000.txt")

// The watch-only descriptor of the open wallet, one line in `text` (`len` bytes, no NUL),
// and the file name for it in `name`.
// One of BITCOIN_FILES_*: OK, READ_FAILED when the partition gives no key,
// or WRITE_FAILED when `text` is too small.
uint32_t export_build(char *text, size_t size, size_t *len, char name[EXPORT_NAME_SIZE]);
