// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The install facts on the panel that do not come from NS:
// the images in slot0 and slot1 as the partition reads them,
// and the install record that tells MCUboot what it may install.

#pragma once

#include "shared/fw_image.h"
#include "shared/install_auth.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// A signed image the partition read itself from slot0 or slot1.
// NS cannot read the secure half of slot0.
// NS can change slot1 after it was hashed, but MCUboot then sees another hash and installs nothing.
typedef struct {
    bool ok;
    uint8_t major;
    uint8_t minor;
    uint16_t revision;
    bool is_boot;          // linked for s0 or s1: a bootloader, not an app
    bool has_boot_version; // a valid fw_info, as b0 reads it
    uint32_t boot_version;
    uint32_t security; // its security counter (protected TLV), 0 when none
    uint8_t sha256[INSTALL_AUTH_HASH_SIZE];
    char hash[FW_IMAGE_HASH_TEXT_SIZE]; // first hex characters of sha256
} firmware_image_t;

// The app that runs. Hashes slot0 on the first call, then returns the same result.
// slot0 does not change before the next reset.
const firmware_image_t *firmware_now(void);

// Hashes the image NS wrote to slot1 now. `ok` is false when slot1 holds no signed image layout.
void firmware_staged(firmware_image_t *out);

// The security floor in the install record: MCUboot installs no app below it.
uint32_t firmware_min_security(void);

// Writes AUTHORIZED with `sha256`, so MCUboot may install that image on the next boot.
// One of BITCOIN_INSTALL_*: PENDING while the last install still swaps or runs as a test,
// WRITE_FAILED when the write failed.
// MCUboot clears PENDING on the boot after the confirm.
uint32_t firmware_authorize(const uint8_t sha256[INSTALL_AUTH_HASH_SIZE]);

// The flash backend: firmware_flash.c on the device, sim/src/firmware_flash.c in the sim.
// A read is false past the end.
bool firmware_slot0_read(uint32_t off, void *buf, size_t len);
uint32_t firmware_slot0_size(void);
bool firmware_slot1_read(uint32_t off, void *buf, size_t len);
uint32_t firmware_slot1_size(void);
// True when `load_addr` is the start of s0 or s1, so the image is a bootloader.
// NS decides the same way.
// NCS signs the app with ROM_FIXED too, so the flag does not tell them apart.
bool firmware_is_boot_addr(uint32_t load_addr);
// The b0 version in the fw_info of the image in slot1. False when it has no valid one.
bool firmware_slot1_boot_version(uint32_t *version);
// Both copies of the install record.
void firmware_auth_read(uint8_t area[INSTALL_AUTH_AREA_SIZE]);
// One copy at `off` in the record area. `rec` is 4-byte aligned.
bool firmware_auth_write(uint32_t off, const uint8_t rec[INSTALL_AUTH_COPY_SIZE]);
