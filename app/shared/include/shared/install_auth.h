// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

// The install authorization: one record in `sigu_install_partition`, below slot0_ns,
// so NS cannot write it.
// The SP writes AUTHORIZED with the slot1 hash after the user confirms. MCUboot writes the rest.
// NS writes slot1 and both trailers, so this record decides what MCUboot may swap.
// The rules are here, so MCUboot and the sim run the same code.
//
// The record also holds the security floor:
// MCUboot installs no app with a security counter below `min_security`.
// The counter is imgtool --security-counter.
// The floor rises to the counter of a new app once that app is kept,
// confirmed or installed as permanent, and never on a swap back.
//
// Two copies, A at offset 0 and B at INSTALL_AUTH_COPY_STRIDE.
// Each write goes to the other copy with the next sequence number,
// and a reader takes the valid copy with the higher one.
// So a write cut by a power loss fails its CRC, and the copy before it stays.
// A copy, 6 RRAM write blocks of 16 bytes, little endian:
// magic u32, state u32, min_security u32, pending u32, the SHA-256 of the image to install,
// the SHA-256 of the image to swap back to, sequence u32, CRC-32 u32 of all bytes before it,
// 8 bytes 0xff.
// A hash covers the whole signed image (header, body and TLVs).
// With no valid copy, the record is IDLE with floor 0,
// but the floor of an old single record (magic "SIGB") is kept.

#include <stdbool.h>
#include <stdint.h>

#define INSTALL_AUTH_COPY_SIZE 96
#define INSTALL_AUTH_COPY_STRIDE 128
// What a reader reads: both copies.
#define INSTALL_AUTH_AREA_SIZE (2 * INSTALL_AUTH_COPY_STRIDE)
#define INSTALL_AUTH_HASH_SIZE 32

typedef enum {
    INSTALL_AUTH_IDLE = 0,
    // The user confirmed the image with `hash`.
    // MCUboot may start one swap of it, on the next boot only.
    INSTALL_AUTH_AUTHORIZED = 1,
    // MCUboot started a swap. After a reset it may finish it or start it again.
    // Only install_auth_after_swap() leaves this state, after MCUboot is done and before NS runs.
    INSTALL_AUTH_SWAPPING = 2,
    // The new app runs as a test. MCUboot may swap back, only to the image with `revert`.
    INSTALL_AUTH_TESTING = 3,
} install_auth_state_t;

typedef struct {
    install_auth_state_t state;
    uint32_t min_security; // no app below this security counter installs
    uint32_t pending;      // the counter of the app being installed, 0 when none
    uint8_t hash[INSTALL_AUTH_HASH_SIZE];
    uint8_t revert[INSTALL_AUTH_HASH_SIZE];
    uint32_t seq;  // the sequence number of the copy it was read from, or last written
    uint32_t copy; // that copy: 0 (A) or 1 (B), 2 when there is none
} install_auth_t;

// The swap MCUboot would do, from boot_swap_type_multi().
typedef enum {
    INSTALL_AUTH_SWAP_NONE,
    INSTALL_AUTH_SWAP_TEST,
    INSTALL_AUTH_SWAP_PERM,
    INSTALL_AUTH_SWAP_REVERT,
} install_auth_swap_t;

// The slot0 trailer flags, from boot_read_swap_state_by_id().
typedef struct {
    bool magic;     // BOOT_MAGIC_GOOD
    bool copy_done; // BOOT_FLAG_SET
    bool image_ok;  // BOOT_FLAG_SET
} install_auth_slot0_t;

// The image in slot1, as MCUboot read it.
typedef struct {
    bool ok; // a signed image layout, hashed, with readable protected TLVs
    uint8_t hash[INSTALL_AUTH_HASH_SIZE];
    bool is_boot;      // linked for s0 or s1: b0's counter covers it, not the floor
    uint32_t security; // its security counter, 0 when it has none
} install_auth_image_t;

// Reads the newest valid copy from both.
void install_auth_parse(const uint8_t area[INSTALL_AUTH_AREA_SIZE], install_auth_t *auth);

// Encodes `auth` as the next copy, for the copy it was not read from.
// Returns that copy's offset in the area, and updates `seq` and `copy` to it.
// Write all INSTALL_AUTH_COPY_SIZE bytes there.
uint32_t install_auth_encode(install_auth_t *auth, uint8_t out[INSTALL_AUTH_COPY_SIZE]);

// Call before install_auth_at_boot() and install_auth_after_swap() when `pending` is not 0,
// with slot0 as MCUboot reads it.
// The floor may rise only to the counter of an image MCUboot checked and runs.
// So `pending` stays only if slot0 holds the authorized image:
// the counter was read from slot1 before any check,
// and the swap may not have happened (bad signature) or slot0 may have changed since.
void install_auth_check_kept(install_auth_t *auth, const install_auth_image_t *slot0);

// Before MCUboot reads the trailers. Updates `auth`.
// True when slot0's trailer must be closed:
// set copy_done and image_ok, so MCUboot neither resumes a swap nor swaps back.
bool install_auth_at_boot(install_auth_t *auth, const install_auth_slot0_t *slot0);

// After a swap, before NS runs. Updates `auth`.
// SWAPPING after it means the swap did not finish, and MCUboot must not start the app.
void install_auth_after_swap(install_auth_t *auth, const install_auth_slot0_t *slot0);

// True when the image is an app below the floor. The panel blocks it too.
bool install_auth_below_floor(const install_auth_t *auth, const install_auth_image_t *slot1);

// Before MCUboot swaps. True when the swap may run. MCUboot then calls install_auth_start().
bool install_auth_may_swap(const install_auth_t *auth, install_auth_swap_t swap,
                           const install_auth_image_t *slot1);

// When MCUboot is about to swap, after install_auth_start().
// A second check, from the record and slot1 read again:
// SWAPPING, and slot1 is the image the swap is for,
// `hash` above the floor or `revert` for a swap back.
bool install_auth_may_run(const install_auth_t *auth, install_auth_swap_t swap,
                          const install_auth_image_t *slot1);

// SWAPPING, with the counter that becomes the floor if the new app is kept.
// `revert` is set by the caller for a test swap.
void install_auth_start(install_auth_t *auth, install_auth_swap_t swap,
                        const install_auth_image_t *slot1);
