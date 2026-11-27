// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "shared/install_auth.h"
#include "shared/wire.h"
#include <string.h>

#define MAGIC 0x43474953U        // "SIGC"
#define LEGACY_MAGIC 0x42474953U // "SIGB", one record with no copies
#define LEGACY_FLOOR_OFF 8
#define CRC_OFF 84 // the CRC covers bytes 0 to 83: head 16, hashes 64, sequence 4
#define NO_COPY 2

// CRC-32 (IEEE 802.3, reflected), bit by bit. 84 bytes, a few times per install.
static uint32_t crc32(const uint8_t *p, uint32_t len)
{
    uint32_t crc = 0xffffffffU;

    while (len--) {
        crc ^= *p++;
        for (int i = 0; i < 8; i++) {
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
        }
    }
    return ~crc;
}

// False when the copy is erased, torn or broken.
static bool parse_copy(const uint8_t *rec, install_auth_t *auth)
{
    wire_r r = wire_reader(rec, INSTALL_AUTH_COPY_SIZE);
    uint32_t magic = wire_get_le32(&r);
    uint32_t state = wire_get_le32(&r);
    uint32_t crc;

    memset(auth, 0, sizeof(*auth));
    auth->min_security = wire_get_le32(&r);
    auth->pending = wire_get_le32(&r);
    wire_get_field(&r, auth->hash, INSTALL_AUTH_HASH_SIZE, INSTALL_AUTH_HASH_SIZE);
    wire_get_field(&r, auth->revert, INSTALL_AUTH_HASH_SIZE, INSTALL_AUTH_HASH_SIZE);
    auth->seq = wire_get_le32(&r);
    crc = wire_get_le32(&r);
    if (!r.ok || magic != MAGIC || crc != crc32(rec, CRC_OFF) || state > INSTALL_AUTH_TESTING) {
        return false;
    }
    auth->state = (install_auth_state_t)state;
    return true;
}

void install_auth_parse(const uint8_t area[INSTALL_AUTH_AREA_SIZE], install_auth_t *auth)
{
    install_auth_t b;
    bool a_ok = parse_copy(area, auth);
    bool b_ok = parse_copy(area + INSTALL_AUTH_COPY_STRIDE, &b);
    wire_r r;

    // Sequence numbers wrap, so the newer copy is the one ahead by less than half the range.
    if (b_ok && (!a_ok || (int32_t)(b.seq - auth->seq) > 0)) {
        *auth = b;
        auth->copy = 1;
        return;
    }
    if (a_ok) {
        auth->copy = 0;
        return;
    }
    memset(auth, 0, sizeof(*auth));
    auth->copy = NO_COPY;
    // The record before the copies sits where copy A goes. Keep its floor, never lower it.
    // The first write goes to copy B, so it stays until a valid copy exists.
    r = wire_reader(area, LEGACY_FLOOR_OFF + 4);
    if (wire_get_le32(&r) == LEGACY_MAGIC) {
        (void)wire_get_le32(&r);
        auth->min_security = wire_get_le32(&r);
    }
}

uint32_t install_auth_encode(install_auth_t *auth, uint8_t out[INSTALL_AUTH_COPY_SIZE])
{
    wire_w w = wire_writer(out, INSTALL_AUTH_COPY_SIZE);

    auth->seq++;
    auth->copy = auth->copy == 1 ? 0 : 1;
    wire_put_le32(&w, MAGIC);
    wire_put_le32(&w, (uint32_t)auth->state);
    wire_put_le32(&w, auth->min_security);
    wire_put_le32(&w, auth->pending);
    wire_put_field(&w, auth->hash, INSTALL_AUTH_HASH_SIZE, INSTALL_AUTH_HASH_SIZE);
    wire_put_field(&w, auth->revert, INSTALL_AUTH_HASH_SIZE, INSTALL_AUTH_HASH_SIZE);
    wire_put_le32(&w, auth->seq);
    wire_put_le32(&w, crc32(out, CRC_OFF));
    memset(out + CRC_OFF + 4, 0xff, INSTALL_AUTH_COPY_SIZE - CRC_OFF - 4);
    return auth->copy * INSTALL_AUTH_COPY_STRIDE;
}

// The swap is over and slot0 keeps what it has. If that is the new app, `pending` is its counter.
// A swap back set `pending` to 0.
static void finish(install_auth_t *auth)
{
    if (auth->pending > auth->min_security) {
        auth->min_security = auth->pending;
    }
    auth->pending = 0;
    auth->state = INSTALL_AUTH_IDLE;
}

// slot0 is open while a swap runs, and after a test swap until NS confirms the new app.
// MCUboot writes the magic before it moves any data,
// sets copy_done when a swap to a new app is done, and sets image_ok when a swap back is done.
// A bootloader install does not touch slot0.
static bool is_open(const install_auth_slot0_t *slot0)
{
    return slot0->magic && !slot0->image_ok;
}

void install_auth_check_kept(install_auth_t *auth, const install_auth_image_t *slot0)
{
    if (!slot0->ok || memcmp(slot0->hash, auth->hash, INSTALL_AUTH_HASH_SIZE) != 0) {
        auth->pending = 0;
    }
}

void install_auth_after_swap(install_auth_t *auth, const install_auth_slot0_t *slot0)
{
    if (auth->state != INSTALL_AUTH_SWAPPING) {
        return;
    }
    if (!is_open(slot0)) {
        finish(auth);
    } else if (slot0->copy_done) {
        auth->state = INSTALL_AUTH_TESTING;
    }
}

bool install_auth_at_boot(install_auth_t *auth, const install_auth_slot0_t *slot0)
{
    switch (auth->state) {
    case INSTALL_AUTH_SWAPPING:
        // A reset in the middle of an authorized swap.
        // MCUboot finishes it or starts it again,
        // and install_auth_after_swap() decides once it is done.
        // Not here: until MCUboot rewrites slot0's trailer,
        // a swap back cut early still shows the finished install.
        return false;
    case INSTALL_AUTH_TESTING:
        if (!is_open(slot0)) {
            finish(auth); // confirmed: the new app stays
            return false;
        }
        if (slot0->copy_done) {
            return false;
        }
        // No authorized swap runs, so NS wrote a swap to resume. Closing keeps the new app.
        finish(auth);
        return true;
    default:
        // MCUboot did not start this. NS wrote the trailer, to resume or swap back into slot1.
        return is_open(slot0);
    }
}

bool install_auth_below_floor(const install_auth_t *auth, const install_auth_image_t *slot1)
{
    return !slot1->is_boot && slot1->security < auth->min_security;
}

bool install_auth_may_swap(const install_auth_t *auth, install_auth_swap_t swap,
                           const install_auth_image_t *slot1)
{
    if (!slot1->ok) {
        return false;
    }
    switch (swap) {
    case INSTALL_AUTH_SWAP_TEST:
    case INSTALL_AUTH_SWAP_PERM:
        return auth->state == INSTALL_AUTH_AUTHORIZED &&
               memcmp(slot1->hash, auth->hash, INSTALL_AUTH_HASH_SIZE) == 0 &&
               !install_auth_below_floor(auth, slot1);
    case INSTALL_AUTH_SWAP_REVERT:
        return auth->state == INSTALL_AUTH_TESTING &&
               memcmp(slot1->hash, auth->revert, INSTALL_AUTH_HASH_SIZE) == 0;
    default:
        return false;
    }
}

bool install_auth_may_run(const install_auth_t *auth, install_auth_swap_t swap,
                          const install_auth_image_t *slot1)
{
    if (!slot1->ok || auth->state != INSTALL_AUTH_SWAPPING) {
        return false;
    }
    switch (swap) {
    case INSTALL_AUTH_SWAP_TEST:
    case INSTALL_AUTH_SWAP_PERM:
        return memcmp(slot1->hash, auth->hash, INSTALL_AUTH_HASH_SIZE) == 0 &&
               !install_auth_below_floor(auth, slot1);
    case INSTALL_AUTH_SWAP_REVERT:
        return memcmp(slot1->hash, auth->revert, INSTALL_AUTH_HASH_SIZE) == 0;
    default:
        return false;
    }
}

void install_auth_start(install_auth_t *auth, install_auth_swap_t swap,
                        const install_auth_image_t *slot1)
{
    bool new_app = swap != INSTALL_AUTH_SWAP_REVERT && !slot1->is_boot;

    auth->pending = new_app ? slot1->security : 0;
    auth->state = INSTALL_AUTH_SWAPPING;
}
