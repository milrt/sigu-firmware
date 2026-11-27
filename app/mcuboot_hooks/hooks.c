// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// MCUboot installs only what the user confirmed on the panel.
// NS writes slot1 and both trailers, so a request, a swap back or a resume can come from NS alone.
// We run boot_go() ourselves, and first check the trailers against the install record,
// which NS cannot write (shared/install_auth.h has the rules):
//   - a request (test or permanent) needs AUTHORIZED and the same SHA-256 of slot1.
//     Otherwise we break the slot1 magic, so MCUboot sees no request.
//     An unused AUTHORIZED goes IDLE.
//   - before the swap we store SWAPPING and the hash of the app in slot0, for a swap back.
//   - a resume needs SWAPPING. A swap back needs TESTING and that hash in slot1.
//     Otherwise we close slot0's trailer (copy_done and image_ok), so MCUboot boots slot0.
//   - an app below the security floor (min_security) never installs.
//     The floor rises to the new app's counter once it is kept, and only if slot0 holds that app:
//     MCUboot checked its signature then. Bootloaders have b0's counter instead.
// After boot_go(), before the app runs, SWAPPING becomes TESTING or IDLE,
// so NS never runs while a resume is allowed. When a write fails, we do not boot.
// boot_perform_update_hook() refuses any swap boot_go_hook() did not allow,
// and checks again on its own: the record read again must be SWAPPING,
// and for a swap that starts on this boot, slot1 is hashed again.
// On a resume slot1 is half moved, so the state is all it has.
// Against a glitch, each decision is a value far from 0 and from its opposite (YES, NO),
// and it is tested twice, so one skipped branch cannot open a swap.
// Before boot_go() we also read the record and slot0's trailer again,
// and do not boot unless slot0 is closed or our swap runs.

#include "shared/fw_image.h"
#include "shared/install_auth.h"
#include <psa/crypto.h>
#include <string.h>
#include <zephyr/devicetree.h>
#include <zephyr/storage/flash_map.h>
#include "bootutil/boot_hooks.h"
#include "bootutil/boot_public_hooks.h"
#include "bootutil/bootutil.h"
#include "bootutil/bootutil_log.h"
#include "bootutil/bootutil_public.h"
#include "bootutil/fault_injection_hardening.h"
#include "bootutil/image.h"
#include "flash_map_backend/flash_map_backend.h"
#include "sysflash/sysflash.h"

BOOT_LOG_MODULE_DECLARE(mcuboot);

#define AUTH_ID PARTITION_ID(sigu_install_partition)
#define S0_ADDR DT_REG_ADDR(DT_NODELABEL(s0_partition))
#define S1_ADDR DT_REG_ADDR(DT_NODELABEL(s1_partition))
#define CHUNK 256

// In bootutil_public.c, declared only in the private bootutil_priv.h.
int boot_write_copy_done(const struct flash_area *fap);
int boot_write_image_ok(const struct flash_area *fap);

// A single bit flip or a zeroed register is neither of these.
#define YES 0x3CA55AC3u
#define NO 0xC35AA53Cu

static volatile uint32_t swap_allowed = NO;
// YES when the record was SWAPPING at the start of this boot: slot1 may be half moved.
static volatile uint32_t resuming = NO;

static bool auth_read(install_auth_t *auth)
{
    const struct flash_area *fa;
    uint8_t area[INSTALL_AUTH_AREA_SIZE];
    int rc;

    if (flash_area_open(AUTH_ID, &fa) != 0) {
        return false;
    }
    rc = flash_area_read(fa, 0, area, sizeof(area));
    flash_area_close(fa);
    if (rc != 0) {
        return false;
    }
    install_auth_parse(area, auth);
    return true;
}

// Writes `auth` when it differs from `before`, as the next copy.
// A power loss in the middle leaves the copy before it.
static bool auth_store(const install_auth_t *before, install_auth_t *auth)
{
    const struct flash_area *fa;
    uint8_t rec[INSTALL_AUTH_COPY_SIZE];
    uint32_t off;
    int rc;

    if (memcmp(before, auth, sizeof(*auth)) == 0) {
        return true;
    }
    BOOT_LOG_INF("sigu: record %d -> %d, min_security %u, pending %u", (int)before->state,
                 (int)auth->state, (unsigned int)auth->min_security, (unsigned int)auth->pending);
    off = install_auth_encode(auth, rec);
    if (flash_area_open(AUTH_ID, &fa) != 0) {
        return false;
    }
    rc = flash_area_write(fa, off, rec, sizeof(rec));
    flash_area_close(fa);
    if (rc != 0) {
        BOOT_LOG_ERR("sigu: cannot write the install record");
    }
    return rc == 0;
}

static install_auth_swap_t swap_type(void)
{
    switch (boot_swap_type_multi(0)) {
    case BOOT_SWAP_TYPE_TEST:
        return INSTALL_AUTH_SWAP_TEST;
    case BOOT_SWAP_TYPE_PERM:
        return INSTALL_AUTH_SWAP_PERM;
    case BOOT_SWAP_TYPE_REVERT:
        return INSTALL_AUTH_SWAP_REVERT;
    default:
        return INSTALL_AUTH_SWAP_NONE;
    }
}

static bool slot0_state(install_auth_slot0_t *slot0)
{
    struct boot_swap_state st;

    if (boot_read_swap_state_by_id(FLASH_AREA_IMAGE_PRIMARY(0), &st) != 0) {
        return false;
    }
    slot0->magic = st.magic == BOOT_MAGIC_GOOD;
    slot0->copy_done = st.copy_done == BOOT_FLAG_SET;
    slot0->image_ok = st.image_ok == BOOT_FLAG_SET;
    return true;
}

// copy_done stops a resume (swap_status_source()), and image_ok stops a swap back.
// We read the flags back, because for a resume this write is the only check.
static bool close_slot0(void)
{
    const struct flash_area *fa;
    struct boot_swap_state st;
    bool ok = false;

    BOOT_LOG_WRN("sigu: slot0 trailer not from an install, closing it");
    if (flash_area_open(FLASH_AREA_IMAGE_PRIMARY(0), &fa) != 0) {
        return false;
    }
    if (boot_read_swap_state(fa, &st) == 0) {
        if (st.copy_done != BOOT_FLAG_SET) {
            (void)boot_write_copy_done(fa);
        }
        if (st.image_ok != BOOT_FLAG_SET) {
            (void)boot_write_image_ok(fa);
        }
        ok = boot_read_swap_state(fa, &st) == 0 && st.copy_done == BOOT_FLAG_SET &&
             st.image_ok == BOOT_FLAG_SET;
    }
    flash_area_close(fa);
    if (!ok) {
        BOOT_LOG_ERR("sigu: cannot close the slot0 trailer");
    }
    return ok;
}

// A broken magic is not a request.
// If this write fails, boot_perform_update_hook() still refuses the swap.
static void drop_request(void)
{
    const struct flash_area *fa;
    uint8_t zero[BOOT_MAGIC_ALIGN_SIZE] = {0};

    if (flash_area_open(FLASH_AREA_IMAGE_SECONDARY(0), &fa) != 0) {
        return;
    }
    (void)flash_area_write(fa, flash_area_get_size(fa) - sizeof(zero), zero, sizeof(zero));
    flash_area_close(fa);
}

static bool area_read(void *ctx, uint32_t off, void *buf, size_t len)
{
    const struct flash_area *fa = ctx;

    return off <= flash_area_get_size(fa) && len <= flash_area_get_size(fa) - off &&
           flash_area_read(fa, off, buf, len) == 0;
}

// The whole signed image in a slot, hashed as firmware.c hashes it for the panel,
// and its security counter.
static void image_read(uint8_t area_id, install_auth_image_t *out)
{
    const struct flash_area *fa;
    uint8_t buf[CHUNK];
    uint8_t info[FW_IMAGE_TLV_INFO_SIZE];
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    fw_image_t img;
    uint32_t total;
    size_t len;
    bool ok;

    memset(out, 0, sizeof(*out));
    if (psa_crypto_init() != PSA_SUCCESS || flash_area_open(area_id, &fa) != 0) {
        return;
    }
    ok = area_read((void *)fa, 0, buf, FW_IMAGE_HEADER_SIZE) && fw_image_parse(buf, &img) &&
         area_read((void *)fa, fw_image_tlv_offset(&img), info, sizeof(info)) &&
         fw_image_total(&img, info, &total) && total <= flash_area_get_size(fa) &&
         fw_image_security(&img, area_read, (void *)fa, &out->security) &&
         psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS;
    for (uint32_t off = 0; ok && off < total; off += CHUNK) {
        size_t n = total - off < CHUNK ? total - off : CHUNK;

        ok = area_read((void *)fa, off, buf, n) && psa_hash_update(&op, buf, n) == PSA_SUCCESS;
    }
    flash_area_close(fa);
    if (!ok) {
        psa_hash_abort(&op);
        return;
    }
    out->ok = psa_hash_finish(&op, out->hash, sizeof(out->hash), &len) == PSA_SUCCESS &&
              len == sizeof(out->hash);
    out->is_boot = img.load_addr == S0_ADDR || img.load_addr == S1_ADDR;
}

// For the log: why a request was dropped.
static const char *drop_reason(const install_auth_t *auth, const install_auth_image_t *slot1)
{
    if (!slot1->ok) {
        return "slot1 unreadable";
    }
    if (auth->state != INSTALL_AUTH_AUTHORIZED) {
        return "no OK on the panel";
    }
    if (memcmp(slot1->hash, auth->hash, INSTALL_AUTH_HASH_SIZE) != 0) {
        return "slot1 is not the image the panel showed";
    }
    return "below min_security";
}

// Keeps `pending` only if slot0 holds the authorized image.
// Hashing slot0 costs about as much as MCUboot's own check, and only on the boots of an install.
static void check_kept(install_auth_t *auth)
{
    install_auth_image_t now;

    if (auth->pending != 0) {
        image_read(FLASH_AREA_IMAGE_PRIMARY(0), &now);
        install_auth_check_kept(auth, &now);
    }
}

// NO when we must not boot.
static uint32_t check(void)
{
    install_auth_t before;
    install_auth_t auth;
    install_auth_slot0_t slot0;
    install_auth_swap_t swap;
    install_auth_image_t slot1;
    install_auth_image_t now;

    swap_allowed = NO;
    resuming = NO;
    if (!auth_read(&auth) || !slot0_state(&slot0)) {
        BOOT_LOG_ERR("sigu: cannot read the install record or the slot0 trailer");
        return NO;
    }
    before = auth;
    // In the middle of our swap slot0 is half moved, so its hash cannot match yet.
    // settle() checks it once the swap is done.
    if (auth.state != INSTALL_AUTH_SWAPPING) {
        check_kept(&auth);
    }
    if (install_auth_at_boot(&auth, &slot0) && !close_slot0()) {
        return NO;
    }
    if (!auth_store(&before, &auth)) {
        return NO;
    }
    // A reset in the middle of our swap: MCUboot finishes it, so let it.
    // SWAPPING exists only while our own swap runs, and settle() clears it before NS runs.
    // Change nothing, slot1 is half moved.
    if (auth.state == INSTALL_AUTH_SWAPPING) {
        resuming = YES;
        swap_allowed = YES;
        return YES;
    }
    before = auth;
    swap = swap_type();
    if (swap == INSTALL_AUTH_SWAP_NONE) {
        // An authorization is for the next boot only.
        auth.state = auth.state == INSTALL_AUTH_AUTHORIZED ? INSTALL_AUTH_IDLE : auth.state;
        return auth_store(&before, &auth) ? YES : NO;
    }
    image_read(FLASH_AREA_IMAGE_SECONDARY(0), &slot1);
    if (!install_auth_may_swap(&auth, swap, &slot1)) {
        if (swap == INSTALL_AUTH_SWAP_REVERT) {
            BOOT_LOG_WRN("sigu: swap back not to the app before the install, dropped");
            if (!close_slot0()) {
                return NO;
            }
        } else {
            BOOT_LOG_WRN("sigu: install dropped: %s (security %u)", drop_reason(&auth, &slot1),
                         (unsigned int)slot1.security);
            drop_request();
        }
        auth.state = auth.state == INSTALL_AUTH_AUTHORIZED ? INSTALL_AUTH_IDLE : auth.state;
        return auth_store(&before, &auth) ? YES : NO;
    }
    if (swap != INSTALL_AUTH_SWAP_REVERT) {
        // No valid app in slot0 leaves a zero hash, so nothing to swap back to.
        image_read(FLASH_AREA_IMAGE_PRIMARY(0), &now);
        memcpy(auth.revert, now.hash, sizeof(auth.revert));
    }
    // SWAPPING before the swap starts, so a reset in the middle can resume it.
    install_auth_start(&auth, swap, &slot1);
    // The same rule again, so a skipped branch above does not store SWAPPING.
    if (!install_auth_may_run(&auth, swap, &slot1)) {
        BOOT_LOG_ERR("sigu: swap failed the second check");
        return NO;
    }
    if (!auth_store(&before, &auth)) {
        return NO;
    }
    BOOT_LOG_INF("sigu: swap type %d authorized", (int)swap);
    swap_allowed = YES;
    return YES;
}

// After check(), before boot_go(), from flash again:
// slot0's trailer must be closed, unless our swap runs or a test app waits for its confirm.
// That is, check() would close nothing now.
static uint32_t verify_closed(void)
{
    install_auth_t auth;
    install_auth_slot0_t slot0;

    if (!auth_read(&auth) || !slot0_state(&slot0)) {
        return NO;
    }
    if (install_auth_at_boot(&auth, &slot0)) {
        BOOT_LOG_ERR("sigu: slot0 trailer still open");
        return NO;
    }
    return YES;
}

// The second check of a swap, independent of check(): the record and slot1 read again.
static uint32_t verify_swap(void)
{
    install_auth_t auth;
    install_auth_image_t slot1;

    if (!auth_read(&auth) || auth.state != INSTALL_AUTH_SWAPPING) {
        return NO;
    }
    // A boot before this one checked slot1 and stored SWAPPING.
    if (resuming == YES) {
        return YES;
    }
    image_read(FLASH_AREA_IMAGE_SECONDARY(0), &slot1);
    if (!install_auth_may_run(&auth, swap_type(), &slot1)) {
        return NO;
    }
    return YES;
}

// The swap is done, or there was none. NS must not run while SWAPPING allows a resume.
static uint32_t settle(void)
{
    install_auth_t before;
    install_auth_t auth;
    install_auth_slot0_t slot0;

    if (!auth_read(&auth)) {
        return NO;
    }
    if (auth.state != INSTALL_AUTH_SWAPPING) {
        return YES;
    }
    if (!slot0_state(&slot0)) {
        return NO;
    }
    before = auth;
    // boot_go() returned, so MCUboot checked slot0.
    // With a bad signature in slot1 there was no swap, and slot0 still holds the old app.
    check_kept(&auth);
    install_auth_after_swap(&auth, &slot0);
    if (auth.state == INSTALL_AUTH_SWAPPING) {
        BOOT_LOG_ERR("sigu: swap not finished");
        return NO;
    }
    return auth_store(&before, &auth) ? YES : NO;
}

// A failure returns FIH_FAILURE, and MCUboot's main() then panics.
fih_ret boot_go_hook(struct boot_rsp *rsp)
{
    FIH_DECLARE(fih_rc, FIH_FAILURE);
    volatile uint32_t checked;
    volatile uint32_t closed = NO;
    volatile uint32_t settled = NO;

    checked = check();
    if (checked != YES) {
        FIH_RET(FIH_FAILURE);
    }
    closed = verify_closed();
    if (checked != YES || closed != YES) {
        FIH_RET(FIH_FAILURE);
    }
    FIH_CALL(boot_go, fih_rc, rsp);
    if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
        FIH_RET(fih_rc);
    }
    settled = settle();
    if (settled != YES) {
        FIH_RET(FIH_FAILURE);
    }
    if (checked != YES || closed != YES || settled != YES) {
        FIH_RET(FIH_FAILURE);
    }
    FIH_RET(fih_rc);
}

// 0 skips the swap. MCUboot then validates slot0 and boots it.
// Image 0 is the app. Image 1 is MCUboot itself (the NCS second stage):
// a bootloader in slot1 is copied to the inactive s0/s1.
// Both take slot1, which check() read, so either may run, once.
int boot_perform_update_hook(int img_index, struct image_header *img_head,
                             const struct flash_area *area)
{
    volatile uint32_t again = NO;

    (void)img_head;
    (void)area;
    if (swap_allowed != YES) {
        BOOT_LOG_ERR("sigu: swap of image %d not checked, skipped", img_index);
        return 0;
    }
    again = verify_swap();
    if (again != YES) {
        swap_allowed = NO;
        BOOT_LOG_ERR("sigu: swap of image %d failed the second check, skipped", img_index);
        return 0;
    }
    if (swap_allowed == YES && again == YES) {
        swap_allowed = NO;
        return BOOT_HOOK_REGULAR;
    }
    return 0;
}

int boot_read_image_header_hook(int img_index, int slot, struct image_header *img_head)
{
    (void)img_index;
    (void)slot;
    (void)img_head;
    return BOOT_HOOK_REGULAR;
}

fih_ret boot_image_check_hook(int img_index, int slot)
{
    (void)img_index;
    (void)slot;
    FIH_RET(FIH_BOOT_HOOK_REGULAR);
}

int boot_read_swap_state_primary_slot_hook(int image_index, struct boot_swap_state *state)
{
    (void)image_index;
    (void)state;
    return BOOT_HOOK_REGULAR;
}

int boot_copy_region_post_hook(int img_index, const struct flash_area *area, size_t size)
{
    (void)img_index;
    (void)area;
    (void)size;
    return 0;
}

int boot_serial_uploaded_hook(int img_index, const struct flash_area *area, size_t size)
{
    (void)img_index;
    (void)area;
    (void)size;
    return 0;
}

int boot_img_install_stat_hook(int image_index, int slot, int *img_install_stat)
{
    (void)image_index;
    (void)slot;
    (void)img_install_stat;
    return BOOT_HOOK_REGULAR;
}
