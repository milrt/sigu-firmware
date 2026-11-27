// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The flash: slot0, slot1, s0, s1 and the install record in RAM, at their device offsets.
// NS, the SP (sim/src/firmware_flash.c) and the real MCUboot (sim/mcuboot) all use it,
// through the flash map API.
// NS asks for an install with MCUboot's own bootutil_public.c, as Zephyr's dfu/mcuboot.c does,
// so every trailer is real bytes.
// "mcuboot" runs one MCUboot boot with our hooks.
//
// slot0 starts with a made-up signed image of the running version (app_version.h):
// a header, a body of i % 251 bytes, and a TLV area with its SHA-256, as the tests build theirs.
// The bootloader in s0/s1 is two numbers for NS ("boot s0|s1 <version>").
// Nothing restarts: a restart only logs "[SIM] reboot" and parks the thread.
// "boot ..." and "forge ..." write a trailer or slot1,
// as a past swap, a broken NS or a power loss would leave them.

#include "files/firmware.h"
#include "sched.h"
#include "shared/hash.h"
#include "sim.h"
#include "sim_mcuboot.h"
#include <app_version.h>
#include <errno.h>
#include <psa/crypto.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tfm_ioctl_api.h>
#include <bootutil/bootutil_public.h>
#include <zephyr/devicetree.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/reboot.h>

// In bootutil_public.c and bootutil_misc.c, declared only in the private bootutil_priv.h.
int boot_write_magic(const struct flash_area *fap);
int boot_write_copy_done(const struct flash_area *fap);
int boot_write_image_ok(const struct flash_area *fap);
int boot_write_swap_info(const struct flash_area *fap, uint8_t swap_type, uint8_t image_num);
uint32_t boot_status_off(const struct flash_area *fap);

#define IMAGE_SIZE 0x2000
#define HDR_SIZE 0x800
#define NS_ADDR 0x84000
// The TLV area: the info, then the SHA-256 TLV (IMAGE_TLV_SHA256).
#define TLV_INFO_SIZE 4
#define TLV_HASH_TYPE 0x10
#define TLV_AREA_SIZE (TLV_INFO_SIZE + 4 + 32)
// Room for MCUboot's trailer at the end of slot1, as install.c keeps it free.
#define TRAILER_AREA 0x2000

static uint8_t slot0[SIM_SIZE_slot0_partition];
static uint8_t slot1[SIM_SIZE_slot1_partition];
static uint8_t s0[SIM_SIZE_s0_partition];
static uint8_t s1[SIM_SIZE_s1_partition];
static uint8_t install[SIM_SIZE_sigu_install_partition];

#define AREA(label, buf)                                                                           \
    {.fa = {.fa_id = PARTITION_ID(label),                                                          \
            .fa_off = PARTITION_OFFSET(label),                                                     \
            .fa_size = PARTITION_SIZE(label)},                                                     \
     .mem = buf}

static struct {
    struct flash_area fa;
    uint8_t *mem;
} areas[SIM_AREAS] = {
    AREA(slot0_partition, slot0), AREA(slot1_partition, slot1),          AREA(s0_partition, s0),
    AREA(s1_partition, s1),       AREA(sigu_install_partition, install),
};

static bool ready;
static bool s0_active = true;
static uint32_t boot_version = 1;
static off_t last_record_write = -1; // the install record copy written last, for forge tear

// Power loss injection. While MCUboot boots, every write and erase counts.
// At `cut_at`, the write lands only in part, and the boot stops there, as at a power loss.
// RRAM writes whole 16-byte lines, so half of a longer write lands.
extern bool sim_mcuboot_booting;
static uint32_t writes;
static uint32_t cut_at;
static jmp_buf cut_env;
static uint8_t *saved[SIM_AREAS];

static void put_le(uint8_t *p, uint32_t v, int n)
{
    for (int i = 0; i < n; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

// The running app, laid out as imgtool does with ROM_FIXED, as NCS signs the app.
static void build_slot0(void)
{
    uint32_t body = IMAGE_SIZE - HDR_SIZE - TLV_AREA_SIZE;
    uint8_t *tlv = slot0 + HDR_SIZE + body;

    for (uint32_t i = 0; i < IMAGE_SIZE; i++) {
        slot0[i] = (uint8_t)(i % 251);
    }
    memset(slot0, 0, FW_IMAGE_HEADER_SIZE);
    put_le(slot0 + 0, 0x96f3b83d, 4);
    put_le(slot0 + 4, NS_ADDR, 4);
    put_le(slot0 + 8, HDR_SIZE, 2);
    put_le(slot0 + 12, body, 4);
    put_le(slot0 + 16, FW_IMAGE_F_ROM_FIXED, 4);
    slot0[20] = APP_VERSION_MAJOR;
    slot0[21] = APP_VERSION_MINOR;
    put_le(slot0 + 22, APP_PATCHLEVEL, 2);
    put_le(tlv, 0x6907, 2);
    put_le(tlv + 2, TLV_AREA_SIZE, 2);
    put_le(tlv + 4, TLV_HASH_TYPE, 2);
    put_le(tlv + 6, 32, 2);
    // MCUboot checks slot0 on every boot. Its hash covers the header and the body.
    if (psa_crypto_init() != PSA_SUCCESS ||
        hash_sha256(slot0, HDR_SIZE + body, tlv + 8, 32) != PSA_SUCCESS) {
        abort();
    }
}

static void init(void)
{
    if (ready) {
        return;
    }
    ready = true;
    for (int i = 0; i < SIM_AREAS; i++) {
        memset(areas[i].mem, 0xff, areas[i].fa.fa_size);
    }
    build_slot0();
}

static bool in_area(const struct flash_area *fa, off_t off, size_t len)
{
    return off >= 0 && (size_t)off <= fa->fa_size && len <= fa->fa_size - (size_t)off;
}

int flash_area_open(uint8_t id, const struct flash_area **fa)
{
    if (id >= SIM_AREAS) {
        return -ENOENT;
    }
    init();
    *fa = &areas[id].fa;
    return 0;
}

void flash_area_close(const struct flash_area *fa)
{
    (void)fa;
}

int flash_area_read(const struct flash_area *fa, off_t off, void *dst, size_t len)
{
    if (!in_area(fa, off, len)) {
        return -EINVAL;
    }
    memcpy(dst, areas[fa->fa_id].mem + off, len);
    return 0;
}

static void count_write(uint8_t *dst, uint8_t fill, const void *src, size_t len)
{
    size_t part = len / 2 / 16 * 16;

    if (!sim_mcuboot_booting || ++writes != cut_at) {
        return;
    }
    if (src) {
        memcpy(dst, src, part);
    } else {
        memset(dst, fill, part);
    }
    longjmp(cut_env, 1);
}

int flash_area_write(const struct flash_area *fa, off_t off, const void *src, size_t len)
{
    if (!in_area(fa, off, len)) {
        return -EINVAL;
    }
    count_write(areas[fa->fa_id].mem + off, 0, src, len);
    memcpy(areas[fa->fa_id].mem + off, src, len);
    if (fa->fa_id == PARTITION_ID(sigu_install_partition)) {
        last_record_write = off;
    }
    return 0;
}

int flash_area_erase(const struct flash_area *fa, off_t off, size_t len)
{
    if (!in_area(fa, off, len)) {
        return -EINVAL;
    }
    count_write(areas[fa->fa_id].mem + off, 0xff, NULL, len);
    memset(areas[fa->fa_id].mem + off, 0xff, len);
    return 0;
}

// RRAM writes 16 bytes at a time.
uint32_t flash_area_align(const struct flash_area *fa)
{
    (void)fa;
    return 16;
}

uint8_t flash_area_erased_val(const struct flash_area *fa)
{
    (void)fa;
    return 0xff;
}

// Zephyr's subsys/dfu/boot/mcuboot.c.
int boot_request_upgrade_multi(int image_index, int permanent)
{
    return boot_set_pending_multi(image_index, permanent) == 0 ? 0 : -EFAULT;
}

int mcuboot_swap_type_multi(int image_index)
{
    return boot_swap_type_multi(image_index);
}

int boot_write_img_confirmed_multi(int image_index)
{
    bool test = boot_swap_type_multi(image_index) == BOOT_SWAP_TYPE_REVERT;

    if (boot_set_confirmed_multi(image_index) != 0) {
        return -EIO;
    }
    if (test) {
        fprintf(stderr, "[SIM] confirmed\n");
    }
    return 0;
}

void sys_reboot(int type)
{
    (void)type;
    fprintf(stderr, "[SIM] reboot\n");
    for (;;) {
        sched_sleep_ms(1000);
    }
}

// Only the running slot has a version. The other one reads as empty, as after b0 started it.
int tfm_platform_firmware_info(uint32_t fw_address, struct fw_info *info)
{
    uint32_t running = s0_active ? DT_REG_ADDR(DT_NODELABEL(s0_partition))
                                 : DT_REG_ADDR(DT_NODELABEL(s1_partition));
    const uint32_t magic[] = {FIRMWARE_INFO_MAGIC};

    if (fw_address != running) {
        return -EINVAL;
    }
    memset(info, 0, sizeof(*info));
    memcpy(info->magic, magic, sizeof(magic));
    info->version = boot_version;
    info->address = fw_address;
    info->valid = CONFIG_FW_INFO_VALID_VAL;
    return 0;
}

int tfm_platform_s0_active(uint32_t s0_address, uint32_t s1_address, bool *active)
{
    (void)s0_address;
    (void)s1_address;
    *active = s0_active;
    return 0;
}

void sim_boot_set(bool s0, uint32_t version)
{
    s0_active = s0;
    boot_version = version;
}

static const struct flash_area *slot0_area(void)
{
    const struct flash_area *fa;

    flash_area_open(PARTITION_ID(slot0_partition), &fa);
    return fa;
}

static void clear_trailer(const struct flash_area *fa)
{
    flash_area_erase(fa, (off_t)(fa->fa_size - TRAILER_AREA), TRAILER_AREA);
}

// As MCUboot leaves slot0 after a test swap: the magic, copy_done, no image_ok.
void sim_boot_unconfirmed(void)
{
    const struct flash_area *fa = slot0_area();

    clear_trailer(fa);
    boot_write_swap_info(fa, BOOT_SWAP_TYPE_TEST, 0);
    boot_write_copy_done(fa);
    boot_write_magic(fa);
}

// As MCUboot leaves slot0 after it swapped a failed test app back.
void sim_boot_failed(void)
{
    const struct flash_area *fa = slot0_area();

    clear_trailer(fa);
    boot_write_swap_info(fa, BOOT_SWAP_TYPE_REVERT, 0);
    boot_write_image_ok(fa);
    boot_write_magic(fa);
}

bool sim_slot1_dump(const char *path)
{
    FILE *f = fopen(path, "wb");
    bool ok;

    if (!f) {
        return false;
    }
    init();
    ok = fwrite(slot1, 1, sizeof(slot1), f) == sizeof(slot1);
    return fclose(f) == 0 && ok;
}

void sim_mcuboot(uint32_t cut)
{
    init();
    writes = 0;
    cut_at = cut;
    if (setjmp(cut_env) == 0) {
        sim_mcuboot_boot();
        fprintf(stderr, "[SIM] mcuboot: %u flash writes\n", (unsigned int)writes);
    } else {
        sim_mcuboot_booting = false;
        fprintf(stderr, "[SIM] power cut at flash write %u\n", (unsigned int)cut);
    }
    cut_at = 0;
}

// All flash, to try one boot from the same state again.
void sim_flash_snapshot(void)
{
    init();
    for (int i = 0; i < SIM_AREAS; i++) {
        if (!saved[i]) {
            saved[i] = malloc(areas[i].fa.fa_size);
        }
        memcpy(saved[i], areas[i].mem, areas[i].fa.fa_size);
    }
}

bool sim_flash_restore(void)
{
    for (int i = 0; i < SIM_AREAS; i++) {
        if (!saved[i]) {
            return false;
        }
        memcpy(areas[i].mem, saved[i], areas[i].fa.fa_size);
    }
    return true;
}

bool sim_slot0_dump(const char *path)
{
    FILE *f = fopen(path, "wb");
    bool ok;

    if (!f) {
        return false;
    }
    init();
    ok = fwrite(slot0, 1, sizeof(slot0), f) == sizeof(slot0);
    return fclose(f) == 0 && ok;
}

void sim_forge_request(bool permanent)
{
    boot_request_upgrade_multi(0, permanent);
}

void sim_forge_byte(uint32_t off)
{
    init();
    if (off < sizeof(slot1)) {
        slot1[off] ^= 0x01;
    }
}

// As a malicious NS: writes a host file to the start of slot1.
// NS owns slot1, so it can do this at any time,
// also between the panel's read and the install press, and after it.
bool sim_forge_slot1(const char *path)
{
    FILE *f = fopen(path, "rb");
    size_t n;

    if (!f) {
        return false;
    }
    init();
    n = fread(slot1, 1, sizeof(slot1), f);
    fclose(f);
    fprintf(stderr, "[SIM] NS wrote %u bytes to slot1\n", (unsigned int)n);
    return true;
}

// A power loss in the SP's next record write: only the first `words` 32-bit words land.
// The SP writes word by word on the device (Driver_FLASH0).
static int auth_cut_words = -1;

void sim_forge_auth_cut(int words)
{
    auth_cut_words = words;
}

bool sim_auth_cut_take(uint32_t *words)
{
    if (auth_cut_words < 0) {
        return false;
    }
    *words = (uint32_t)auth_cut_words;
    auth_cut_words = -1;
    return true;
}

// slot0's trailer as in the middle of a swap:
// the magic, no copy_done, no image_ok, and one status entry, so MCUboot would resume.
void sim_forge_resume(void)
{
    const struct flash_area *fa = slot0_area();
    uint8_t status[16];

    memset(status, 0xff, sizeof(status));
    status[0] = 0x01;
    clear_trailer(fa);
    boot_write_swap_info(fa, BOOT_SWAP_TYPE_TEST, 0);
    flash_area_write(fa, (off_t)boot_status_off(fa), status, sizeof(status));
    boot_write_magic(fa);
}

void sim_forge_clear(void)
{
    const struct flash_area *fa;

    flash_area_open(PARTITION_ID(slot1_partition), &fa);
    clear_trailer(fa);
}

// A power loss in the middle of the last record write: that copy fails its CRC.
void sim_forge_tear(void)
{
    init();
    if (last_record_write >= 0) {
        install[last_record_write + INSTALL_AUTH_COPY_SIZE / 2] ^= 0x01;
        fprintf(stderr, "[SIM] record copy at %d torn\n", (int)last_record_write);
    }
}

static char keep_path[512];

// Every area, in the order of the table.
static void flash_save(void)
{
    FILE *f = fopen(keep_path, "wb");

    if (!f) {
        return;
    }
    for (int i = 0; i < SIM_AREAS; i++) {
        fwrite(areas[i].mem, 1, areas[i].fa.fa_size, f);
    }
    fclose(f);
}

void sim_flash_keep(const char *dir)
{
    FILE *f;

    snprintf(keep_path, sizeof(keep_path), "%s/flash.bin", dir);
    init();
    f = fopen(keep_path, "rb");
    if (f) {
        for (int i = 0; i < SIM_AREAS; i++) {
            if (fread(areas[i].mem, 1, areas[i].fa.fa_size, f) != areas[i].fa.fa_size) {
                break;
            }
        }
        fclose(f);
    }
    atexit(flash_save);
}
