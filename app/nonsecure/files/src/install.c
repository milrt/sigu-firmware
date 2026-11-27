// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "install.h"
#include "shared/fw_image.h"
#include "shared/hash.h"
#include "shared/wire.h"
#include <bootutil/bootutil_public.h>
#include <fw_info.h>
#include <stdbool.h>
#include <string.h>
#include <tfm_ioctl_api.h>
#include <zephyr/devicetree.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/fs/fs.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>

LOG_MODULE_REGISTER(install);

#define APP_PATH "/SD:/sigu-app.bin"
#define BOOT_S0_PATH "/SD:/sigu-mcuboot-s0.bin"
#define BOOT_S1_PATH "/SD:/sigu-mcuboot-s1.bin"

#define S0_ADDR DT_REG_ADDR(DT_NODELABEL(s0_partition))
#define S1_ADDR DT_REG_ADDR(DT_NODELABEL(s1_partition))
#define S_SIZE DT_REG_SIZE(DT_NODELABEL(s0_partition))
#define SLOT1_ID PARTITION_ID(slot1_partition)
#define SLOT1_SIZE PARTITION_SIZE(slot1_partition)

// Room for the swap-using-move trailer at the end of slot1:
// 3 x 16 bytes of status for each of its 156 sectors, plus the magic and flags.
// MCUboot makes the exact check.
#define TRAILER_SIZE 0x2000

// fw_info sits at one of these offsets from the image start. b0 looks at the same ones.
static const uint32_t fw_info_offsets[] = {0x0, 0x200, 0x400, 0x600, 0x800, 0xe00, 0x1000};
#define FW_INFO_SCAN_SIZE (0x1000 + sizeof(struct fw_info))

#define CHUNK 1024

struct app {
    bool present;
    uint8_t state;
    fw_image_t img;
    size_t size;
    uint8_t hash[BITCOIN_INSTALL_HASH_SIZE];
};

struct boot {
    bool present;
    uint8_t state;
    uint32_t version;
};

// What the panel shows.
static struct app shown_app;
static struct boot shown_boot;

// Static because they are too big for the stack.
static uint8_t head[FW_INFO_SCAN_SIZE];
static uint8_t chunk[CHUNK];
static uint8_t check[CHUNK];

// False on a short file.
static bool read_at(const char *path, off_t off, void *buf, size_t len)
{
    struct fs_file_t f;
    bool ok;

    fs_file_t_init(&f);
    if (fs_open(&f, path, FS_O_READ) != 0) {
        return false;
    }
    ok = fs_seek(&f, off, FS_SEEK_SET) == 0 && fs_read(&f, buf, len) == (ssize_t)len;
    fs_close(&f);
    return ok;
}

// -1 when the file is not there.
static ssize_t file_size(const char *path)
{
    static struct fs_dirent entry;

    if (fs_stat(path, &entry) != 0 || entry.type != FS_DIR_ENTRY_FILE) {
        return -1;
    }
    return (ssize_t)entry.size;
}

// The b0 version counter of the image in `buf`, or -1 when it has no valid fw_info.
static int64_t fw_info_version(const uint8_t *buf, size_t len)
{
    const uint32_t magic[] = {FIRMWARE_INFO_MAGIC};

    for (size_t i = 0; i < sizeof(fw_info_offsets) / sizeof(fw_info_offsets[0]); i++) {
        size_t at = fw_info_offsets[i];
        struct fw_info info;

        if (at + sizeof(info) > len) {
            break;
        }
        memcpy(&info, buf + at, sizeof(info));
        if (memcmp(info.magic, magic, sizeof(magic)) == 0 &&
            info.valid == CONFIG_FW_INFO_VALID_VAL) {
            return info.version;
        }
    }
    return -1;
}

// The b0 version of the running bootloader, 0 when TF-M cannot tell.
static uint32_t running_boot(bool *s0_active)
{
    struct fw_info info;

    if (tfm_platform_s0_active(S0_ADDR, S1_ADDR, s0_active) != 0 ||
        tfm_platform_firmware_info(*s0_active ? S0_ADDR : S1_ADDR, &info) != 0) {
        LOG_ERR("cannot read the running bootloader");
        return 0;
    }
    return info.version;
}

// Reads the whole file in chunks. With `fa`, it also writes each chunk to slot1 and reads it back.
// `hash` gets the SHA-256 of the bytes read.
static uint32_t stream(const char *path, size_t len, const struct flash_area *fa, uint8_t *hash)
{
    size_t align = fa ? flash_area_align(fa) : 1;
    hash_sha256_stream_t sha;
    uint32_t code = BITCOIN_INSTALL_OK;
    struct fs_file_t f;
    size_t done = 0;

    if (hash_sha256_stream_init(&sha) != PSA_SUCCESS) {
        return BITCOIN_INSTALL_READ_FAILED;
    }
    fs_file_t_init(&f);
    if (fs_open(&f, path, FS_O_READ) != 0) {
        hash_sha256_stream_abort(&sha);
        return BITCOIN_INSTALL_READ_FAILED;
    }
    while (code == BITCOIN_INSTALL_OK && done < len) {
        size_t n = len - done < CHUNK ? len - done : CHUNK;
        size_t padded = (n + align - 1) / align * align;

        if (fs_read(&f, chunk, n) != (ssize_t)n ||
            hash_sha256_stream_update(&sha, chunk, n) != PSA_SUCCESS) {
            code = BITCOIN_INSTALL_READ_FAILED;
            break;
        }
        memset(chunk + n, 0xff, padded - n);
        if (fa &&
            (flash_area_write(fa, done, chunk, padded) != 0 ||
             flash_area_read(fa, done, check, padded) != 0 || memcmp(chunk, check, padded) != 0)) {
            code = BITCOIN_INSTALL_WRITE_FAILED;
            break;
        }
        done += n;
    }
    fs_close(&f);
    if (code != BITCOIN_INSTALL_OK ||
        hash_sha256_stream_finish(&sha, hash, BITCOIN_INSTALL_HASH_SIZE) != PSA_SUCCESS) {
        hash_sha256_stream_abort(&sha);
        return code != BITCOIN_INSTALL_OK ? code : BITCOIN_INSTALL_READ_FAILED;
    }
    return BITCOIN_INSTALL_OK;
}

// The app file: a signed image that ends with its last TLV, not for s0/s1,
// and small enough for slot1 with its trailer.
// The hash covers the whole file.
static void scan_app(struct app *a)
{
    ssize_t size = file_size(APP_PATH);
    uint8_t hdr[FW_IMAGE_HEADER_SIZE];
    uint8_t info[FW_IMAGE_TLV_INFO_SIZE];
    uint32_t total;

    memset(a, 0, sizeof(*a));
    if (size < 0) {
        return;
    }
    a->present = true;
    a->state = BITCOIN_INSTALL_STATE_INVALID;
    a->size = size;
    if ((size_t)size > SLOT1_SIZE - TRAILER_SIZE || !read_at(APP_PATH, 0, hdr, sizeof(hdr)) ||
        !fw_image_parse(hdr, &a->img) || a->img.load_addr == S0_ADDR ||
        a->img.load_addr == S1_ADDR ||
        !read_at(APP_PATH, fw_image_tlv_offset(&a->img), info, sizeof(info)) ||
        !fw_image_total(&a->img, info, &total) || total != (size_t)size ||
        stream(APP_PATH, size, NULL, a->hash) != BITCOIN_INSTALL_OK) {
        return;
    }
    a->state = BITCOIN_INSTALL_STATE_OK;
}

// The b0 version of one bootloader file, linked for `addr`. -1 when it is not one.
static int64_t boot_version(const char *path, uint32_t addr)
{
    ssize_t size = file_size(path);
    fw_image_t img;

    if (size < (ssize_t)FW_INFO_SCAN_SIZE || (size_t)size > S_SIZE ||
        !read_at(path, 0, head, sizeof(head)) || !fw_image_parse(head, &img) ||
        !(img.flags & FW_IMAGE_F_ROM_FIXED) || img.load_addr != addr) {
        return -1;
    }
    return fw_info_version(head, sizeof(head));
}

// A bootloader needs both files, one linked for s0 and one for s1.
// NS writes the one for the slot that does not run.
static void scan_boot(struct boot *b)
{
    bool s0 = file_size(BOOT_S0_PATH) >= 0;
    bool s1 = file_size(BOOT_S1_PATH) >= 0;
    int64_t v0;
    int64_t v1;

    memset(b, 0, sizeof(*b));
    if (!s0 && !s1) {
        return;
    }
    b->present = true;
    if (!s0 || !s1) {
        b->state = BITCOIN_INSTALL_STATE_INCOMPLETE;
        return;
    }
    v0 = boot_version(BOOT_S0_PATH, S0_ADDR);
    v1 = boot_version(BOOT_S1_PATH, S1_ADDR);
    if (v0 < 0 || v0 != v1) {
        b->state = BITCOIN_INSTALL_STATE_INVALID;
        return;
    }
    b->state = BITCOIN_INSTALL_STATE_OK;
    b->version = (uint32_t)v0;
}

static void put_record(wire_w *w, uint8_t kind, uint8_t state, const fw_image_t *img, uint32_t boot,
                       const uint8_t *hash)
{
    static const uint8_t zero[BITCOIN_INSTALL_HASH_SIZE];

    wire_put_u8(w, kind);
    wire_put_u8(w, state);
    wire_put_u8(w, img ? img->major : 0);
    wire_put_u8(w, img ? img->minor : 0);
    wire_put_le(w, img ? img->revision : 0, 2);
    wire_put_le32(w, boot);
    wire_put_field(w, hash ? hash : zero, BITCOIN_INSTALL_HASH_SIZE, BITCOIN_INSTALL_HASH_SIZE);
}

size_t install_scan(bool mounted, uint8_t records[INSTALL_RECORDS_SIZE])
{
    wire_w w = wire_writer(records, INSTALL_RECORDS_SIZE);
    size_t n = 0;

    memset(&shown_app, 0, sizeof(shown_app));
    memset(&shown_boot, 0, sizeof(shown_boot));
    if (!mounted) {
        return 0;
    }
    scan_app(&shown_app);
    scan_boot(&shown_boot);
    if (shown_app.present) {
        put_record(&w, BITCOIN_INSTALL_APP, shown_app.state, &shown_app.img, 0, shown_app.hash);
        n++;
    }
    if (shown_boot.present) {
        put_record(&w, BITCOIN_INSTALL_BOOT, shown_boot.state, NULL, shown_boot.version, NULL);
        n++;
    }
    return w.ok ? n : 0;
}

// When MCUboot starts to swap a failed test app back,
// it writes REVERT as the swap type into slot0's trailer.
// That stays until the next install.
// NS reports it on every boot, and the partition shows it once per rollback.
static bool install_failed(void)
{
    static bool logged;
    struct boot_swap_state st;
    bool revert = boot_read_swap_state_by_id(PARTITION_ID(slot0_partition), &st) == 0 &&
                  st.magic == BOOT_MAGIC_GOOD && st.swap_type == BOOT_SWAP_TYPE_REVERT;

    if (revert && !logged) {
        LOG_WRN("last firmware install failed");
        logged = true;
    }
    return revert;
}

// A new app runs as a test until health.c confirms it.
// That shows as REVERT on the slot pair, while install_failed() reads slot0's own trailer,
// so check this one first.
static uint8_t fw_status(void)
{
    static bool logged;

    if (mcuboot_swap_type_multi(0) == BOOT_SWAP_TYPE_REVERT) {
        if (!logged) {
            LOG_INF("install confirming");
            logged = true;
        }
        return BITCOIN_FW_CONFIRMING;
    }
    return install_failed() ? BITCOIN_FW_FAILED : BITCOIN_FW_OK;
}

// The sd_job thread calls this every second. The boot version cannot change before a reset.
void install_fw_state(uint8_t out[BITCOIN_FW_STATE_SIZE])
{
    static bool have_boot;
    static uint32_t boot;
    wire_w w = wire_writer(out, BITCOIN_FW_STATE_SIZE);
    bool s0_active;

    if (!have_boot) {
        boot = running_boot(&s0_active);
        have_boot = true;
    }
    wire_put_le32(&w, boot);
    wire_put_u8(&w, fw_status());
}

// Erases slot1 and copies the file. `hash` gets the SHA-256 of what was written.
static uint32_t write_slot1(const char *path, size_t len, uint8_t *hash)
{
    const struct flash_area *fa;
    uint32_t code;

    if (flash_area_open(SLOT1_ID, &fa) != 0) {
        return BITCOIN_INSTALL_WRITE_FAILED;
    }
    if (flash_area_erase(fa, 0, fa->fa_size) != 0) {
        code = BITCOIN_INSTALL_WRITE_FAILED;
    } else {
        code = stream(path, len, fa, hash);
    }
    flash_area_close(fa);
    return code;
}

// The app the panel showed, the same bytes.
static uint32_t write_app(void)
{
    uint8_t hash[BITCOIN_INSTALL_HASH_SIZE];
    uint32_t code;

    if (!shown_app.present || shown_app.state != BITCOIN_INSTALL_STATE_OK) {
        return BITCOIN_INSTALL_BAD_FILE;
    }
    if (file_size(APP_PATH) != (ssize_t)shown_app.size) {
        return BITCOIN_INSTALL_CHANGED;
    }
    code = write_slot1(APP_PATH, shown_app.size, hash);
    if (code == BITCOIN_INSTALL_OK && memcmp(hash, shown_app.hash, sizeof(hash)) != 0) {
        return BITCOIN_INSTALL_CHANGED;
    }
    return code;
}

// The bootloader the panel showed, the same version.
// b0 starts the slot with the higher version, so it must be above the running one.
static uint32_t write_boot(void)
{
    uint8_t hash[BITCOIN_INSTALL_HASH_SIZE];
    struct boot now;
    bool s0_active;
    uint32_t running = running_boot(&s0_active);
    const char *path = s0_active ? BOOT_S1_PATH : BOOT_S0_PATH;
    ssize_t size;

    if (!shown_boot.present || shown_boot.state != BITCOIN_INSTALL_STATE_OK) {
        return BITCOIN_INSTALL_BAD_FILE;
    }
    scan_boot(&now);
    if (now.state != BITCOIN_INSTALL_STATE_OK || now.version != shown_boot.version) {
        return BITCOIN_INSTALL_CHANGED;
    }
    if (running == 0) {
        return BITCOIN_INSTALL_READ_FAILED;
    }
    if (now.version <= running) {
        return BITCOIN_INSTALL_NOT_NEWER;
    }
    size = file_size(path);
    if (size < 0) {
        return BITCOIN_INSTALL_READ_FAILED;
    }
    return write_slot1(path, size, hash);
}

// What the last install job wrote to slot1, for install_commit(). 0 when nothing.
static uint32_t staged;

uint32_t install_run(uint32_t job)
{
    bool boot = job == BITCOIN_JOB_INSTALL_BOOT;
    uint32_t code;

    staged = 0;
    // slot1 holds the old app that MCUboot swaps back to, until the new one is confirmed.
    if (mcuboot_swap_type_multi(0) == BOOT_SWAP_TYPE_REVERT) {
        LOG_WRN("the running app is not confirmed yet");
        return BITCOIN_INSTALL_PENDING;
    }
    code = boot ? write_boot() : write_app();
    if (code != BITCOIN_INSTALL_OK) {
        if (code == BITCOIN_INSTALL_CHANGED) {
            LOG_WRN("the install file changed since the scan");
        }
        return code;
    }
    staged = job;
    if (boot) {
        LOG_INF("install boot v%u written to slot1", shown_boot.version);
    } else {
        LOG_INF("install app %u.%u.%u written to slot1", shown_app.img.major, shown_app.img.minor,
                shown_app.img.revision);
    }
    return BITCOIN_INSTALL_STAGED;
}

uint32_t install_commit(void)
{
    bool boot = staged == BITCOIN_JOB_INSTALL_BOOT;

    if (staged == 0) {
        return BITCOIN_INSTALL_BAD_FILE;
    }
    if (mcuboot_swap_type_multi(0) == BOOT_SWAP_TYPE_REVERT) {
        return BITCOIN_INSTALL_PENDING;
    }
    // The trailer goes at the end of slot1 for both kinds,
    // and MCUboot picks the image by its load address.
    // The app boots as a test. b0 owns s0/s1 and never swaps back, so a bootloader is permanent.
    // Not boot_request_upgrade():
    // without FLASH_AREA_IMAGE_SECONDARY in Zephyr's mcuboot.c it is an empty stub that returns 0.
    // We read the trailer back, so a stub like that fails here and not after the restart.
    if (boot_request_upgrade_multi(0, boot ? BOOT_UPGRADE_PERMANENT : BOOT_UPGRADE_TEST) != 0 ||
        mcuboot_swap_type_multi(0) != (boot ? BOOT_SWAP_TYPE_PERM : BOOT_SWAP_TYPE_TEST)) {
        return BITCOIN_INSTALL_WRITE_FAILED;
    }
    staged = 0;
    LOG_INF("install requested");
    return BITCOIN_INSTALL_OK;
}
