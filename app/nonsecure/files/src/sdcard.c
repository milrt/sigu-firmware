// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/bitcoin_client.h"
#include "card_detect.h"
#include "export.h"
#include "install.h"
#include "bitcoin/psbt.h"
#include "bitcoin/psbt_signer.h"
#include <ctype.h>
#include <errno.h>
#include <ff.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/fs/fs.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/disk_access.h>
#include <zephyr/sys/base64.h>
#include <zephyr/sys/reboot.h>

LOG_MODULE_REGISTER(sdcard);

// The sd_job thread owns the card.
// Every second it checks the card and the firmware state,
// and every 200 ms it asks the partition for a job.
// A job (sign, install or export) runs on this thread too, so no check touches the card during it.

// FatFS finds the disk by the mount point, so it must match disk-name "SD" in the overlay.
#define MOUNT "/SD:"
#define DISK "SD"

#define POLL_MS 200
#define CHECK_POLLS 5

// Time for the panel to show "restarting..." before the chip resets.
#define RESTART_MS 2000

// "<base>-signed.psbt" for the longest "<base>.psbt" in the list.
#define SIGNED_SIZE (BITCOIN_FILE_NAME_MAX_SIZE + 7)
#define PATH_SIZE (sizeof(MOUNT "/") + SIGNED_SIZE)

// The base64 of the largest PSBT, with room for a trailing newline.
#define TEXT_SIZE (4 * ((BITCOIN_PSBT_FILE_MAX + 2) / 3) + 8)

#define STACK_SIZE 8192
#define PRIORITY 10

static FATFS fat_fs;
static struct fs_mount_t mnt = {
    .type = FS_FATFS,
    .fs_data = &fat_fs,
    .mnt_point = MOUNT,
};

static uint32_t card = BITCOIN_CARD_NONE;

// Static because they are too big for the stack. `names` is the NUL-padded list for the partition.
// `text` holds the file read, then the file to write.
// `raw` holds the decoded PSBT, then the signed one.
// psbt_create_from_bin() copies into psbt_heap, so both are free again after it.
static uint8_t text[TEXT_SIZE];
static uint8_t raw[BITCOIN_PSBT_FILE_MAX];
static struct fs_dirent entry;
static char names[BITCOIN_FILES_MAX][BITCOIN_FILE_NAME_MAX_SIZE];
static size_t count;

static const uint8_t magic[] = {'p', 's', 'b', 't', 0xff};

// Forced, so the next init starts the card again from CMD0 whatever the reference count is.
static void release_disk(void)
{
    bool force = true;

    disk_access_ioctl(DISK, DISK_IOCTL_CTRL_DEINIT, &force);
}

static bool ends_with(const char *s, size_t len, const char *end)
{
    size_t n = strlen(end);

    if (len < n) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (tolower((unsigned char)s[len - n + i]) != end[i]) {
            return false;
        }
    }
    return true;
}

// FAT names have any case. "._x.psbt" is macOS metadata.
// A name that does not fit the slot is left out, because a cut name would not open again.
static bool name_ok(const char *name)
{
    size_t len = strlen(name);

    return len < BITCOIN_FILE_NAME_MAX_SIZE && name[0] != '.' && ends_with(name, len, ".psbt") &&
           !ends_with(name, len, "-signed.psbt");
}

// FAT gives the entries in the order they were made. A sorted list is easier to read.
static void sort(void)
{
    char tmp[BITCOIN_FILE_NAME_MAX_SIZE];

    for (size_t i = 1; i < count; i++) {
        size_t j = i;

        memcpy(tmp, names[i], sizeof(tmp));
        while (j > 0 && strcmp(names[j - 1], tmp) > 0) {
            memcpy(names[j], names[j - 1], sizeof(tmp));
            j--;
        }
        memcpy(names[j], tmp, sizeof(tmp));
    }
}

static void read_dir(void)
{
    struct fs_dir_t dir;

    fs_dir_t_init(&dir);
    if (fs_opendir(&dir, MOUNT) != 0) {
        LOG_ERR("cannot open " MOUNT);
        return;
    }

    while (count < BITCOIN_FILES_MAX && fs_readdir(&dir, &entry) == 0 && entry.name[0] != '\0') {
        if (entry.type == FS_DIR_ENTRY_FILE && name_ok(entry.name)) {
            strcpy(names[count++], entry.name);
        }
    }

    fs_closedir(&dir);
    sort();
}

// What the last report sent.
// The lists change only on a scan, the firmware state also when health.c confirms a new app.
static uint8_t installs[INSTALL_RECORDS_SIZE];
static size_t n_installs;
static uint8_t sent_fw[BITCOIN_FW_STATE_SIZE];

// Sends the PSBT list, the install files and a fresh firmware state, without a rescan.
static void report(void)
{
    psa_status_t status;

    install_fw_state(sent_fw);
    status = bitcoin_client_files_set(names[0], count, card, sent_fw, installs, n_installs);
    if (status != PSA_SUCCESS) {
        LOG_ERR("files_set failed: %d", status);
    }
}

// Reports again when the firmware state changed, for example after the confirm.
static void check_fw(void)
{
    uint8_t fw[BITCOIN_FW_STATE_SIZE];

    install_fw_state(fw);
    if (memcmp(fw, sent_fw, sizeof(fw)) != 0) {
        report();
    }
}

// Scans the card: the PSBTs at the top and the install files.
// Both lists are empty when the card is not MOUNTED.
static void set_card(uint32_t c)
{
    card = c;
    count = 0;
    memset(names, 0, sizeof(names));
    if (card == BITCOIN_CARD_MOUNTED) {
        read_dir();
    }
    n_installs = install_scan(card == BITCOIN_CARD_MOUNTED, installs);
    report();
}

// A card in the slot that does not start or mount stays ERROR until it is pulled,
// so it is not tried again every second.
static void check_card(void)
{
    bool present = card_present();

    if (present && card == BITCOIN_CARD_NONE) {
        bool ok = disk_access_ioctl(DISK, DISK_IOCTL_CTRL_INIT, NULL) == 0 && fs_mount(&mnt) == 0;

        set_card(ok ? BITCOIN_CARD_MOUNTED : BITCOIN_CARD_ERROR);
    } else if (!present && card != BITCOIN_CARD_NONE) {
        if (card == BITCOIN_CARD_MOUNTED) {
            fs_unmount(&mnt);
        }
        release_disk();
        set_card(BITCOIN_CARD_NONE);
    }
}

// A file that fills `text` counts as too big, because it cannot be told from a longer one.
static uint32_t read_psbt(const char *path, size_t *len)
{
    struct fs_file_t f;
    ssize_t n;

    fs_file_t_init(&f);
    if (fs_open(&f, path, FS_O_READ) != 0) {
        return BITCOIN_FILES_READ_FAILED;
    }
    n = fs_read(&f, text, sizeof(text));
    fs_close(&f);

    if (n < 0) {
        return BITCOIN_FILES_READ_FAILED;
    }
    if (n == sizeof(text)) {
        return BITCOIN_FILES_TOO_BIG;
    }
    *len = n;
    return BITCOIN_FILES_OK;
}

static bool has_magic(const uint8_t *data, size_t len)
{
    return len >= sizeof(magic) && memcmp(data, magic, sizeof(magic)) == 0;
}

// A file is a binary PSBT (BIP174) or its base64, as BlueWallet writes it.
// A binary file is used where it is, a base64 one is decoded into `raw`.
static uint32_t decode_psbt(size_t len, const uint8_t **data, size_t *data_len, bool *b64)
{
    int rc;

    *b64 = !has_magic(text, len);
    if (!*b64) {
        *data = text;
        *data_len = len;
        return len > BITCOIN_PSBT_FILE_MAX ? BITCOIN_FILES_TOO_BIG : BITCOIN_FILES_OK;
    }

    while (len > 0 && isspace(text[len - 1])) {
        len--;
    }
    rc = base64_decode(raw, sizeof(raw), data_len, text, len);
    if (rc == -ENOMEM) {
        return BITCOIN_FILES_TOO_BIG;
    }
    if (rc != 0 || !has_magic(raw, *data_len)) {
        return BITCOIN_FILES_BAD_PSBT;
    }
    *data = raw;
    return BITCOIN_FILES_OK;
}

// A pulled card can leave half a file. A cut PSBT does not parse, so the coordinator refuses it.
static uint32_t write_file(const char *path, const uint8_t *data, size_t len)
{
    struct fs_file_t f;
    int rc;

    fs_file_t_init(&f);
    if (fs_open(&f, path, FS_O_CREATE | FS_O_WRITE | FS_O_TRUNC) != 0) {
        return BITCOIN_FILES_WRITE_FAILED;
    }
    rc = fs_write(&f, data, len) == (ssize_t)len ? fs_sync(&f) : -EIO;
    if (fs_close(&f) != 0 || rc != 0) {
        return BITCOIN_FILES_WRITE_FAILED;
    }
    return BITCOIN_FILES_OK;
}

// The signed file uses the encoding of the file it came from.
// The list only has names that end in ".psbt", in any case.
// The source is never opened for writing.
static uint32_t save(psbt_t *psbt, const char *name, bool b64)
{
    size_t base = strlen(name) - strlen(".psbt");
    size_t len = sizeof(raw);
    size_t text_len = 0;
    char path[PATH_SIZE];

    if (psbt_to_bin(psbt, raw, &len) != PSBT_OK) {
        return BITCOIN_FILES_WRITE_FAILED;
    }
    snprintf(path, sizeof(path), MOUNT "/%.*s-signed.psbt", (int)base, name);
    if (!b64) {
        return write_file(path, raw, len);
    }
    if (base64_encode(text, sizeof(text), &text_len, raw, len) != 0) {
        return BITCOIN_FILES_WRITE_FAILED;
    }
    return write_file(path, text, text_len);
}

static uint32_t sign_file(const char *name)
{
    char path[PATH_SIZE];
    psbt_t psbt;
    const uint8_t *data = NULL;
    size_t data_len = 0;
    size_t len = 0;
    bool b64 = false;
    uint32_t code;

    if (card != BITCOIN_CARD_MOUNTED) {
        return BITCOIN_FILES_NO_CARD;
    }
    if (strlen(name) < strlen(".psbt")) {
        return BITCOIN_FILES_READ_FAILED;
    }
    snprintf(path, sizeof(path), MOUNT "/%s", name);

    code = read_psbt(path, &len);
    if (code == BITCOIN_FILES_OK) {
        code = decode_psbt(len, &data, &data_len, &b64);
    }
    if (code != BITCOIN_FILES_OK) {
        return code;
    }
    if (psbt_create_from_bin(&psbt, data, data_len) != PSBT_OK) {
        return BITCOIN_FILES_BAD_PSBT;
    }

    // The review screen on the panel shows the transaction and takes the approval.
    if (psbt_sign(&psbt, &bitcoin_service, NULL) == PSBT_OK) {
        code = save(&psbt, name, b64);
    } else {
        code = BITCOIN_FILES_NOT_SIGNED;
    }
    psbt_free(&psbt);
    return code;
}

// A refused result means the panel already ended the job, with a cancel or a reject.
// The card is listed again after every job, because it may have changed during the review.
static void run_sign(const char *name)
{
    uint32_t code = sign_file(name);
    psa_status_t status = bitcoin_client_files_result(code);

    if (status != PSA_SUCCESS) {
        LOG_INF("card job %u ended on the panel first: %d", code, status);
    }
    set_card(card);
}

// An install job writes slot1, and the panel shows it.
// A commit job needs no card:
// MCUboot installs on the next boot, so NS restarts once the panel knows.
static void run_install(uint32_t kind)
{
    uint32_t code;
    psa_status_t status;

    if (kind == BITCOIN_JOB_INSTALL_COMMIT) {
        code = install_commit();
    } else {
        code = card == BITCOIN_CARD_MOUNTED ? install_run(kind) : BITCOIN_INSTALL_NO_CARD;
    }
    status = bitcoin_client_files_result(code);

    if (status != PSA_SUCCESS) {
        LOG_ERR("install result %u refused: %d", code, status);
    }
    if (code == BITCOIN_INSTALL_OK) {
        k_msleep(RESTART_MS);
        LOG_INF("restarting to install");
        sys_reboot(SYS_REBOOT_COLD);
    }
    set_card(card);
}

// The panel shows the fingerprint and the first address from the partition, to check the file.
// The card list has only PSBTs, so there is no rescan.
static void run_export(void)
{
    char name[EXPORT_NAME_SIZE];
    char path[PATH_SIZE];
    size_t len = 0;
    uint32_t code = BITCOIN_FILES_NO_CARD;
    psa_status_t status;

    if (card == BITCOIN_CARD_MOUNTED) {
        code = export_build((char *)text, sizeof(text), &len, name);
    }
    if (code == BITCOIN_FILES_OK) {
        snprintf(path, sizeof(path), MOUNT "/%s", name);
        code = write_file(path, text, len);
    }
    if (code == BITCOIN_FILES_OK) {
        LOG_INF("wallet saved to %s", path);
    } else {
        LOG_ERR("wallet export failed: %u", code);
    }
    status = bitcoin_client_files_result(code);
    if (status != PSA_SUCCESS) {
        LOG_INF("export ended on the panel first: %d", status);
    }
}

static void sd_thread(void *a, void *b, void *c)
{
    uint32_t polls = 0;
    uint32_t kind = BITCOIN_JOB_SIGN;
    char name[BITCOIN_FILE_NAME_MAX_SIZE];

    ARG_UNUSED(a);
    ARG_UNUSED(b);
    ARG_UNUSED(c);

    // The panel shows the firmware state without a card too.
    set_card(BITCOIN_CARD_NONE);
    for (;;) {
        if (polls++ % CHECK_POLLS == 0) {
            check_card();
            check_fw();
        }
        if (bitcoin_client_files_poll(name, &kind) == PSA_SUCCESS) {
            if (kind == BITCOIN_JOB_EXPORT) {
                run_export();
            } else if (kind != BITCOIN_JOB_SIGN) {
                run_install(kind);
            } else if (name[0] != '\0') {
                run_sign(name);
            }
        }
        k_msleep(POLL_MS);
    }
}

K_THREAD_DEFINE(sd_job, STACK_SIZE, sd_thread, NULL, NULL, NULL, PRIORITY, 0, 0);
