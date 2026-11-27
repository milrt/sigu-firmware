// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// PSA Protected Storage and Internal Trusted Storage as one file per UID,
// "<uid>.ps" and "<uid>.its" in one folder.
// The file holds the create flags and then the data.
// There is no encryption here: on the host, anyone who can read the folder can read the blob.
// The PS blob is still the AES-GCM record from key_storage.c, so the PIN still guards the seed.

// glibc declares nftw() only with it. macOS ignores it.
#define _GNU_SOURCE

#include "sched.h"
#include "sim.h"
#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <psa/internal_trusted_storage.h>
#include <psa/protected_storage.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PS_MAX_SIZE 4096
#define PS ".ps"
#define ITS ".its"

static char root[PATH_MAX];
static bool temp_root;

static int rm_entry(const char *path, const struct stat *st, int flag, struct FTW *ftw)
{
    (void)st;
    (void)flag;
    (void)ftw;
    return remove(path);
}

static void cleanup(void)
{
    if (temp_root) {
        nftw(root, rm_entry, 8, FTW_DEPTH | FTW_PHYS);
    }
}

bool sim_ps_init(const char *dir)
{
    if (!dir) {
        const char *tmp = getenv("TMPDIR");

        snprintf(root, sizeof(root), "%s/sigu-sim-ps.XXXXXX", tmp ? tmp : "/tmp");
        if (!mkdtemp(root)) {
            return false;
        }
        temp_root = true;
        atexit(cleanup);
        return true;
    }
    snprintf(root, sizeof(root), "%s", dir);
    return mkdir(root, 0700) == 0 || errno == EEXIST;
}

// Fault injection for the tests. Counts the PS writes (set and remove) from the "ps" command on.
// ITS writes are not counted.
// At write `fault_at`: CUT ends the process before the write lands, as a power loss just before it.
// CUT_AFTER ends it right after. FAIL makes that one write return a storage failure.
enum { FAULT_NONE, FAULT_CUT, FAULT_CUT_AFTER, FAULT_FAIL };
static int fault_mode;
static uint32_t fault_at;
static uint32_t fault_writes;

void sim_ps_fault(const char *mode, uint32_t at)
{
    sched_lock();
    fault_mode = !strcmp(mode, "cut")        ? FAULT_CUT
                 : !strcmp(mode, "cutafter") ? FAULT_CUT_AFTER
                 : !strcmp(mode, "fail")     ? FAULT_FAIL
                                             : FAULT_NONE;
    fault_at = at;
    fault_writes = 0;
    sched_unlock();
}

static void power_loss(const char *when)
{
    fprintf(stderr, "[SIM] power cut %s PS write %u\n", when, (unsigned int)fault_writes);
    _exit(75);
}

// With the lock held, before a PS write. True when this write must fail.
static bool fault_before(const char *ext)
{
    if (strcmp(ext, PS) != 0 || fault_mode == FAULT_NONE || ++fault_writes != fault_at) {
        return false;
    }
    if (fault_mode == FAULT_CUT) {
        power_loss("before");
    }
    if (fault_mode == FAULT_FAIL) {
        fprintf(stderr, "[SIM] PS write %u fails\n", (unsigned int)fault_writes);
        return true;
    }
    return false;
}

static void fault_after(const char *ext)
{
    if (!strcmp(ext, PS) && fault_mode == FAULT_CUT_AFTER && fault_writes == fault_at) {
        power_loss("after");
    }
}

static void uid_path(const char *ext, psa_storage_uid_t uid, char *out, size_t n)
{
    snprintf(out, n, "%s/%016llx%s", root, (unsigned long long)uid, ext);
}

// Reads the whole object. Returns PSA_ERROR_DOES_NOT_EXIST if there is none.
static psa_status_t load(const char *ext, psa_storage_uid_t uid, uint32_t *flags, uint8_t *data,
                         size_t *len)
{
    char path[PATH_MAX];
    FILE *f;
    size_t n;

    uid_path(ext, uid, path, sizeof(path));
    f = fopen(path, "rb");
    if (!f) {
        return errno == ENOENT ? PSA_ERROR_DOES_NOT_EXIST : PSA_ERROR_STORAGE_FAILURE;
    }
    n = fread(flags, 1, sizeof(*flags), f);
    *len = n == sizeof(*flags) ? fread(data, 1, PS_MAX_SIZE, f) : 0;
    fclose(f);
    return n == sizeof(*flags) ? PSA_SUCCESS : PSA_ERROR_DATA_CORRUPT;
}

static psa_status_t obj_set(const char *ext, psa_storage_uid_t uid, size_t data_length,
                            const void *p_data, psa_storage_create_flags_t create_flags)
{
    static uint8_t old[PS_MAX_SIZE];
    char path[PATH_MAX];
    char tmp[PATH_MAX + 4];
    uint32_t flags;
    size_t len;
    psa_status_t status = PSA_ERROR_STORAGE_FAILURE;
    FILE *f;

    if (uid == 0 || data_length > PS_MAX_SIZE || (data_length && !p_data)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    sched_lock();
    if (load(ext, uid, &flags, old, &len) == PSA_SUCCESS && (flags & PSA_STORAGE_FLAG_WRITE_ONCE)) {
        status = PSA_ERROR_NOT_PERMITTED;
        goto out;
    }
    if (fault_before(ext)) {
        goto out;
    }

    // Written to a temp file and renamed, so a crash never leaves half a blob.
    uid_path(ext, uid, path, sizeof(path));
    snprintf(tmp, sizeof(tmp), "%s.new", path);
    f = fopen(tmp, "wb");
    if (!f) {
        goto out;
    }
    flags = create_flags;
    if (fwrite(&flags, sizeof(flags), 1, f) == 1 &&
        fwrite(p_data, 1, data_length, f) == data_length && fclose(f) == 0) {
        status = rename(tmp, path) == 0 ? PSA_SUCCESS : PSA_ERROR_STORAGE_FAILURE;
        fault_after(ext);
    } else {
        remove(tmp);
    }
out:
    sched_unlock();
    return status;
}

static psa_status_t obj_get(const char *ext, psa_storage_uid_t uid, size_t data_offset,
                            size_t data_size, void *p_data, size_t *p_data_length)
{
    static uint8_t buf[PS_MAX_SIZE];
    uint32_t flags;
    size_t len;
    psa_status_t status;

    if (uid == 0 || !p_data_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    sched_lock();
    status = load(ext, uid, &flags, buf, &len);
    if (status == PSA_SUCCESS && data_offset > len) {
        status = PSA_ERROR_INVALID_ARGUMENT;
    }
    if (status == PSA_SUCCESS) {
        // TF-M clamps the read to the object size.
        size_t n = len - data_offset < data_size ? len - data_offset : data_size;

        memcpy(p_data, buf + data_offset, n);
        *p_data_length = n;
    }
    memset(buf, 0, sizeof(buf));
    sched_unlock();
    return status;
}

static psa_status_t obj_get_info(const char *ext, psa_storage_uid_t uid,
                                 struct psa_storage_info_t *p_info)
{
    static uint8_t buf[PS_MAX_SIZE];
    uint32_t flags;
    size_t len;
    psa_status_t status;

    if (uid == 0 || !p_info) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    sched_lock();
    status = load(ext, uid, &flags, buf, &len);
    if (status == PSA_SUCCESS) {
        p_info->capacity = len;
        p_info->size = len;
        p_info->flags = flags;
    }
    memset(buf, 0, sizeof(buf));
    sched_unlock();
    return status;
}

static psa_status_t obj_remove(const char *ext, psa_storage_uid_t uid)
{
    static uint8_t buf[PS_MAX_SIZE];
    char path[PATH_MAX];
    uint32_t flags;
    size_t len;
    psa_status_t status;

    if (uid == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    sched_lock();
    status = load(ext, uid, &flags, buf, &len);
    if (status == PSA_SUCCESS && (flags & PSA_STORAGE_FLAG_WRITE_ONCE)) {
        status = PSA_ERROR_NOT_PERMITTED;
    }
    if (status == PSA_SUCCESS && fault_before(ext)) {
        status = PSA_ERROR_STORAGE_FAILURE;
    } else if (status == PSA_SUCCESS) {
        uid_path(ext, uid, path, sizeof(path));
        status = remove(path) == 0 ? PSA_SUCCESS : PSA_ERROR_STORAGE_FAILURE;
        fault_after(ext);
    }
    memset(buf, 0, sizeof(buf));
    sched_unlock();
    return status;
}

psa_status_t psa_ps_set(psa_storage_uid_t uid, size_t data_length, const void *p_data,
                        psa_storage_create_flags_t create_flags)
{
    return obj_set(PS, uid, data_length, p_data, create_flags);
}

psa_status_t psa_ps_get(psa_storage_uid_t uid, size_t data_offset, size_t data_size, void *p_data,
                        size_t *p_data_length)
{
    return obj_get(PS, uid, data_offset, data_size, p_data, p_data_length);
}

psa_status_t psa_ps_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info)
{
    return obj_get_info(PS, uid, p_info);
}

psa_status_t psa_ps_remove(psa_storage_uid_t uid)
{
    return obj_remove(PS, uid);
}

psa_status_t psa_its_set(psa_storage_uid_t uid, size_t data_length, const void *p_data,
                         psa_storage_create_flags_t create_flags)
{
    return obj_set(ITS, uid, data_length, p_data, create_flags);
}

psa_status_t psa_its_get(psa_storage_uid_t uid, size_t data_offset, size_t data_length,
                         void *p_data, size_t *p_data_length)
{
    return obj_get(ITS, uid, data_offset, data_length, p_data, p_data_length);
}

psa_status_t psa_its_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info)
{
    return obj_get_info(ITS, uid, p_info);
}

psa_status_t psa_its_remove(psa_storage_uid_t uid)
{
    return obj_remove(ITS, uid);
}
