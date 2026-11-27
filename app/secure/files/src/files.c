// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "files/files.h"
#include "shared/wire.h"
#include <stddef.h>
#include <string.h>

static char list[BITCOIN_FILES_MAX][BITCOIN_FILE_NAME_MAX_SIZE];
static uint32_t count;
static uint32_t generation;
static uint32_t card;
static uint32_t boot_version;
static uint32_t fw_status;
static files_install_t installs[BITCOIN_INSTALLS_MAX];
static uint32_t install_count;

static struct {
    files_job_state_t state;
    uint32_t kind;
    uint32_t code;
    bool signed_input;
    char name[BITCOIN_FILE_NAME_MAX_SIZE];
} job;

// The fonts have only printable ASCII.
static void printable(char *s)
{
    for (char *c = s; *c; c++) {
        if ((unsigned char)*c < 0x20 || (unsigned char)*c > 0x7e) {
            *c = '?';
        }
    }
}

static void copy_name(char *dst, const char *src)
{
    strncpy(dst, src, BITCOIN_FILE_NAME_MAX_SIZE - 1);
    dst[BITCOIN_FILE_NAME_MAX_SIZE - 1] = '\0';
}

void files_clear(void)
{
    count = 0;
    install_count = 0;
    generation++;
}

bool files_add(const char *name)
{
    if (count == BITCOIN_FILES_MAX) {
        return false;
    }
    copy_name(list[count], name);
    printable(list[count]);
    count++;
    return true;
}

uint32_t files_count(void)
{
    return count;
}

const char *files_name(uint32_t i)
{
    return i < count ? list[i] : NULL;
}

uint32_t files_generation(void)
{
    return generation;
}

void files_set_card(uint32_t c)
{
    card = c;
}

uint32_t files_card(void)
{
    return card;
}

static bool read_install(wire_r *r, files_install_t *in)
{
    in->kind = wire_get_u8(r);
    in->state = wire_get_u8(r);
    in->major = wire_get_u8(r);
    in->minor = wire_get_u8(r);
    in->revision = (uint16_t)wire_get_le(r, 2);
    in->boot_version = wire_get_le32(r);
    wire_get_field(r, in->hash, sizeof(in->hash), sizeof(in->hash));
    return r->ok && (in->kind == BITCOIN_INSTALL_BOOT || in->kind == BITCOIN_INSTALL_APP) &&
           in->state <= BITCOIN_INSTALL_STATE_INCOMPLETE;
}

bool files_set_installs(const uint8_t *records, size_t len)
{
    size_t n = len / BITCOIN_INSTALL_RECORD_SIZE;
    wire_r r = wire_reader(records, len);

    install_count = 0;
    if (len % BITCOIN_INSTALL_RECORD_SIZE != 0 || n > BITCOIN_INSTALLS_MAX) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (!read_install(&r, &installs[i]) || (i > 0 && installs[i].kind == installs[0].kind)) {
            return false;
        }
    }
    install_count = n;
    return true;
}

void files_set_fw(uint32_t boot, uint32_t status)
{
    boot_version = boot;
    fw_status = status;
}

uint32_t files_boot_version(void)
{
    return boot_version;
}

uint32_t files_fw_status(void)
{
    return fw_status;
}

uint32_t files_install_count(void)
{
    return install_count;
}

const files_install_t *files_install(uint32_t i)
{
    return i < install_count ? &installs[i] : NULL;
}

files_job_state_t files_job_state(void)
{
    return job.state;
}

const char *files_job_name(void)
{
    return job.name;
}

uint32_t files_job_kind(void)
{
    return job.kind;
}

static bool is_stage(uint32_t kind)
{
    return kind == BITCOIN_JOB_INSTALL_BOOT || kind == BITCOIN_JOB_INSTALL_APP;
}

bool files_job_is_install(void)
{
    return is_stage(job.kind) || job.kind == BITCOIN_JOB_INSTALL_COMMIT;
}

uint32_t files_job_code(void)
{
    return job.code;
}

static bool request(uint32_t kind, const char *name)
{
    if (job.state == FILES_JOB_REQUESTED || job.state == FILES_JOB_BUSY) {
        return false;
    }
    job.state = FILES_JOB_REQUESTED;
    job.kind = kind;
    job.code = BITCOIN_FILES_OK;
    job.signed_input = false;
    copy_name(job.name, name);
    return true;
}

bool files_job_request_sign(const char *name)
{
    return request(BITCOIN_JOB_SIGN, name);
}

bool files_job_request_install(uint32_t kind)
{
    if (!is_stage(kind)) {
        return false;
    }
    return request(kind, "");
}

bool files_job_request_commit(void)
{
    return request(BITCOIN_JOB_INSTALL_COMMIT, "");
}

bool files_job_request_export(void)
{
    return request(BITCOIN_JOB_EXPORT, "");
}

const char *files_job_take(uint32_t *kind)
{
    if (job.state != FILES_JOB_REQUESTED) {
        return NULL;
    }
    job.state = FILES_JOB_BUSY;
    *kind = job.kind;
    return job.name;
}

// An install job never ends with OK, and a commit job never with STAGED,
// so the screen never shows "restarting" for a slot1 the user did not see.
static bool code_allowed(uint32_t code)
{
    if (is_stage(job.kind)) {
        return code < BITCOIN_INSTALL_CODES && code != BITCOIN_INSTALL_OK;
    }
    if (job.kind == BITCOIN_JOB_INSTALL_COMMIT) {
        return code < BITCOIN_INSTALL_CODES && code != BITCOIN_INSTALL_STAGED;
    }
    return code < BITCOIN_FILES_REJECTED;
}

bool files_job_finish(uint32_t code)
{
    if (job.state != FILES_JOB_BUSY || !code_allowed(code)) {
        return false;
    }
    job.state = FILES_JOB_DONE;
    job.code = code;
    return true;
}

void files_job_note_signed(void)
{
    if (job.state == FILES_JOB_BUSY && job.kind == BITCOIN_JOB_SIGN) {
        job.signed_input = true;
    }
}

bool files_job_signed(void)
{
    return job.signed_input;
}

void files_job_reject(void)
{
    if (job.state == FILES_JOB_BUSY && job.kind == BITCOIN_JOB_SIGN) {
        job.state = FILES_JOB_DONE;
        job.code = BITCOIN_FILES_REJECTED;
    }
}

void files_job_close(void)
{
    job.state = FILES_JOB_IDLE;
}
