// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/display_priv.h"
#include "core/text.h"
#include "components/header.h"
#include "components/label.h"
#include "components/softkeys.h"
#include "files/files.h"
#include "files/firmware.h"
#include "bitcoin/bitcoin_core.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Firmware installation from the card.
// "Now" is what runs: the app version and hash read here from slot0,
// and the boot version NS read from TF-M.
// Below it are the install files NS found.
// Install asks NS to write the selected one to slot1, then the screen hashes slot1 and shows it.
// Install there writes the install record with that hash, and NS asks MCUboot to install it.
// MCUboot installs only that hash, so NS cannot install anything the user did not see.
// MCUboot and b0 check the signature. Any app installs, older too, after a warning.
// A bootloader not above the running one is blocked: b0 would never start it.

#define COL_NAME 18
#define COL_VERSION 78
#define COL_EXTRA 136
#define NOW_Y 38
#define NOW_ROW_Y 60
#define ROW_STEP 24
#define RULE_Y 112
#define CARD_Y 120
#define CARD_STEP 26
#define FILL_X 6
#define FILL_UP 2
#define EMPTY_Y 146

// The job views.
#define TEXT_X 12
#define TEXT_W 216
#define TITLE_Y 56
#define TEXT_Y 100

// The confirm view. The full 16 hex characters go on their own line under each version.
#define ASK_Y 38
#define NEW_Y 62
#define FULL_X 26
#define FULL_DY 20
#define CONFIRM_NOW_Y 104
#define WARN_Y 150
// Hex characters of a hash in a list row. More do not fit.
#define ROW_HEX 8
#define EXTRA_DY 3
// Install is armed after 1 s, as on the review screen, so a held key does not install.
#define ARM_TICKS 50

#define VERSION_SIZE 16
#define HASH_SIZE (FW_IMAGE_HASH_TEXT_SIZE + 2)
#define FULL_SIZE (FW_IMAGE_HASH_TEXT_SIZE + 1)

static uint32_t shown_gen;
static files_job_state_t shown_state;
static uint32_t sel;

// What the user picked, kept for the confirm view: the list can change under it.
static uint32_t want_kind;
static uint8_t want_hash[BITCOIN_INSTALL_HASH_SIZE];
static uint32_t want_boot;
// slot1 as hashed once NS staged it. Install authorizes this hash, never a later read.
static firmware_image_t staged;
static bool staged_read;
static uint32_t staged_floor; // min_security when slot1 was read
static int confirm_ticks;
// How firmware_authorize() ended, BITCOIN_INSTALL_OK until it failed.
static uint32_t auth_code;

// An install changes the code that will hold the keys, so it needs the PIN, as a signature does.
// With a stored wallet, the install waits until that wallet is open.
// A temporary wallet does not count, anyone can open one.
// No wallet or an unreadable record does not block:
// a new device and an app that cannot read the record must still take an update.
static bool needs_unlock(void)
{
    wallet_session_t *w = bitcoin_core_session_production();
    uint32_t state = BITCOIN_STATUS_NONE;
    uint32_t attempts = 0;
    bool stored = false;

    if (bitcoin_core_stored(w, &stored) != PSA_SUCCESS || !stored) {
        return false;
    }
    return bitcoin_core_status(w, &state, &attempts) != PSA_SUCCESS ||
           state != BITCOIN_STATUS_OPEN || bitcoin_core_is_temporary(w);
}

static bool our_job(void)
{
    return files_job_state() != FILES_JOB_IDLE && files_job_is_install();
}

static const char *reason(uint32_t code)
{
    switch (code) {
    case BITCOIN_INSTALL_NO_CARD:
        return "no card";
    case BITCOIN_INSTALL_READ_FAILED:
        return "cannot read the file";
    case BITCOIN_INSTALL_BAD_FILE:
        return "not a valid install file";
    case BITCOIN_INSTALL_NOT_NEWER:
        return "not newer than this one";
    case BITCOIN_INSTALL_WRITE_FAILED:
        return "cannot write the flash";
    case BITCOIN_INSTALL_PENDING:
        return "the last install is not done, restart and try again";
    case BITCOIN_INSTALL_CHANGED:
        return "file changed, check the list again";
    case BITCOIN_INSTALL_STAGED:
        return "not the file you picked";
    default:
        return "failed";
    }
}

// "1.4.0".
static void app_text(char out[VERSION_SIZE], uint32_t major, uint32_t minor, uint32_t revision)
{
    size_t len = 0;

    out[0] = '\0';
    text_add_u32(out, VERSION_SIZE, &len, major);
    text_add(out, VERSION_SIZE, &len, ".");
    text_add_u32(out, VERSION_SIZE, &len, minor);
    text_add(out, VERSION_SIZE, &len, ".");
    text_add_u32(out, VERSION_SIZE, &len, revision);
}

// "v4".
static void boot_text(char out[VERSION_SIZE], uint32_t version)
{
    size_t len = 0;

    out[0] = '\0';
    text_add(out, VERSION_SIZE, &len, "v");
    text_add_u32(out, VERSION_SIZE, &len, version);
}

// "[8f3a0c9b]" from the first ROW_HEX hex characters.
static void hash_text(char out[HASH_SIZE], const char *hex)
{
    char cut[ROW_HEX + 1];
    size_t len = 0;

    memcpy(cut, hex, ROW_HEX);
    cut[ROW_HEX] = '\0';
    out[0] = '\0';
    text_add(out, HASH_SIZE, &len, "[");
    text_add(out, HASH_SIZE, &len, cut);
    text_add(out, HASH_SIZE, &len, "]");
}

// "8f3a0c9b 1d2e4f60", all the hex characters, in two groups to compare.
static void full_hash_text(char out[FULL_SIZE], const char *hex)
{
    memcpy(out, hex, ROW_HEX);
    out[ROW_HEX] = ' ';
    memcpy(out + ROW_HEX + 1, hex + ROW_HEX, FW_IMAGE_HASH_TEXT_SIZE - ROW_HEX);
}

static bool blocked(const files_install_t *in)
{
    return in->kind == BITCOIN_INSTALL_BOOT && in->boot_version <= files_boot_version();
}

static bool installable(const files_install_t *in)
{
    return in && in->state == BITCOIN_INSTALL_STATE_OK && !blocked(in);
}

static void draw_row(int y, const char *name, const char *version, const char *extra,
                     uint16_t color)
{
    panel_draw_text(COL_NAME, y, name, &font_20, color);
    panel_draw_text(COL_VERSION, y, version, &font_20, color);
    if (extra) {
        panel_draw_text(COL_EXTRA, y + EXTRA_DY, extra, &font_16, color);
    }
}

static void draw_now(void)
{
    const firmware_image_t *now = firmware_now();
    char app[VERSION_SIZE] = "?";
    char boot[VERSION_SIZE] = "?";
    char hash[HASH_SIZE] = "";

    if (now->ok) {
        app_text(app, now->major, now->minor, now->revision);
        hash_text(hash, now->hash);
    }
    if (files_boot_version() != 0) {
        boot_text(boot, files_boot_version());
    }
    panel_draw_text(COL_NAME, NOW_Y, "Now:", &font_16, COL_MUTE);
    draw_row(NOW_ROW_Y, "App", app, hash, COL_INK);
    draw_row(NOW_ROW_Y + ROW_STEP, "Boot", boot, NULL, COL_INK);
}

static void draw_install(int y, const files_install_t *in, bool on)
{
    const char *name = in->kind == BITCOIN_INSTALL_APP ? "App" : "Boot";
    char version[VERSION_SIZE];
    char hash[HASH_SIZE];
    const char *extra = NULL;

    if (on) {
        panel_fill_rect(FILL_X, y - FILL_UP, PANEL_W - 2 * FILL_X, CARD_STEP, COL_SELECT);
    }
    if (in->state == BITCOIN_INSTALL_STATE_INVALID) {
        draw_row(y, name, "(invalid)", NULL, COL_MUTE);
        return;
    }
    if (in->state == BITCOIN_INSTALL_STATE_INCOMPLETE) {
        draw_row(y, name, "(incomplete)", NULL, COL_MUTE);
        return;
    }
    if (in->kind == BITCOIN_INSTALL_APP) {
        char hex[FW_IMAGE_HASH_TEXT_SIZE];

        app_text(version, in->major, in->minor, in->revision);
        fw_image_hash_text(in->hash, hex);
        hash_text(hash, hex);
        extra = hash;
    } else {
        boot_text(version, in->boot_version);
        extra = blocked(in) ? "(blocked)" : NULL;
    }
    draw_row(y, name, version, extra, on && installable(in) ? COL_INK : COL_MUTE);
}

// NULL when there are install files to list.
static const char *empty_text(void)
{
    if (files_card() == BITCOIN_CARD_NONE) {
        return "insert SD card";
    }
    if (files_card() != BITCOIN_CARD_MOUNTED) {
        return "SD card error";
    }
    if (files_install_count() == 0) {
        return "No install files";
    }
    return NULL;
}

static bool is_stage_job(void)
{
    return files_job_kind() != BITCOIN_JOB_INSTALL_COMMIT;
}

// NS staged a file. Read slot1 once, so the view and the install press use the same hash.
static void read_staged(void)
{
    if (!staged_read) {
        firmware_staged(&staged);
        staged_floor = firmware_min_security();
        staged_read = true;
        confirm_ticks = 0;
    }
}

// slot1 is what the user picked: the kind, and for an app the bytes the list showed.
static bool staged_ok(void)
{
    if (!staged.ok) {
        return false;
    }
    if (want_kind == BITCOIN_JOB_INSTALL_BOOT) {
        return staged.is_boot && staged.has_boot_version && staged.boot_version == want_boot;
    }
    return !staged.is_boot && memcmp(staged.sha256, want_hash, sizeof(want_hash)) == 0;
}

// MCUboot would drop it anyway. Bootloaders have b0's counter instead.
static bool below_floor(void)
{
    return !staged.is_boot && staged.security < staged_floor;
}

static bool confirming(void)
{
    return is_stage_job() && files_job_state() == FILES_JOB_DONE &&
           files_job_code() == BITCOIN_INSTALL_STAGED && staged_ok() && !below_floor() &&
           auth_code == BITCOIN_INSTALL_OK;
}

static bool older(void)
{
    const firmware_image_t *now = firmware_now();
    uint32_t a = (uint32_t)staged.major << 24 | (uint32_t)staged.minor << 16 | staged.revision;
    uint32_t b = (uint32_t)now->major << 24 | (uint32_t)now->minor << 16 | now->revision;

    return now->ok && a < b;
}

// One image: the version and the short hash, then the full hash below.
static void draw_image(int y, const char *name, const char *version, const char *hex,
                       uint16_t color)
{
    char full[FULL_SIZE];

    draw_row(y, name, version, NULL, color);
    full_hash_text(full, hex);
    panel_draw_text(FULL_X, y + FULL_DY, full, &font_16, color);
}

// Every value here is read from slot0 or slot1, never one NS sent.
static void draw_confirm(void)
{
    char version[VERSION_SIZE];
    bool app = want_kind == BITCOIN_JOB_INSTALL_APP;

    label_draw(app ? "Install this app?" : "Install this boot?", &font_20, COL_INK, LABEL_TOP_MID,
               0, ASK_Y);
    if (app) {
        app_text(version, staged.major, staged.minor, staged.revision);
    } else {
        boot_text(version, staged.boot_version);
    }
    draw_image(NEW_Y, "New", version, staged.hash, COL_INK);
    if (app) {
        const firmware_image_t *now = firmware_now();
        char now_version[VERSION_SIZE] = "?";

        if (now->ok) {
            app_text(now_version, now->major, now->minor, now->revision);
            draw_image(CONFIRM_NOW_Y, "Now", now_version, now->hash, COL_MUTE);
        } else {
            draw_row(CONFIRM_NOW_Y, "Now", now_version, NULL, COL_MUTE);
        }
    }
    if (app && older()) {
        panel_draw_text_wrapped(TEXT_X, WARN_Y, TEXT_W,
                                "Older than Now. It may not read your wallet.", &font_16,
                                COL_ALERT);
    }
    softkeys_set("cancel", NULL, confirm_ticks >= ARM_TICKS ? "install" : NULL);
}

static void draw_job(void)
{
    files_job_state_t state = files_job_state();
    uint32_t code = files_job_code();
    const char *why;
    bool ok;

    if (state != FILES_JOB_DONE) {
        label_draw(is_stage_job() ? "copying..." : "installing...", &font_24, COL_INK,
                   LABEL_TOP_MID, 0, TITLE_Y);
        panel_draw_text_wrapped(TEXT_X, TEXT_Y, TEXT_W, "keep power on and the card in", &font_20,
                                COL_MUTE);
        softkeys_set(state == FILES_JOB_REQUESTED ? "cancel" : NULL, NULL, NULL);
        return;
    }
    if (is_stage_job() && code == BITCOIN_INSTALL_STAGED) {
        read_staged();
        if (confirming()) {
            draw_confirm();
            return;
        }
        code = auth_code != BITCOIN_INSTALL_OK ? auth_code : BITCOIN_INSTALL_STAGED;
    }
    ok = !is_stage_job() && code == BITCOIN_INSTALL_OK;
    why = reason(code);
    if (ok) {
        why = "restarting to install...";
    } else if (is_stage_job() && code == BITCOIN_INSTALL_STAGED && staged_ok() && below_floor()) {
        why = "older than the security level of this device";
    }
    label_draw(ok ? "ready" : "not installed", &font_24, ok ? COL_GOOD : COL_ALERT, LABEL_TOP_MID,
               0, TITLE_Y);
    panel_draw_text_wrapped(TEXT_X, TEXT_Y, TEXT_W, why, &font_20, COL_INK);
    softkeys_set("back", NULL, NULL);
}

static void draw(void)
{
    const char *empty = empty_text();
    uint32_t n = files_install_count();

    shown_gen = files_generation();
    shown_state = files_job_state();
    if (sel >= n) {
        sel = 0;
    }
    panel_clear(COL_BG);
    header_draw("Firmware", &font_16, COL_SURFACE, COL_MUTE);
    if (our_job()) {
        draw_job();
        return;
    }
    draw_now();
    panel_fill_rect(FILL_X, RULE_Y, PANEL_W - 2 * FILL_X, 1, COL_SURFACE);
    if (!empty && needs_unlock()) {
        empty = "unlock the wallet first";
    }
    if (empty) {
        label_draw(empty, &font_20, COL_MUTE, LABEL_TOP_MID, 0, EMPTY_Y);
        softkeys_set("back", NULL, NULL);
        return;
    }
    for (uint32_t i = 0; i < n; i++) {
        draw_install(CARD_Y + (int)i * CARD_STEP, files_install(i), i == sel);
    }
    softkeys_set("back", n > 1 ? "next" : NULL, installable(files_install(sel)) ? "install" : NULL);
}

static void firmware_enter(void *arg)
{
    (void)arg;
    sel = 0;
    staged_read = false;
    auth_code = BITCOIN_INSTALL_OK;
    draw();
}

// No way out while NS writes the flash, but a job NS has not taken can still be dropped.
// Cancel on the confirm view leaves slot1 staged, but with no record MCUboot never installs it.
static void firmware_del(void)
{
    if (our_job() && files_job_state() == FILES_JOB_BUSY) {
        return;
    }
    if (our_job()) {
        files_job_close();
        draw();
        return;
    }
    display_show(&menu_screen, NULL);
}

static void firmware_next(void)
{
    if (!our_job() && !empty_text() && files_install_count() > 1) {
        sel = (sel + 1) % files_install_count();
        draw();
    }
}

// The record holds the hash on screen. The commit job only tells NS to go on.
static void confirm_ok(void)
{
    if (confirm_ticks < ARM_TICKS || needs_unlock()) {
        return;
    }
    auth_code = firmware_authorize(staged.sha256);
    if (auth_code == BITCOIN_INSTALL_OK) {
        files_job_request_commit();
    }
    draw();
}

// A list that changed since the last draw is not what the user saw. The tick draws it first.
static void firmware_ok(void)
{
    const files_install_t *in = files_install(sel);

    if (our_job() && shown_state == files_job_state() && confirming()) {
        confirm_ok();
        return;
    }
    if (our_job() || files_generation() != shown_gen || empty_text() || !installable(in) ||
        needs_unlock()) {
        return;
    }
    want_kind =
        in->kind == BITCOIN_INSTALL_APP ? BITCOIN_JOB_INSTALL_APP : BITCOIN_JOB_INSTALL_BOOT;
    memcpy(want_hash, in->hash, sizeof(want_hash));
    want_boot = in->boot_version;
    staged_read = false;
    auth_code = BITCOIN_INSTALL_OK;
    if (files_job_request_install(want_kind)) {
        draw();
    }
}

static void firmware_tick(void)
{
    if (confirming() && confirm_ticks < ARM_TICKS && ++confirm_ticks == ARM_TICKS) {
        draw();
        return;
    }
    if (files_generation() != shown_gen || files_job_state() != shown_state) {
        draw();
    }
}

const display_screen_ops_t firmware_screen = {
    .enter = firmware_enter,
    .on_del = firmware_del,
    .on_next = firmware_next,
    .on_ok = firmware_ok,
    .tick = firmware_tick,
};
