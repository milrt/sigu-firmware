// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// One command per line, for scripts and tests. Every command answers "ok" or "err <why>".
//   key a|s|d [count]         press the left, middle or right key, then wait until the SP
//                             has handled it
//   wait <ms>
//   ticks <n>                 run n display ticks at once (the idle lock is 15000)
//   tick hold|go              hold back the display tick, after the one in flight, or let it
//                             run again. Not with ticks or key, which wait for ticks
//   shot <file.png>           save the panel
//   text                      the text on the panel now, each drawn line joined with " | "
//   card in|out               put the SD card in the slot, or take it out
//   boot s0|s1 <version>      which slot runs the bootloader, and its b0 version
//   boot unconfirmed          the app runs as a test until NS confirms it (send it early)
//   boot failed               the last install failed and was swapped back (send it first)
//   boot confirm              NS confirms the test app now, as nonsecure/health does
//   slot1 <file>              save slot1, where an install goes
//   mcuboot [cut <n>]         boot the real MCUboot with our hooks, as on the next reset.
//                             With cut, the power fails at its n-th flash write
//   snapshot | restore        save all flash, put it back
//   slot0 <file>              save slot0
//   forge test|perm           as a broken NS, ask MCUboot to install slot1, with no panel confirm
//   forge byte <offset>       as a broken NS, flip one byte of slot1
//   forge resume              as a broken NS, write slot0's trailer as in the middle of a swap
//   forge clear               as NS that never requests, remove the request from slot1
//   forge tear                a power loss in the middle of the last install record write
//   forge slot1 <file>        as a malicious NS, write a host file to the start of slot1
//   forge authcut <words>     a power loss in the SP's next record write, after that many words
//   wallet setup <pin> <words..>  recover, verify and confirm in one go, on the SP thread
//   wallet open <pin> [passphrase]
//   wallet temp <words..>     a temporary wallet, no PS and no PIN
//                             no opcode does these, the panel does. This saves the typing.
//   ns status                 the NS client calls:
//   ns test_secure            the SP self-tests (test SID), output on stderr
//   ns test_nonsecure         the NS self-tests, failures on stderr.
//                             Answers "ok passed=<n> failed=0" or "err passed=<n> failed=<n>"
//   ns freeze|thaw            park the honest NS threads (card job, health) at their next sleep,
//                             so a script can act as NS in their place
//   ipc p|t <type> [vec..]    one raw psa_call as a malicious NS,
//                             to TFM_BITCOIN (p) or TFM_BITCOIN_TEST (t).
//                             A vec is i<hex> (invec), i- (empty invec),
//                             z<n> (invec of n zero bytes) or o<n> (outvec of n bytes),
//                             at most 4 in all.
//                             Answers "ok <status> <hex of each outvec, - if empty>"
//   ipc cost <ms>             each psa_call keeps the SP thread that long,
//                             as a slow call on the device does. 0 turns it off
//   tickcount                 how many display ticks the SP has finished
//   light                     the backlight percent now
//   ps cut|cutafter|fail <n>  at the n-th PS write from now: a power loss before it,
//                             a power loss after it (the sim exits with 75), or a storage failure
//   ps off
//   quit

#include "bitcoin/bitcoin_client.h"
#include "bitcoin/bitcoin_core.h"
#include "bitcoin/nonsecure_bitcoin_test.h"
#include "drivers/input.h"
#include "sched.h"
#include "shared/test_util.h"
#include "sim.h"
#include <zephyr/dfu/mcuboot.h>
#include <psa/client.h>
#include <psa_manifest/sid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// A press is read on one tick and drawn on that tick. Two ticks make sure both happened.
#define KEY_TICKS 2

static uint32_t key_bit(const char *name)
{
    if (!strcmp(name, "d")) {
        return INPUT_OK;
    }
    if (!strcmp(name, "s")) {
        return INPUT_NEXT;
    }
    if (!strcmp(name, "a")) {
        return INPUT_DEL;
    }
    return 0;
}

static bool reply(bool ok, const char *why)
{
    if (ok) {
        printf("ok\n");
    } else {
        printf("err %s\n", why);
    }
    fflush(stdout);
    return true;
}

static bool reply_status(psa_status_t status, const char *text)
{
    if (status != PSA_SUCCESS) {
        printf("err psa %d\n", (int)status);
    } else {
        printf("ok%s%s\n", text ? " " : "", text ? text : "");
    }
    fflush(stdout);
    return true;
}

// As `bitcoin test_nonsecure` in the shell.
static bool ns_test_nonsecure(void)
{
    char text[48];

    test_assert_init();
    nonsecure_bitcoin_test_run_all();
    test_assert_results_t *results = test_assert_get_results();
    snprintf(text, sizeof(text), "passed=%u failed=%u", (unsigned)results->passed,
             (unsigned)results->failure_count);
    return results->failure_count ? reply(false, text) : reply_status(PSA_SUCCESS, text);
}

// `rest` is what follows "ns ". The words of a mnemonic stay one string.
static bool ns_command(char *rest)
{
    char *sub = strtok(rest, " \t\r\n");

    if (!sub) {
        return reply(false, "usage: ns status|test_secure|test_nonsecure|freeze|thaw");
    }
    if (!strcmp(sub, "status")) {
        uint32_t state = 0;
        uint32_t attempts = 0;
        char text[48];
        psa_status_t st = bitcoin_client_status(&state, &attempts);

        snprintf(text, sizeof(text), "state=%u attempts=%u", state, attempts);
        return reply_status(st, text);
    }
    if (!strcmp(sub, "test_secure")) {
        return reply_status(bitcoin_client_test_run_all(), NULL);
    }
    if (!strcmp(sub, "test_nonsecure")) {
        return ns_test_nonsecure();
    }
    if (!strcmp(sub, "freeze") || !strcmp(sub, "thaw")) {
        sim_ns_freeze(!strcmp(sub, "freeze"));
        return reply(true, NULL);
    }
    return reply(false, "usage: ns status|test_secure|test_nonsecure|freeze|thaw");
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

// The bytes of a hex string, in a new buffer of at least one byte. NULL on a bad string.
static uint8_t *hex_bytes(const char *hex, size_t *len)
{
    size_t n = strlen(hex);
    uint8_t *buf = malloc(n / 2 + 1);

    if (!buf || n % 2 != 0) {
        free(buf);
        return NULL;
    }
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            free(buf);
            return NULL;
        }
        buf[i] = (uint8_t)(hi << 4 | lo);
    }
    *len = n / 2;
    return buf;
}

#define IPC_VEC_MAX (1u << 24)

// `rest` is what follows "ipc ". One psa_call with the vectors as given, no client checks.
static bool ipc_command(char *rest)
{
    psa_invec in[PSA_MAX_IOVEC];
    psa_outvec out[PSA_MAX_IOVEC];
    size_t n_in = 0;
    size_t n_out = 0;
    char *svc = strtok(rest, " \t\r\n");
    char *type = strtok(NULL, " \t\r\n");
    char *vec;
    bool ok = svc && type && (!strcmp(svc, "p") || !strcmp(svc, "t"));
    psa_handle_t handle;
    psa_status_t status;

    while (ok && (vec = strtok(NULL, " \t\r\n")) != NULL) {
        size_t len = 0;
        uint8_t *buf = NULL;

        if (n_in + n_out == PSA_MAX_IOVEC) {
            ok = false;
        } else if (vec[0] == 'i' && n_out == 0) {
            buf = hex_bytes(!strcmp(vec, "i-") ? "" : vec + 1, &len);
        } else if (vec[0] == 'z' || vec[0] == 'o') {
            len = strtoul(vec + 1, NULL, 10);
            buf = len <= IPC_VEC_MAX ? calloc(len + 1, 1) : NULL;
        }
        ok = ok && buf && (vec[0] == 'o' || n_out == 0);
        if (!ok) {
            free(buf);
        } else if (vec[0] == 'o') {
            out[n_out++] = (psa_outvec){.base = buf, .len = len};
        } else {
            in[n_in++] = (psa_invec){.base = buf, .len = len};
        }
    }
    if (ok) {
        bool test = !strcmp(svc, "t");

        handle = psa_connect(test ? TFM_BITCOIN_TEST_SID : TFM_BITCOIN_SID,
                             test ? TFM_BITCOIN_TEST_VERSION : TFM_BITCOIN_VERSION);
        ok = PSA_HANDLE_IS_VALID(handle);
    }
    if (ok) {
        status = psa_call(handle, (int32_t)strtol(type, NULL, 10), in, n_in, out, n_out);
        psa_close(handle);
        printf("ok %d", (int)status);
        for (size_t i = 0; i < n_out; i++) {
            printf(out[i].len ? " " : " -");
            for (size_t j = 0; j < out[i].len; j++) {
                printf("%02x", ((const uint8_t *)out[i].base)[j]);
            }
        }
        printf("\n");
        fflush(stdout);
    }
    for (size_t i = 0; i < n_in; i++) {
        free((void *)(uintptr_t)in[i].base);
    }
    for (size_t i = 0; i < n_out; i++) {
        free(out[i].base);
    }
    return ok ? true : reply(false, "usage: ipc p|t <type> [i<hex>|i-|z<n>]... [o<n>]...");
}

static void text_on_sp(void *arg)
{
    sim_panel_text(arg, 1024);
}

struct wallet_job {
    const char *pin;
    const char *text; // the words for setup, the passphrase for open
    psa_status_t status;
};

static void setup_on_sp(void *arg)
{
    struct wallet_job *j = arg;
    wallet_session_t *w = bitcoin_core_session_production();

    j->status = bitcoin_core_recover(w, j->text);
    if (j->status == PSA_SUCCESS) {
        j->status = bitcoin_core_confirm(w, j->pin);
    }
}

static void open_on_sp(void *arg)
{
    struct wallet_job *j = arg;

    j->status = bitcoin_core_open(bitcoin_core_session_production(), j->pin, j->text);
}

static void temp_on_sp(void *arg)
{
    struct wallet_job *j = arg;

    j->status = bitcoin_core_open_temporary(bitcoin_core_session_production(), j->text, "");
}

// `rest` is what follows "wallet ".
static bool wallet_command(char *rest)
{
    char *sub = strtok(rest, " \t\r\n");

    if (sub && !strcmp(sub, "temp")) {
        char *words = strtok(NULL, "\r\n");
        struct wallet_job t = {.text = words};

        if (!words) {
            return reply(false, "usage: wallet temp <words>");
        }
        sim_ipc_run_on_sp(temp_on_sp, &t);
        return reply_status(t.status, NULL);
    }

    char *pin = strtok(NULL, " \t\r\n");
    char *tail = strtok(NULL, "\r\n");
    struct wallet_job j = {.pin = pin, .text = tail ? tail : ""};

    if (sub && pin && tail && !strcmp(sub, "setup")) {
        sim_ipc_run_on_sp(setup_on_sp, &j);
        return reply_status(j.status, NULL);
    }
    if (sub && pin && !strcmp(sub, "open")) {
        sim_ipc_run_on_sp(open_on_sp, &j);
        return reply_status(j.status, NULL);
    }
    return reply(false, "usage: wallet setup <pin> <words>|open <pin> [pass]|temp <words>");
}

bool sim_control_line(const char *line)
{
    char cmd[16] = "";
    char arg[256] = "";
    int count = 1;
    int n = sscanf(line, "%15s %255s %d", cmd, arg, &count);

    if (n < 1 || cmd[0] == '#') {
        return true;
    }
    if (!strcmp(cmd, "ns")) {
        char buf[512];

        snprintf(buf, sizeof(buf), "%s", line + strspn(line, " \t") + 2);
        return ns_command(buf);
    }
    if (!strcmp(cmd, "ipc") && !strcmp(arg, "cost") && n >= 3 && count >= 0) {
        sim_ipc_cost((uint32_t)count);
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "light")) {
        printf("ok %u\n", (unsigned int)sim_panel_light());
        fflush(stdout);
        return true;
    }
    if (!strcmp(cmd, "tickcount")) {
        printf("ok %u\n", (unsigned int)sim_ipc_ticks());
        fflush(stdout);
        return true;
    }
    if (!strcmp(cmd, "ipc")) {
        char *buf = strdup(line + strspn(line, " \t") + 3);
        bool more = buf && ipc_command(buf);

        free(buf);
        return more;
    }
    if (!strcmp(cmd, "wallet")) {
        char buf[512];

        snprintf(buf, sizeof(buf), "%s", line + strspn(line, " \t") + 6);
        return wallet_command(buf);
    }
    if (!strcmp(cmd, "quit")) {
        return false;
    }
    if (!strcmp(cmd, "key")) {
        uint32_t bit = key_bit(arg);

        if (!bit || count < 1) {
            return reply(false, "usage: key a|s|d [count]");
        }
        while (count--) {
            sim_input_press(bit);
            sim_ipc_wait_ticks(KEY_TICKS);
        }
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "wait")) {
        sched_sleep_ms((uint32_t)strtol(arg, NULL, 10));
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "tick")) {
        if (strcmp(arg, "hold") && strcmp(arg, "go")) {
            return reply(false, "usage: tick hold|go");
        }
        sim_ipc_hold_irqs(!strcmp(arg, "hold"));
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "ticks")) {
        sim_tick_burst((uint32_t)strtol(arg, NULL, 10));
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "card")) {
        if (strcmp(arg, "in") && strcmp(arg, "out")) {
            return reply(false, "usage: card in|out");
        }
        sim_card_set(!strcmp(arg, "in"));
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "boot") && !strcmp(arg, "unconfirmed")) {
        sim_boot_unconfirmed();
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "boot") && !strcmp(arg, "confirm")) {
        boot_write_img_confirmed_multi(0);
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "boot") && !strcmp(arg, "failed")) {
        sim_boot_failed();
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "boot")) {
        if ((strcmp(arg, "s0") && strcmp(arg, "s1")) || n < 3 || count < 0) {
            return reply(false, "usage: boot s0|s1 <version> | boot unconfirmed | boot failed");
        }
        sim_boot_set(!strcmp(arg, "s0"), (uint32_t)count);
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "mcuboot")) {
        if (n >= 2 && (strcmp(arg, "cut") || n < 3 || count < 1)) {
            return reply(false, "usage: mcuboot [cut <n>]");
        }
        sim_mcuboot(n >= 3 ? (uint32_t)count : 0);
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "snapshot")) {
        sim_flash_snapshot();
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "restore")) {
        return reply(sim_flash_restore(), "no snapshot");
    }
    if (!strcmp(cmd, "slot0")) {
        return reply(arg[0] && sim_slot0_dump(arg), "cannot write the file");
    }
    if (!strcmp(cmd, "forge") && (!strcmp(arg, "test") || !strcmp(arg, "perm"))) {
        sim_forge_request(!strcmp(arg, "perm"));
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "forge") && !strcmp(arg, "resume")) {
        sim_forge_resume();
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "forge") && !strcmp(arg, "tear")) {
        sim_forge_tear();
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "forge") && (!strcmp(arg, "slot1") || !strcmp(arg, "authcut"))) {
        char what[16] = "";
        char value[256] = "";

        if (sscanf(line, "%*s %15s %255s", what, value) != 2) {
            return reply(false, "usage: forge slot1 <file> | authcut <words>");
        }
        if (!strcmp(what, "slot1")) {
            return reply(sim_forge_slot1(value), "cannot read the file");
        }
        sim_forge_auth_cut((int)strtol(value, NULL, 10));
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "forge") && !strcmp(arg, "clear")) {
        sim_forge_clear();
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "forge") && !strcmp(arg, "byte") && n >= 3 && count >= 0) {
        sim_forge_byte((uint32_t)count);
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "slot1")) {
        return reply(arg[0] && sim_slot1_dump(arg), "cannot write the file");
    }
    if (!strcmp(cmd, "ps")) {
        if (n < 2 || (strcmp(arg, "off") && (n < 3 || count < 1))) {
            return reply(false, "usage: ps cut|cutafter|fail <n> | ps off");
        }
        sim_ps_fault(arg, (uint32_t)count);
        return reply(true, NULL);
    }
    if (!strcmp(cmd, "text")) {
        char text[1024];

        sim_ipc_run_on_sp(text_on_sp, text);
        printf("ok %s\n", text);
        fflush(stdout);
        return true;
    }
    if (!strcmp(cmd, "shot")) {
        return reply(arg[0] && sim_panel_png(arg), "cannot write the file");
    }
    return reply(false, "unknown command");
}
