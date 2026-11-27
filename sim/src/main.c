// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// sigu-sim: the secure partition, the panel and the keys on the host.

#include "sched.h"
#include "sim.h"
#include <SDL.h>
#include <limits.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void usage(void)
{
    fprintf(stderr, "usage: sigu-sim [--headless] [--ephemeral] [--ps DIR] [--card DIR|--no-card]\n"
                    "                [--scale N] [--boot-failed] [--reboot]\n"
                    "  --headless   no window; drive it with commands on stdin\n"
                    "  --ephemeral  keep the wallet in a temp dir that is removed at exit\n"
                    "  --ps DIR     Protected Storage folder (default ~/.sigu-sim/ps)\n"
                    "  --card DIR   the SD card folder (default ~/.sigu-sim/card)\n"
                    "  --no-card    start with the card out of the slot\n"
                    "  --scale N    window zoom, 1 to 4 (default 1, the panel at its own pixels)\n"
                    "  --boot-failed  start as after a failed install that MCUboot swapped back\n"
                    "  --reboot     keep the flash in the PS folder, and boot MCUboot first\n"
                    "keys: A, S and D press the left, middle and right key. Or click them.\n"
                    "      C takes the SD card out, or puts it back in.\n");
    exit(2);
}

static void control_task(void *arg)
{
    bool headless = *(bool *)arg;
    // An "ipc" line carries a previous tx as hex, up to BITCOIN_PREV_TX_MAX_SIZE bytes and more.
    static char line[1 << 20];

    while (fgets(line, sizeof(line), stdin)) {
        if (!sim_control_line(line)) {
            exit(0);
        }
    }
    // With a window, a closed stdin is normal. Headless, it is the end of the script.
    if (headless) {
        exit(0);
    }
}

int main(int argc, char **argv)
{
    static bool headless;
    bool ephemeral = false;
    const char *ps_dir = NULL;
    const char *card_dir = NULL;
    bool no_card = false;
    char def_dir[PATH_MAX];
    char def_card[PATH_MAX];
    int scale = 1;
    bool reboot = false;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--headless")) {
            headless = true;
        } else if (!strcmp(argv[i], "--ephemeral")) {
            ephemeral = true;
        } else if (!strcmp(argv[i], "--ps") && i + 1 < argc) {
            ps_dir = argv[++i];
        } else if (!strcmp(argv[i], "--card") && i + 1 < argc) {
            card_dir = argv[++i];
        } else if (!strcmp(argv[i], "--no-card")) {
            no_card = true;
        } else if (!strcmp(argv[i], "--reboot")) {
            reboot = true;
        } else if (!strcmp(argv[i], "--boot-failed")) {
            sim_boot_failed();
        } else if (!strcmp(argv[i], "--scale") && i + 1 < argc) {
            scale = atoi(argv[++i]);
            if (scale < 1 || scale > 4) {
                usage();
            }
        } else {
            usage();
        }
    }

    const char *home = getenv("HOME");

    snprintf(def_dir, sizeof(def_dir), "%s/.sigu-sim", home ? home : ".");
    mkdir(def_dir, 0700);
    if (!ephemeral && !ps_dir) {
        snprintf(def_dir, sizeof(def_dir), "%s/.sigu-sim/ps", home ? home : ".");
        ps_dir = def_dir;
    }
    if (!card_dir) {
        snprintf(def_card, sizeof(def_card), "%s/.sigu-sim/card", home ? home : ".");
        mkdir(def_card, 0700);
        card_dir = def_card;
    }
    if (!sim_card_init(card_dir, !no_card)) {
        fprintf(stderr, "[SIM] no such card folder: %s\n", card_dir);
        return 1;
    }
    if (!sim_ps_init(ephemeral ? NULL : ps_dir)) {
        fprintf(stderr, "[SIM] cannot open the PS folder\n");
        return 1;
    }
    fprintf(stderr, "[SIM] SIMULATOR. The wallet is stored on this computer. "
                    "Do not use it for real funds.\n");
    fprintf(stderr, "[SIM] PS: %s\n", ephemeral ? "temp dir, removed at exit" : ps_dir);
    fprintf(stderr, "[SIM] card: %s (%s)\n", sim_card_dir(), no_card ? "out" : "in");

    // TF-M starts its crypto service before any partition.
    if (psa_crypto_init() != PSA_SUCCESS) {
        fprintf(stderr, "[SIM] psa_crypto_init failed\n");
        return 1;
    }

    // MCUboot runs before TF-M and NS.
    if (reboot && !ephemeral) {
        sim_flash_keep(ps_dir);
        sim_mcuboot(0);
    }
    sim_start();
    sched_start("control", control_task, &headless);

    if (headless) {
        for (;;) {
            pause();
        }
    }
    if (!sim_window_open(scale)) {
        return 1;
    }
    while (sim_window_frame()) {
        SDL_Delay(10);
    }
    return 0;
}
