// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The dev build's self-test commands. Built only with CONFIG_SHELL and CONFIG_SIGU_SELFTEST.

#include "bitcoin/bitcoin_client.h"
#include "bitcoin/nonsecure_bitcoin_test.h"
#include "shared/test_util.h"
#include <stdbool.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/storage/flash_map.h>

static int cmd_test_secure(const struct shell *shell, size_t argc, char **argv)
{
    psa_status_t status = bitcoin_client_test_run_all();
    if (status != PSA_SUCCESS) {
        shell_error(shell, "FAILED");
        return -EIO;
    }

    shell_info(shell, "PASSED");

    return 0;
}

static int cmd_test_nonsecure(const struct shell *shell, size_t argc, char **argv)
{
    test_assert_init();

    nonsecure_bitcoin_test_run_all();

    test_assert_results_t *results = test_assert_get_results();
    if (results->failure_count > 0) {
        shell_error(shell, "FAILED");
        return -EIO;
    }

    shell_info(shell, "PASSED");

    return 0;
}

// TF-M makes slot0_ns read-only except its last sector, the MCUboot trailer.
// This writes 16 bytes back with the value they have:
// in the body the write must fault (the chip stops, a reset boots as before),
// and in the trailer it must work.
// Without the MPC setting the write lands and changes nothing, so the test cannot break the image.
static int cmd_test_slot0_ns_write(const struct shell *shell, size_t argc, char **argv)
{
    const struct flash_area *fa;
    uint8_t buf[16];
    bool body = !strcmp(argv[1], "body");
    off_t off;

    if (!body && strcmp(argv[1], "trailer")) {
        shell_error(shell, "Usage: test_slot0_ns_write body|trailer");
        return -EINVAL;
    }
    if (flash_area_open(PARTITION_ID(slot0_ns_partition), &fa) != 0) {
        shell_error(shell, "Cannot open slot0_ns");
        return -EIO;
    }
    off = body ? 0x1000 : (off_t)fa->fa_size - (off_t)sizeof(buf);
    if (flash_area_read(fa, off, buf, sizeof(buf)) != 0) {
        flash_area_close(fa);
        shell_error(shell, "Read failed");
        return -EIO;
    }
    shell_print(shell, "Writing 16 bytes at slot0_ns+0x%lx (%s). Expect %s.", (long)off, argv[1],
                body ? "a fault: the chip stops, reset it" : "ok");
    k_msleep(100); // let the console print it before a fault stops the chip
    int err = flash_area_write(fa, off, buf, sizeof(buf));

    flash_area_close(fa);
    if (err != 0) {
        shell_error(shell, "Write failed: %d", err);
        return -EIO;
    }
    shell_print(shell, body ? "Write went through: slot0_ns is writable from NS"
                            : "Write ok: the trailer sector stays writable");
    return body ? -EIO : 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
    bitcoin_subcmds, SHELL_CMD_ARG(test_secure, NULL, "Run secure tests", cmd_test_secure, 1, 0),
    SHELL_CMD_ARG(test_nonsecure, NULL, "Run non-secure tests", cmd_test_nonsecure, 1, 0),
    SHELL_CMD_ARG(test_slot0_ns_write, NULL, "Write to slot0_ns <body|trailer>, must fault",
                  cmd_test_slot0_ns_write, 2, 0),
    SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(bitcoin, &bitcoin_subcmds, "Bitcoin Hardware Wallet Commands", NULL);
