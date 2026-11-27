// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// MCUboot's log on stderr, as "I: ..." on the device console, after a "[MCUBOOT] " tag.
// Info lines only while MCUboot boots:
// NS calls bootutil_public.c too,
// and the device logs those at WRN (CONFIG_MCUBOOT_UTIL_LOG_LEVEL_WRN in prj.conf).

#pragma once

#include <stdbool.h>
#include <stdio.h>

extern bool sim_mcuboot_booting;

#define MCUBOOT_LOG_MODULE_DECLARE(module)
#define MCUBOOT_LOG_MODULE_REGISTER(module)

#define MCUBOOT_LOG_ERR(fmt, ...) fprintf(stderr, "[MCUBOOT] E: " fmt "\n", ##__VA_ARGS__)
#define MCUBOOT_LOG_WRN(fmt, ...) fprintf(stderr, "[MCUBOOT] W: " fmt "\n", ##__VA_ARGS__)
#define MCUBOOT_LOG_INF(fmt, ...)                                                                  \
    do {                                                                                           \
        if (sim_mcuboot_booting) {                                                                 \
            fprintf(stderr, "[MCUBOOT] I: " fmt "\n", ##__VA_ARGS__);                              \
        }                                                                                          \
    } while (0)
#define MCUBOOT_LOG_DBG(...) ((void)0)
#define MCUBOOT_LOG_SIM(...) ((void)0)
