// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The NS log goes to stderr, as the NS console would show it.

#pragma once

#include <stdio.h>

#define LOG_MODULE_REGISTER(name, ...)                                                             \
    static const char *const log_module __attribute__((unused)) = #name

#define SIM_LOG(level, fmt, ...)                                                                   \
    fprintf(stderr, "[NS] <" level "> %s: " fmt "\n", log_module, ##__VA_ARGS__)

#define LOG_ERR(...) SIM_LOG("err", __VA_ARGS__)
#define LOG_WRN(...) SIM_LOG("wrn", __VA_ARGS__)
#define LOG_INF(...) SIM_LOG("inf", __VA_ARGS__)
#define LOG_DBG(...) ((void)log_module)
