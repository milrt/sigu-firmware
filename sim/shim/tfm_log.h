// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The SP log goes to stderr, as the secure UART would show it.

#pragma once

#include <stdio.h>

#define INFO(...) fprintf(stderr, "[SP] " __VA_ARGS__)
#define ERROR(...) fprintf(stderr, "[SP] ERROR: " __VA_ARGS__)
#define WARN(...) fprintf(stderr, "[SP] WARN: " __VA_ARGS__)
#define VERBOSE(...) ((void)0)
