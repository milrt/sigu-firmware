// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

void ripemd160(const unsigned char *input, size_t ilen, unsigned char output[20]);
