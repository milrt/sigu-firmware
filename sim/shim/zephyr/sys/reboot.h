// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The sim cannot restart. sys_reboot() logs "[SIM] reboot" and parks the calling thread.

#pragma once

#define SYS_REBOOT_WARM 0
#define SYS_REBOOT_COLD 1

__attribute__((noreturn)) void sys_reboot(int type);
