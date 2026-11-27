// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The host has no radio and no SPU.

#pragma once

#define NRF_RADIO_S_BASE 0
#define SPU_LOCK_CONF_LOCKED 1
#define spu_peripheral_config_secure(base, lock) ((void)(base), (void)(lock))
