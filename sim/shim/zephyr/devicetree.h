// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The few devicetree values NS reads, from app/boards/sigu_partitions.dtsi. Keep them in sync.
// DT_ALIAS only names a node for DEVICE_DT_GET in zephyr/device.h.

#pragma once

#define SIM_DT_CAT(a, b) a##b
#define SIM_DT_PASTE(a, b) SIM_DT_CAT(a, b)

#define DT_NODELABEL(label) SIM_DT_##label
#define DT_ALIAS(alias) SIM_DT_alias_##alias
#define DT_REG_ADDR(node) SIM_DT_PASTE(node, _ADDR)
#define DT_REG_SIZE(node) SIM_DT_PASTE(node, _SIZE)

#define SIM_DT_s0_partition_ADDR 0x8000
#define SIM_DT_s0_partition_SIZE (68 * 1024)
#define SIM_DT_s1_partition_ADDR 0x19000
#define SIM_DT_s1_partition_SIZE (68 * 1024)
