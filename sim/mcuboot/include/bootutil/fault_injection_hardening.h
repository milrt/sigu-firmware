// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// MCUboot's header, found first in the include path.
// Its FIH_LABEL is an assembly label for a fault test tool, and WebAssembly takes no such label.
// So the web build drops it. Native builds keep MCUboot's header as it is.

#pragma once

#include_next <bootutil/fault_injection_hardening.h>

#ifdef __EMSCRIPTEN__
#undef FIH_LABEL
#define FIH_LABEL(str) ((void)0)
#endif
