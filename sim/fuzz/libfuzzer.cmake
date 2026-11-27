# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

# libFuzzer when the compiler has it (clang on Linux, Homebrew llvm). Apple clang does not, and
# then the targets link fuzz/replay.c, which only replays files.
include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_FLAGS -fsanitize=fuzzer)
set(CMAKE_REQUIRED_LINK_OPTIONS -fsanitize=fuzzer)
check_c_source_compiles(
  "#include <stddef.h>
   #include <stdint.h>
   int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { (void)d; (void)n; return 0; }"
  SIGU_HAVE_LIBFUZZER)
unset(CMAKE_REQUIRED_FLAGS)
unset(CMAKE_REQUIRED_LINK_OPTIONS)

# Coverage for everything, so the fuzzer sees the paths inside the libraries too.
if(SIGU_HAVE_LIBFUZZER)
  add_compile_options(-fsanitize=fuzzer-no-link)
endif()
