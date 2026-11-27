# Copyright (C) 2025 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

# The install record check, see hooks.c. sysbuild/mcuboot.conf turns the hooks on.
if(CONFIG_MCUBOOT)
  if(NOT CONFIG_BOOT_GO_HOOKS OR NOT CONFIG_BOOT_IMAGE_ACCESS_HOOKS)
    message(FATAL_ERROR "sigu: MCUboot needs CONFIG_BOOT_GO_HOOKS and CONFIG_BOOT_IMAGE_ACCESS_HOOKS")
  endif()
  # Without SHA-256, every install would be dropped as not authorized.
  if(NOT CONFIG_PSA_WANT_ALG_SHA_256)
    message(FATAL_ERROR "sigu: MCUboot needs CONFIG_PSA_WANT_ALG_SHA_256 (see Kconfig here)")
  endif()
  set(sigu_shared ${CMAKE_CURRENT_LIST_DIR}/../shared)
  zephyr_library()
  zephyr_library_sources(
    hooks.c
    ${sigu_shared}/src/fw_image.c
    ${sigu_shared}/src/install_auth.c
  )
  zephyr_library_include_directories(${sigu_shared}/include)
  zephyr_library_link_libraries(MCUBOOT_BOOTUTIL)
endif()
