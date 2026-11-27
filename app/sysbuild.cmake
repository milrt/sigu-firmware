# Copyright (C) 2025 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

# Sysbuild includes this file for the app image, before any image is configured.

# The install record check (mcuboot_hooks/hooks.c), in both MCUboot images, in every build.
foreach(image mcuboot mcuboot_s1_variant)
  set(${image}_EXTRA_ZEPHYR_MODULES ${APP_DIR}/mcuboot_hooks CACHE INTERNAL "")
endforeach()

if(NOT SB_CONFIG_SIGU_RELEASE)
  return()
endif()

set_config_bool(${DEFAULT_IMAGE} CONFIG_SIGU_RELEASE y)

get_filename_component(sigu_repo_dir ${APP_DIR}/.. ABSOLUTE)
file(GLOB sigu_published_keys ${ZEPHYR_MCUBOOT_MODULE_DIR}/root-*.pem)
if(NOT sigu_published_keys)
  message(FATAL_ERROR "No MCUboot sample keys in '${ZEPHYR_MCUBOOT_MODULE_DIR}', cannot check.")
endif()

# Sets <out> to the SHA256 of the key file in SB_CONFIG_<name>. A release key must be outside
# the repo. It must not be an MCUboot sample key, because their private keys are published.
function(sigu_check_release_key name out)
  string(CONFIGURE "${SB_CONFIG_${name}}" key)
  if(key STREQUAL "")
    message(FATAL_ERROR "Release: SB_CONFIG_${name} is not set. Pass -DSB_CONFIG_${name}=<pem> "
                        "with a release key that is kept offline.")
  endif()
  if(NOT IS_ABSOLUTE "${key}" OR NOT EXISTS "${key}")
    message(FATAL_ERROR "Release: SB_CONFIG_${name} must be an absolute path to a file: '${key}'")
  endif()
  get_filename_component(key ${key} REALPATH)
  cmake_path(IS_PREFIX sigu_repo_dir "${key}" NORMALIZE in_repo)
  if(in_repo)
    message(FATAL_ERROR "Release: SB_CONFIG_${name} is inside the repo: '${key}'")
  endif()
  file(SHA256 ${key} hash)
  foreach(published ${sigu_published_keys})
    file(SHA256 ${published} published_hash)
    if(hash STREQUAL published_hash)
      message(FATAL_ERROR "Release: SB_CONFIG_${name} is the MCUboot sample key '${published}'. "
                          "Its private key is public.")
    endif()
  endforeach()
  set(${out} ${hash} PARENT_SCOPE)
endfunction()

sigu_check_release_key(BOOT_SIGNATURE_KEY_FILE mcuboot_key_hash)

if(SB_CONFIG_SECURE_BOOT_SIGNING_CUSTOM)
  # The signing command holds the b0 key, so there is no private key file to check.
  if(SB_CONFIG_SECURE_BOOT_SIGNING_PUBLIC_KEY STREQUAL "")
    message(FATAL_ERROR "Release: SB_CONFIG_SECURE_BOOT_SIGNING_PUBLIC_KEY is not set.")
  endif()
else()
  sigu_check_release_key(SECURE_BOOT_SIGNING_KEY_FILE b0_key_hash)
  # One leaked key must not open both stages.
  if(b0_key_hash STREQUAL mcuboot_key_hash)
    message(FATAL_ERROR "Release: b0 and MCUboot use the same signing key.")
  endif()
endif()
