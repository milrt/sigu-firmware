# Copyright (C) 2025 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(tfm_app_rot_partition_bitcoin STATIC)

add_subdirectory(bitcoin)

target_include_directories(tfm_app_rot_partition_bitcoin
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  PUBLIC
    display/include
    files/include
    drivers/include
  PRIVATE
    ${CMAKE_BINARY_DIR}/bitcoin_partition
    ../shared/include
    bitcoin/src
    display/src
    ${QRCODEGEN_DIR}
    # nrfx HAL, for the panel, the keys and the tick timer. Same set Nordic's own
    # tfm_secure_peripheral sample adds to its App-RoT partition.
    ${HAL_NORDIC_PATH}/nrfx
    ${HAL_NORDIC_PATH}/nrfx/mdk
    ${HAL_NORDIC_PATH}/nrfx/drivers/include
)

target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/bitcoin_partition
)

target_sources(tfm_app_rot_partition_bitcoin PRIVATE
  bitcoin_service.c
  files/src/files.c
  files/src/firmware.c
  files/src/firmware_flash.c
  drivers/src/input.c
  drivers/src/panel.c
  drivers/src/panel_hw.c
  drivers/src/tamper.c
  drivers/src/tick.c
  display/src/core/display.c
  display/src/core/config.c
  display/src/core/theme.c
  display/src/core/text.c
  display/src/fonts/montserrat_16.c
  display/src/fonts/montserrat_20.c
  display/src/fonts/montserrat_24.c
  display/src/components/header.c
  display/src/components/label.c
  display/src/components/list.c
  display/src/components/qr.c
  display/src/components/softkeys.c
  display/src/components/wheel.c
  display/src/components/word_picker.c
  display/src/components/seed_entry.c
  display/src/components/passphrase_entry.c
  display/src/components/pin_entry.c
  display/src/screens/status.c
  display/src/screens/review.c
  display/src/screens/menu.c
  display/src/screens/temp_wallet.c
  display/src/screens/wallet_setup.c
  display/src/screens/unlock.c
  display/src/screens/settings.c
  display/src/screens/files.c
  display/src/screens/sign_job.c
  display/src/screens/firmware.c
  display/src/screens/export.c
  display/src/screens/receive.c
  display/src/screens/reset.c
  ${QRCODEGEN_DIR}/qrcodegen.c
)

# Must match the service list in the configured tfm_bitcoin_partition.yaml. If they disagree,
# psa_wait() returns a signal that has no handler.
if(SIGU_SELFTEST)
  target_compile_definitions(tfm_app_rot_partition_bitcoin PRIVATE SIGU_SELFTEST)
endif()

# Generated from the manifest.
target_sources(tfm_app_rot_partition_bitcoin PRIVATE
  ${CMAKE_BINARY_DIR}/bitcoin_partition/auto_generated/intermedia_tfm_bitcoin_partition.c
)
target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/bitcoin_partition/auto_generated/load_info_tfm_bitcoin_partition.c
)

target_link_libraries(tfm_app_rot_partition_bitcoin PRIVATE
  bitcoin
  # The seed entry screen offers words from the same list bip39.c uses.
  bip39_wordlist
  tfm_sprt
  psa_crypto_config
  # The nrfx/MDK device definitions (NRF54L15_XXAA, NRF_P0 ...) that the nrfx HAL needs.
  platform_s
  c
)

# fw_info_bare.h in files/src/firmware_flash.c needs both magics. NCS passes them to the TF-M
# build, and gives them only to platform_s.
target_compile_definitions(tfm_app_rot_partition_bitcoin PRIVATE
  FIRMWARE_INFO_MAGIC=${FIRMWARE_INFO_MAGIC}
  EXT_API_MAGIC=${EXT_API_MAGIC}
)

target_link_libraries(tfm_spm PRIVATE
  tfm_app_rot_partition_bitcoin
)

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_bitcoin
)

target_compile_definitions(tfm_config INTERFACE
  TFM_PARTITION_BITCOIN
  # The display tick is a secure IRQ that mostly lands while NS runs. With the default 0, PendSV
  # does not schedule then, so the partition would see the tick only on the next NS call.
  CONFIG_TFM_SCHEDULE_WHEN_NS_INTERRUPTED=1
  # TF-M allows the option above only if no NS interrupt can preempt a secure thread. Without
  # this mask, an NS interrupt can stop the partition in the middle of its work, and Zephyr can
  # switch to another NS thread. When that thread calls TF-M, the veneer finds the partition stack
  # instead of the sealed NS agent stack and calls psa_panic(). With it, NS interrupts wait while
  # the partition runs.
  CONFIG_TFM_SECURE_THREAD_MASK_NS_INTERRUPT=1
  # SystemInit() in system_nrf54l.c turns the glitch detector off unless this is set. b0 and
  # MCUboot set it through Kconfig, but the TF-M platform has no option for it. TF-M is the last
  # secure stage, so without it the wallet runs with the detector off.
  NRF_SKIP_GLITCHDETECTOR_DISABLE
)
