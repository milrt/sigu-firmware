# Copyright (C) 2025 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.20)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

get_target_property(TFM_BINARY_DIR tfm TFM_BINARY_DIR)

# The second service exists only in a self-test build. Leaving it in the manifest
# while the handler is compiled out would make psa_wait() return a signal nothing
# answers, and tfm_bitcoin_init() panics on that.
#
# Zephyr's autoconf.h does not reach the TF-M build, so the partition gets its
# own spelling of the switch. Non-secure sources test CONFIG_SIGU_SELFTEST.
if(CONFIG_SIGU_SELFTEST)
  set(SIGU_TEST_SERVICE [[
      {
        "name": "TFM_BITCOIN_TEST",
        "sid": "0xFFFFF002",
        "non_secure_clients": true,
        "connection_based": true,
        "version": 3,
        "version_policy": "STRICT",
      },]])
  set(SIGU_SELFTEST_OPTION -DSIGU_SELFTEST=ON)
else()
  set(SIGU_TEST_SERVICE "")
  set(SIGU_SELFTEST_OPTION "")
endif()

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/secure/tfm_bitcoin_partition.yaml.in
  ${CMAKE_CURRENT_BINARY_DIR}/secure/tfm_bitcoin_partition.yaml
)
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/secure/tfm_manifest_list.yaml.in
  ${CMAKE_CURRENT_BINARY_DIR}/secure/tfm_manifest_list.yaml
)

if(NOT WEST_TOPDIR)
  set(WEST_TOPDIR $ENV{WEST_TOPDIR})
endif()
if(NOT WEST_TOPDIR)
  get_filename_component(WEST_TOPDIR ${ZEPHYR_BASE}/../.. ABSOLUTE)
endif()

set(BITCOIN_DIR   ${WEST_TOPDIR}/external/bitcoin)
set(SECP256K1_DIR ${BITCOIN_DIR}/secp256k1)
set(BIPS_DIR      ${BITCOIN_DIR}/bips)
set(LIBBASE58_DIR ${BITCOIN_DIR}/libbase58)
set(QRCODEGEN_DIR ${WEST_TOPDIR}/external/qrcodegen/c)
set(SHARED_DIR    ${CMAKE_CURRENT_SOURCE_DIR}/shared)

set_property(TARGET zephyr_property_target
  APPEND PROPERTY TFM_CMAKE_OPTIONS
  -DTFM_EXTRA_MANIFEST_LIST_FILES=${CMAKE_CURRENT_BINARY_DIR}/secure/tfm_manifest_list.yaml
  -DTFM_EXTRA_PARTITION_PATHS=${CMAKE_CURRENT_SOURCE_DIR}/secure
  -DSECP256K1_DIR=${SECP256K1_DIR}
  -DBIPS_DIR=${BIPS_DIR}
  -DLIBBASE58_DIR=${LIBBASE58_DIR}
  -DQRCODEGEN_DIR=${QRCODEGEN_DIR}
  -DSHARED_DIR=${SHARED_DIR}
  ${SIGU_SELFTEST_OPTION}
)

if(CONFIG_TFM_EXCEPTION_INFO_DUMP)
  set_property(TARGET zephyr_property_target
    APPEND PROPERTY TFM_CMAKE_OPTIONS -DTFM_EXCEPTION_DUMP_LVL=LOG_LEVEL_ERROR)
endif()

project(sigu LANGUAGES C)

# TFM_SP_BITCOIN makes the RADIO secure, so the BLE stack would fault at boot.
if(CONFIG_BT)
  message(FATAL_ERROR "CONFIG_BT is not allowed. The wallet is air-gapped.")
endif()

# Without it, a new chip never gets a HUK, and Protected Storage cannot store the wallet.
if(NOT CONFIG_HW_UNIQUE_KEY_RANDOM)
  message(FATAL_ERROR
    "CONFIG_HW_UNIQUE_KEY_RANDOM is required. TF-M provisions the HUK on first boot.")
endif()

# A release has no way in over USB, and nothing that reads a key or a fault out of the SP.
if(CONFIG_SIGU_RELEASE)
  foreach(option CONFIG_SIGU_SELFTEST CONFIG_SHELL CONFIG_TFM_EXCEPTION_INFO_DUMP)
    if(${option})
      message(FATAL_ERROR
        "${option} is not allowed in a release. Set it to n, and do not pass prj_dev.conf.")
    endif()
  endforeach()
endif()

# TF-M makes everything from slot0_ns to the end of RRAM non-secure. PS, ITS, the NV counters
# and the install record above that line would be open to NS.
dt_nodelabel(ns_path NODELABEL slot0_ns_partition REQUIRED)
dt_reg_addr(ns_addr PATH ${ns_path})
math(EXPR ns_addr "${ns_addr}")
foreach(label tfm_ps_partition tfm_its_partition tfm_otp_partition sigu_install_partition)
  dt_nodelabel(path NODELABEL ${label} REQUIRED)
  dt_reg_addr(addr PATH ${path})
  dt_reg_size(size PATH ${path})
  math(EXPR end "${addr} + ${size}")
  if(end GREATER ns_addr)
    message(FATAL_ERROR "${label} must end below slot0_ns_partition, or NS can write it.")
  endif()
endforeach()

# zephyr/patches.yml makes slot0_ns read-only for NS in TF-M's MPC setup. Without it, one NS
# write there bricks the device. `west update` drops the patch, so check that it is applied.
set(tfm_mpc_cfg
  ${ZEPHYR_TRUSTED_FIRMWARE_M_MODULE_DIR}/platform/ext/target/nordic_nrf/common/core/target_cfg_54l.c)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${tfm_mpc_cfg})
file(READ ${tfm_mpc_cfg} tfm_mpc_src)
string(FIND "${tfm_mpc_src}" "override.permmask |= MPC_OVERRIDE_PERMMASK_WRITE_Msk" found)
if(found EQUAL -1)
  message(FATAL_ERROR "The TF-M patches are not applied. Run: west patch clean && west patch apply")
endif()

# MCUboot's floor check (mcuboot_hooks) needs a security counter in every app image. An image
# without one reads as 0 and installs only while the floor is 0.
if(NOT CONFIG_MCUBOOT_EXTRA_IMGTOOL_ARGS MATCHES "--security-counter [0-9]+")
  message(FATAL_ERROR "Set --security-counter <n> in CONFIG_MCUBOOT_EXTRA_IMGTOOL_ARGS (prj.conf).")
endif()

# install.c reads slot0's MCUboot trailer with the bootutil public API.
if(TARGET MCUBOOT_BOOTUTIL)
  target_link_libraries(app PRIVATE MCUBOOT_BOOTUTIL)
endif()

target_sources(app PRIVATE ${ZEPHYR_BASE}/misc/empty_file.c
    nonsecure/main.c
    nonsecure/files/src/sdcard.c
    nonsecure/files/src/install.c
    nonsecure/files/src/export.c
    nonsecure/files/src/card_detect.c
    nonsecure/health/src/health.c
    nonsecure/bitcoin/src/bitcoin_client.c
    nonsecure/bitcoin/src/psbt.c
    nonsecure/bitcoin/src/psbt_compactsize.c
    nonsecure/bitcoin/src/psbt_tx.c
    nonsecure/bitcoin/src/psbt_heap.c
    nonsecure/bitcoin/src/psbt_signer.c
    shared/src/hash.c
    shared/src/fw_image.c
    shared/src/ripemd160.c
    shared/src/tx_records.c
    shared/src/descriptor.c
)

if(CONFIG_SHELL AND CONFIG_SIGU_SELFTEST)
  target_sources(app PRIVATE nonsecure/shell/src/bitcoin_shell.c)
endif()

if(CONFIG_SIGU_SELFTEST)
  target_sources(app PRIVATE
      shared/src/test_util.c
      nonsecure/bitcoin/tests/src/nonsecure_bitcoin_test.c
      nonsecure/bitcoin/tests/src/psbt_test.c
  )
endif()

target_include_directories(app PRIVATE
  $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/api_ns/interface/include
  nonsecure/bitcoin/include
  nonsecure/bitcoin/tests/include
  shared/tests/include
  shared/include
)

target_compile_definitions(app PRIVATE
  TFM_PARTITION_BITCOIN
)
