# Copyright (C) 2025 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

# Host simulator. It builds the real SP sources with host versions of TF-M's IPC, PS, the
# panel, the keys and the tick. It is not part of the firmware build.

cmake_minimum_required(VERSION 3.20)
project(sigu_sim C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(SIGU_SIM_WERROR "Fail the build on a warning in our sources" ON)
option(SIGU_SIM_SANITIZE "Build everything with ASan and UBSan" OFF)
option(SIGU_SIM_FUZZ "Build only the fuzz targets in fuzz/, with ASan and UBSan" OFF)

# Only our own sources. Third-party code keeps its own flags.
set(SIGU_WARNINGS -Wall -Wextra $<$<BOOL:${SIGU_SIM_WERROR}>:-Werror>)

# Set before the libraries are added, so Mbed TLS and secp256k1 are instrumented too.
if((SIGU_SIM_SANITIZE OR SIGU_SIM_FUZZ) AND NOT EMSCRIPTEN)
  set(SIGU_SANITIZERS -fsanitize=address,undefined -fno-sanitize-recover=all)
  add_compile_options(${SIGU_SANITIZERS} -fno-omit-frame-pointer -g)
  add_link_options(${SIGU_SANITIZERS})
endif()
if(SIGU_SIM_FUZZ)
  include(fuzz/libfuzzer.cmake)
endif()

get_filename_component(SIGU_DIR ${CMAKE_CURRENT_SOURCE_DIR}/.. ABSOLUTE)
set(EXTERNAL_DIR ${SIGU_DIR}/../external CACHE PATH "The west external/ folder")

set(APP_DIR       ${SIGU_DIR}/app)
set(SP_DIR        ${APP_DIR}/secure)
set(SHARED_DIR    ${APP_DIR}/shared)
set(BITCOIN_DIR   ${EXTERNAL_DIR}/bitcoin)
set(SECP256K1_DIR ${BITCOIN_DIR}/secp256k1)
set(BIPS_DIR      ${BITCOIN_DIR}/bips)
set(LIBBASE58_DIR ${BITCOIN_DIR}/libbase58)
set(QRCODEGEN_DIR ${EXTERNAL_DIR}/qrcodegen/c CACHE PATH "nayuki's QR-Code-generator, c/")

# The device uses Oberon PSA, which has no host build. Mbed TLS 3.6 LTS has the same PSA API.
# The release tarball has the generated files, so the build needs no Python.
include(FetchContent)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(LINK_WITH_PTHREAD ON CACHE BOOL "" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
set(MBEDTLS_USER_CONFIG_FILE ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_user_config.h
    CACHE FILEPATH "" FORCE)
FetchContent_Declare(mbedtls
  URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.4/mbedtls-3.6.4.tar.bz2
  URL_HASH SHA256=ec35b18a6c593cf98c3e30db8b98ff93e8940a8c4e690e66b41dfc011d678110
  DOWNLOAD_EXTRACT_TIMESTAMP ON
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(mbedtls)

if(NOT EMSCRIPTEN AND NOT SIGU_SIM_FUZZ)
  find_package(SDL2 REQUIRED)
endif()

include(${SP_DIR}/bitcoin/cmake/bip39_wordlist.cmake)
add_library(bip39_wordlist STATIC ${WORDLIST_OUTPUT_DIR}/bip39_wordlist.c)
target_include_directories(bip39_wordlist PUBLIC ${WORDLIST_OUTPUT_DIR})

include(${SP_DIR}/bitcoin/cmake/secp256k1-config.cmake)
# The device runs the C code. The x86_64 asm also needs more registers than ASan leaves free.
set(SECP256K1_ASM OFF CACHE STRING "Assembly to use" FORCE)
add_subdirectory(${SECP256K1_DIR} ${CMAKE_BINARY_DIR}/secp256k1 EXCLUDE_FROM_ALL)
target_compile_definitions(secp256k1 PRIVATE USE_EXTERNAL_DEFAULT_CALLBACKS)

# app/shared goes into both images on the device. Here there is one image, so it is built once.
add_library(shared STATIC
  ${SHARED_DIR}/src/hash.c
  ${SHARED_DIR}/src/fw_image.c
  ${SHARED_DIR}/src/install_auth.c
  ${SHARED_DIR}/src/ripemd160.c
  ${SHARED_DIR}/src/segwit_addr.c
  ${SHARED_DIR}/src/tx_records.c
  ${SHARED_DIR}/src/descriptor.c
)
target_include_directories(shared PUBLIC shim ${SHARED_DIR}/include)
target_link_libraries(shared PUBLIC mbedcrypto)

# The secure partition, as in app/secure/CMakeLists.txt and app/secure/bitcoin/CMakeLists.txt.
# input.c, panel_hw.c, tamper.c and tick.c come from sim/src instead. panel.c is built through
# src/panel_text.c, which includes it unchanged and adds a text reader for the tests.
# bitcoin_service.c is in SIM_COMMON, so fuzz/fuzz_files_set.c can include it and link sp.
add_library(sp STATIC
  ${SP_DIR}/files/src/files.c
  ${SP_DIR}/files/src/firmware.c
  ${SP_DIR}/display/src/core/display.c
  ${SP_DIR}/display/src/core/config.c
  ${SP_DIR}/display/src/core/theme.c
  src/panel_text.c
  ${SP_DIR}/display/src/core/text.c
  ${SP_DIR}/display/src/fonts/montserrat_16.c
  ${SP_DIR}/display/src/fonts/montserrat_20.c
  ${SP_DIR}/display/src/fonts/montserrat_24.c
  ${SP_DIR}/display/src/components/header.c
  ${SP_DIR}/display/src/components/label.c
  ${SP_DIR}/display/src/components/list.c
  ${SP_DIR}/display/src/components/qr.c
  ${SP_DIR}/display/src/components/softkeys.c
  ${SP_DIR}/display/src/components/wheel.c
  ${SP_DIR}/display/src/components/word_picker.c
  ${SP_DIR}/display/src/components/seed_entry.c
  ${SP_DIR}/display/src/components/passphrase_entry.c
  ${SP_DIR}/display/src/components/pin_entry.c
  ${SP_DIR}/display/src/screens/status.c
  ${SP_DIR}/display/src/screens/review.c
  ${SP_DIR}/display/src/screens/menu.c
  ${SP_DIR}/display/src/screens/temp_wallet.c
  ${SP_DIR}/display/src/screens/wallet_setup.c
  ${SP_DIR}/display/src/screens/unlock.c
  ${SP_DIR}/display/src/screens/settings.c
  ${SP_DIR}/display/src/screens/files.c
  ${SP_DIR}/display/src/screens/sign_job.c
  ${SP_DIR}/display/src/screens/firmware.c
  ${SP_DIR}/display/src/screens/export.c
  ${SP_DIR}/display/src/screens/receive.c
  ${SP_DIR}/display/src/screens/reset.c
  ${QRCODEGEN_DIR}/qrcodegen.c
  ${LIBBASE58_DIR}/base58.c
  ${SP_DIR}/bitcoin/src/bitcoin_core.c
  ${SP_DIR}/bitcoin/src/sighash.c
  ${SP_DIR}/bitcoin/src/tx_session.c
  ${SP_DIR}/bitcoin/src/script.c
  ${SP_DIR}/bitcoin/src/base58.c
  ${SP_DIR}/bitcoin/src/bip39.c
  ${SP_DIR}/bitcoin/src/bip32.c
  ${SP_DIR}/bitcoin/src/key_storage.c
  ${SP_DIR}/bitcoin/src/secp256k1_context.c
  ${SHARED_DIR}/src/test_util.c
  ${SHARED_DIR}/tests/src/hash_test.c
  ${SHARED_DIR}/tests/src/shared_test.c
  ${SP_DIR}/bitcoin/tests/src/secure_bitcoin_test.c
  ${SP_DIR}/bitcoin/tests/src/bip39_test.c
  ${SP_DIR}/bitcoin/tests/src/bip39_test_vectors.c
  ${SP_DIR}/bitcoin/tests/src/bip32_test_vectors.c
  ${SP_DIR}/bitcoin/tests/src/bip32_test.c
  ${SP_DIR}/bitcoin/tests/src/key_storage_test.c
  ${SP_DIR}/bitcoin/tests/src/tx_session_test.c
  ${SP_DIR}/bitcoin/tests/src/script_test.c
  ${SP_DIR}/bitcoin/tests/src/get_key_test.c
  src/input.c
  src/panel_hw.c
  src/tamper.c
  src/tick.c
)

# Also for the sources that include SP internals: bitcoin_service.c and the fuzz targets.
set(SP_PRIVATE_DIRS
  ${SP_DIR}
  ${SP_DIR}/bitcoin/src
  ${SP_DIR}/display/src
  ${SP_DIR}/drivers/src
  ${LIBBASE58_DIR}
  ${QRCODEGEN_DIR}
)

# The sim keeps the self-test build: the test service, the test wallet and the self-tests.
target_compile_definitions(sp PUBLIC SIGU_SELFTEST)

target_include_directories(sp PUBLIC
  shim
  src
  ${SP_DIR}/display/include
  ${SP_DIR}/files/include
  ${SP_DIR}/drivers/include
  ${SP_DIR}/bitcoin/include
  ${SP_DIR}/bitcoin/tests/include
  ${SHARED_DIR}/include
  ${SHARED_DIR}/tests/include
  PRIVATE
  ${SP_PRIVATE_DIRS}
)

target_link_libraries(sp PUBLIC shared bip39_wordlist secp256k1)
target_compile_options(sp PRIVATE ${SIGU_WARNINGS})
target_compile_options(shared PRIVATE ${SIGU_WARNINGS})
# Third-party sources built inside sp.
set_source_files_properties(${QRCODEGEN_DIR}/qrcodegen.c ${LIBBASE58_DIR}/base58.c
                            TARGET_DIRECTORY sp PROPERTIES COMPILE_OPTIONS -w)

# The real MCUboot: its loader, swap-using-move and checks, unchanged, with our hooks
# (app/mcuboot_hooks/hooks.c) and a small port on the sim's flash (mcuboot/). See
# mcuboot/include/mcuboot_config/mcuboot_config.h for how it matches the device.
set(MCUBOOT_DIR ${EXTERNAL_DIR}/bootloader/mcuboot/boot/bootutil CACHE PATH "MCUboot's bootutil")
set(MCUBOOT_SOURCES
  ${MCUBOOT_DIR}/src/loader.c
  ${MCUBOOT_DIR}/src/bootutil_loader.c
  ${MCUBOOT_DIR}/src/bootutil_misc.c
  ${MCUBOOT_DIR}/src/bootutil_public.c
  ${MCUBOOT_DIR}/src/bootutil_area.c
  ${MCUBOOT_DIR}/src/bootutil_img_hash.c
  ${MCUBOOT_DIR}/src/image_validate.c
  ${MCUBOOT_DIR}/src/tlv.c
  ${MCUBOOT_DIR}/src/swap_misc.c
  ${MCUBOOT_DIR}/src/swap_move.c
  ${MCUBOOT_DIR}/src/swap_nsib.c
  ${MCUBOOT_DIR}/src/fault_injection_hardening.c
)
add_library(sim_mcuboot STATIC
  ${MCUBOOT_SOURCES}
  ${APP_DIR}/mcuboot_hooks/hooks.c
  mcuboot/port.c
)
target_include_directories(sim_mcuboot
  PUBLIC mcuboot/include ${MCUBOOT_DIR}/include shim ${SHARED_DIR}/include
  PRIVATE ${MCUBOOT_DIR}/src
)
target_link_libraries(sim_mcuboot PUBLIC shared mbedcrypto)
# The device builds MCUboot with CONFIG_ASSERT=n, so its asserts do nothing there. Same here in
# every build type, or a debug build would stop where the device goes on.
set_source_files_properties(${MCUBOOT_SOURCES} TARGET_DIRECTORY sim_mcuboot
                            PROPERTIES COMPILE_OPTIONS "-w;-DNDEBUG")
target_compile_options(sim_mcuboot PRIVATE ${SIGU_WARNINGS})

# The non-secure side: the PSA client, the PSBT code, the card thread, the health thread
# and the NS self-tests. No shell yet.
# The self-tests use the SP's test_util.c: the sim has one copy.
set(NS_DIR ${APP_DIR}/nonsecure)
add_library(ns STATIC
  ${NS_DIR}/bitcoin/src/bitcoin_client.c
  ${NS_DIR}/bitcoin/src/psbt.c
  ${NS_DIR}/bitcoin/src/psbt_compactsize.c
  ${NS_DIR}/bitcoin/src/psbt_heap.c
  ${NS_DIR}/bitcoin/src/psbt_signer.c
  ${NS_DIR}/bitcoin/src/psbt_tx.c
  ${NS_DIR}/files/src/sdcard.c
  ${NS_DIR}/files/src/install.c
  ${NS_DIR}/files/src/export.c
  ${NS_DIR}/health/src/health.c
  ${NS_DIR}/bitcoin/tests/src/nonsecure_bitcoin_test.c
  ${NS_DIR}/bitcoin/tests/src/psbt_test.c
)
target_compile_definitions(ns PUBLIC CONFIG_SIGU_SELFTEST=1 CONFIG_SIGU_WATCHDOG_TIMEOUT_MS=8000)
# files/src for card_detect.h: sim/src/card.c gives the sim its own card_present().
target_include_directories(ns PUBLIC ${NS_DIR}/bitcoin/include ${NS_DIR}/bitcoin/tests/include
                           ${NS_DIR}/files/src
                           PRIVATE ${NS_DIR}/bitcoin/src)
target_link_libraries(ns PUBLIC shared sim_mcuboot)
target_compile_options(ns PRIVATE ${SIGU_WARNINGS})

if(SIGU_SIM_FUZZ)
  add_subdirectory(fuzz)
  return()
endif()

set(SIM_COMMON
  ${SP_DIR}/bitcoin_service.c
  src/ipc.c
  src/ps.c
  src/control.c
  src/window.c
  src/kernel.c
  src/heap.c
  src/card.c
  src/flash.c
  src/wdt.c
  src/firmware_flash.c
)

if(EMSCRIPTEN)
  # The web build. The threads are fibers (Asyncify), so any static host can serve it.
  add_executable(sigu-sim src/web.c src/sched_fiber.c ${SIM_COMMON})
  set(SDL_PORT "-sUSE_SDL=2")
  target_compile_options(sigu-sim PRIVATE ${SDL_PORT})
  target_link_options(sigu-sim PRIVATE
    ${SDL_PORT}
    -sASYNCIFY
    -sASYNCIFY_STACK_SIZE=131072
    -sSTACK_SIZE=1048576
    -sALLOW_MEMORY_GROWTH
    -sEXIT_RUNTIME=0
    -sENVIRONMENT=web,node
    -sEXPORTED_FUNCTIONS=_main,_sim_web_command
    -sEXPORTED_RUNTIME_METHODS=FS,IDBFS,NODEFS,ccall
    -lidbfs.js
    -lnodefs.js
  )
  target_link_options(sigu-sim PRIVATE "LINKER:--whole-archive" $<TARGET_FILE:ns> "LINKER:--no-whole-archive")
  target_link_libraries(sigu-sim PRIVATE sp ns sim_mcuboot)
  target_compile_options(sigu-sim PRIVATE ${SIGU_WARNINGS})
  target_include_directories(sigu-sim PRIVATE ${SP_PRIVATE_DIRS})
  configure_file(web/index.html ${CMAKE_BINARY_DIR}/index.html COPYONLY)
  return()
endif()

add_executable(sigu-sim
  src/main.c
  src/sched_pthread.c
  ${SIM_COMMON}
)
# K_THREAD_DEFINE registers the card thread from a constructor in sdcard.c. Nothing else
# references that object, so the linker must be told to keep it.
if(APPLE)
  target_link_options(sigu-sim PRIVATE "LINKER:-force_load,$<TARGET_FILE:ns>")
else()
  target_link_options(sigu-sim PRIVATE "LINKER:--whole-archive" $<TARGET_FILE:ns> "LINKER:--no-whole-archive")
endif()
target_link_libraries(sigu-sim PRIVATE sp ns sim_mcuboot SDL2::SDL2 pthread)
target_compile_options(sigu-sim PRIVATE ${SIGU_WARNINGS})
target_include_directories(sigu-sim PRIVATE ${SP_PRIVATE_DIRS})
