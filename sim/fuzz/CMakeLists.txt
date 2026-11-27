# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

# Fuzz targets for the code that reads what the other side sent. Only with -DSIGU_SIM_FUZZ=ON.

function(sigu_fuzz name)
  add_executable(${name} ${ARGN})
  target_compile_options(${name} PRIVATE ${SIGU_WARNINGS})
  if(SIGU_HAVE_LIBFUZZER)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
  else()
    target_sources(${name} PRIVATE replay.c)
  endif()
endfunction()

sigu_fuzz(fuzz_psbt fuzz_psbt.c ${CMAKE_SOURCE_DIR}/src/heap.c ${CMAKE_SOURCE_DIR}/src/sched_pthread.c)
target_include_directories(fuzz_psbt PRIVATE ${NS_DIR}/bitcoin/src ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(fuzz_psbt PRIVATE ns)

sigu_fuzz(fuzz_prev_tx fuzz_prev_tx.c)
target_include_directories(fuzz_prev_tx PRIVATE ${SP_PRIVATE_DIRS})
target_link_libraries(fuzz_prev_tx PRIVATE sp)

sigu_fuzz(fuzz_records fuzz_records.c)
target_link_libraries(fuzz_records PRIVATE shared)

sigu_fuzz(fuzz_files_set fuzz_files_set.c ipc_stub.c ${CMAKE_SOURCE_DIR}/src/ps.c
          ${CMAKE_SOURCE_DIR}/src/firmware_flash.c ${CMAKE_SOURCE_DIR}/src/flash.c
          ${CMAKE_SOURCE_DIR}/src/sched_pthread.c)
target_include_directories(fuzz_files_set PRIVATE ${SP_PRIVATE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(fuzz_files_set PRIVATE sp sim_mcuboot)

# The tx session driven as a malicious NS would, with the review's invariants checked.
sigu_fuzz(fuzz_tx_session fuzz_tx_session.c)
target_include_directories(fuzz_tx_session PRIVATE ${SP_PRIVATE_DIRS})
target_link_libraries(fuzz_tx_session PRIVATE sp)

# The image layout in slot1 and the install record.
sigu_fuzz(fuzz_install fuzz_install.c)
target_link_libraries(fuzz_install PRIVATE shared)
