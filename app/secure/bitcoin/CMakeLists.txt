cmake_minimum_required(VERSION 3.20)

include(cmake/bip39_wordlist.cmake)
add_library(bip39_wordlist STATIC ${WORDLIST_OUTPUT_DIR}/bip39_wordlist.c)
target_include_directories(bip39_wordlist PUBLIC ${WORDLIST_OUTPUT_DIR})
include(cmake/secp256k1-config.cmake)

add_subdirectory(${SECP256K1_DIR} ${CMAKE_BINARY_DIR}/secp256k1)
# Use external default callbacks so we don't pull in fprintf/abort/stderr
target_compile_definitions(secp256k1 PRIVATE USE_EXTERNAL_DEFAULT_CALLBACKS)

add_library(bitcoin STATIC
    ${LIBBASE58_DIR}/base58.c
    ${SHARED_DIR}/src/hash.c
    ${SHARED_DIR}/src/fw_image.c
    ${SHARED_DIR}/src/install_auth.c
    ${SHARED_DIR}/src/ripemd160.c
    ${SHARED_DIR}/src/segwit_addr.c
    ${SHARED_DIR}/src/tx_records.c
    ${SHARED_DIR}/src/descriptor.c
    src/bitcoin_core.c
    src/sighash.c
    src/tx_session.c
    src/script.c
    src/base58.c
    src/bip39.c
    src/bip32.c
    src/key_storage.c
    src/secp256k1_context.c
)

if(SIGU_SELFTEST)
  target_sources(bitcoin PRIVATE
      ${SHARED_DIR}/src/test_util.c
      ${SHARED_DIR}/tests/src/hash_test.c
      ${SHARED_DIR}/tests/src/shared_test.c
      tests/src/secure_bitcoin_test.c
      tests/src/bip39_test.c
      tests/src/bip39_test_vectors.c
      tests/src/bip32_test_vectors.c
      tests/src/bip32_test.c
      tests/src/key_storage_test.c
      tests/src/tx_session_test.c
      tests/src/script_test.c
      tests/src/get_key_test.c
  )
  target_compile_definitions(bitcoin PUBLIC SIGU_SELFTEST)
endif()

target_include_directories(bitcoin PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/include
)

target_include_directories(bitcoin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LIBBASE58_DIR}
    ${SHARED_DIR}/include
    ${SHARED_DIR}/tests/include
)

target_link_libraries(bitcoin PRIVATE
    bip39_wordlist
    secp256k1
    psa_crypto_config
    tfm_sprt
    # Supplies tfm_log.h for INFO() and ERROR().
    platform_s
)
