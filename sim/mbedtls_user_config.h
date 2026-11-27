// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// Mbed TLS for the sim. PSA picks its algorithms from psa/crypto_config.h, which has PBKDF2-HMAC.
// The legacy config does not turn PBKDF2 on for PSA.
// SP and NS are threads here, so the PSA core needs its locks.

#define MBEDTLS_PSA_CRYPTO_CONFIG
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD
