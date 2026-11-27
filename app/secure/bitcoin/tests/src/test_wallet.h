// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "bitcoin/bitcoin_core.h"

// The BIP84 test vector mnemonic.
#define TEST_MNEMONIC                                                                              \
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "     \
    "about"

// The test session, closed and opened again from TEST_MNEMONIC with no passphrase.
// It has programmatic approval and its own storage namespace.
wallet_session_t *open_test_wallet(void);
