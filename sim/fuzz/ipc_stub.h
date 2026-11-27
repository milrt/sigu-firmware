// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <psa/service.h>
#include <stddef.h>
#include <stdint.h>

// Sets up one message with these invecs and no outvecs, as TF-M hands it to the SP.
// The psa_read() calls then read from them. Returns the msg for the handler.
psa_msg_t *ipc_stub_message(int32_t type, const uint8_t *const in[PSA_MAX_IOVEC],
                            const size_t in_len[PSA_MAX_IOVEC]);

// True once the handler called psa_reply() for the message, exactly once.
int ipc_stub_replied(void);
