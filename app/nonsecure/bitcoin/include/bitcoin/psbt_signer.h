// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "bitcoin_client.h"
#include "psbt.h"
#include "psbt_result.h"

// Signs the inputs of `psbt` that belong to the wallet of `svc`, and adds the partial signatures.
// The partition shows the streamed tx on the review screen, and this waits for the approve press.
// `on_wait` may be NULL. It runs once when the wait starts, so the self-tests can approve from it.
//
// Fails if the wallet is not open, if the partition refuses the tx, if the user rejects it,
// or if no input is ours.
psbt_result_t psbt_sign(psbt_t *psbt, const bitcoin_service_t *svc, void (*on_wait)(void));
