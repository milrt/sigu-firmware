// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The BIP380 output descriptor of the BIP84 account 0 on mainnet:
//
//   wpkh([<fingerprint>/84h/0h/0h]<xpub>/<0;1>/*)#<checksum>
//
// BlueWallet, Sparrow, Bitcoin Core and others import it as a watch-only wallet.
// The key origin is needed: the PSBTs that wallet makes must carry this fingerprint,
// or psbt_signer.c does not sign them.
// A descriptor takes an xpub, not a zpub, and wpkh() already says P2WPKH.
// BIP389's <0;1> gives the receive and the change chain in one line.
// NS writes it to the card and the partition builds it for the QR, so there is no snprintf here.

#pragma once

#include "shared/bitcoin_service_defs.h"
#include <stddef.h>
#include <stdint.h>

// The key the descriptor holds: BIP84, mainnet, account 0.
#define DESCRIPTOR_ACCOUNT_PATH "m/84'/0'/0'"

// Room for the descriptor and its NUL.
#define DESCRIPTOR_MAX_SIZE                                                                        \
    (sizeof("wpkh([00000000/84h/0h/0h]/<0;1>/*)#00000000") + BITCOIN_XPUB_MAX_SIZE)

// Writes wpkh([<fp>/84h/0h/0h]<xpub>/<0;1>/*)#<checksum> to `out`, NUL terminated.
// Returns its length without the NUL,
// or 0 when it does not fit or `xpub` has a char BIP380 does not allow.
size_t descriptor_build(const uint8_t fp[BITCOIN_FINGERPRINT_SIZE], const char *xpub, char *out,
                        size_t size);
