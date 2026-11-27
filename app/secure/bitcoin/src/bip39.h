// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// BIP39 with the English wordlist: entropy to words, words to entropy,
// and words and passphrase to the seed.
//
// A mnemonic is 12, 15, 18, 21 or 24 lowercase words from the list,
// one ASCII space between them, with a valid checksum.
// Any other string is PSA_ERROR_INVALID_ARGUMENT:
// no space at the start or end, no two in a row, no capitals.

#pragma once

#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

#define BIP39_SEED_SIZE 64

// The mnemonic of 16, 20, 24, 28 or 32 bytes of entropy, with a NUL.
// PSA_ERROR_BUFFER_TOO_SMALL writes nothing.
psa_status_t bip39_entropy_to_mnemonic(const uint8_t *entropy, size_t entropy_len,
                                       char *mnemonic_out, size_t mnemonic_out_size);

psa_status_t bip39_validate_mnemonic(const char *mnemonic);

// The entropy of a mnemonic. `*entropy_out_size` is the buffer size in and the entropy size out.
// PSA_ERROR_BUFFER_TOO_SMALL writes nothing.
psa_status_t bip39_mnemonic_to_entropy(const char *mnemonic, uint8_t *entropy_out,
                                       size_t *entropy_out_size);

// The seed of a mnemonic and `passphrase` (NULL is "").
// BIP39 makes a seed from any string, but this refuses a mnemonic that is not valid.
psa_status_t bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                                    uint8_t seed_out[BIP39_SEED_SIZE]);
