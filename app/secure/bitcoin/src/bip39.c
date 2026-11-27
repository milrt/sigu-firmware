// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bip39.h"
#include "bip39_wordlist.h"
#include "shared/hash.h"
#include "shared/mem_util.h"
#include <string.h>

#define MAX_WORDS 24
#define MAX_WORD_LEN 8 // the longest word of the English list
#define BITS_PER_WORD 11
#define BITS_SIZE 33 // 24 words of 11 bits: 32 bytes of entropy and the checksum byte
#define MAX_SALT_LEN 1024

// The checksum bits in the byte after the entropy, or 0 for a size BIP39 does not have.
static uint8_t checksum_mask(size_t entropy_len)
{
    switch (entropy_len) {
    case 16:
        return 0xF0;
    case 20:
        return 0xF8;
    case 24:
        return 0xFC;
    case 28:
        return 0xFE;
    case 32:
        return 0xFF;
    default:
        return 0;
    }
}

// 0 for a word count BIP39 does not have.
static size_t entropy_len_of(size_t word_count)
{
    switch (word_count) {
    case 12:
        return 16;
    case 15:
        return 20;
    case 18:
        return 24;
    case 21:
        return 28;
    case 24:
        return 32;
    default:
        return 0;
    }
}

// The index of `word` in the list, or -1.
// Half-open [low, high), so a word that sorts before the first one cannot push high below zero.
static int find_word(const char *word)
{
    for (size_t low = 0, high = BIP39_WORDLIST_EN_SIZE; low < high;) {
        size_t mid = low + (high - low) / 2;
        int cmp = strcmp(word, bip39_wordlist_en[mid]);

        if (cmp == 0) {
            return (int)mid;
        }
        if (cmp < 0) {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    return -1;
}

// Word `n` is the 11 bits from bit 11n of `bits`, most significant first.
static uint16_t get_word(const uint8_t *bits, size_t n)
{
    uint16_t index = 0;

    for (size_t pos = n * BITS_PER_WORD; pos < (n + 1) * BITS_PER_WORD; pos++) {
        index = (index << 1) | ((bits[pos / 8] >> (7 - pos % 8)) & 1);
    }
    return index;
}

// Only ORs, so `bits` must start zeroed.
static void put_word(uint8_t *bits, size_t n, uint16_t index)
{
    for (size_t i = 0; i < BITS_PER_WORD; i++) {
        size_t pos = n * BITS_PER_WORD + i;

        bits[pos / 8] |= ((index >> (BITS_PER_WORD - 1 - i)) & 1) << (7 - pos % 8);
    }
}

// The words of `mnemonic` into the zeroed `bits`.
// An empty word (a space at the start or end, or two in a row) fails, it is not skipped.
static psa_status_t parse_mnemonic(const char *mnemonic, uint8_t bits[BITS_SIZE],
                                   size_t *entropy_len)
{
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    char word[MAX_WORD_LEN + 1] = {0};
    const char *p = mnemonic;
    size_t word_count = 0;

    for (;;) {
        size_t len = 0;

        while (*p >= 'a' && *p <= 'z') {
            if (len == MAX_WORD_LEN) {
                goto cleanup;
            }
            word[len++] = *p++;
        }
        // This also checks the end of the previous word.
        if (len == 0 || word_count == MAX_WORDS) {
            goto cleanup;
        }
        word[len] = '\0';

        int index = find_word(word);
        if (index < 0) {
            goto cleanup;
        }
        put_word(bits, word_count++, (uint16_t)index);

        if (*p == '\0') {
            break;
        }
        if (*p++ != ' ') {
            goto cleanup;
        }
    }

    *entropy_len = entropy_len_of(word_count);
    status = *entropy_len ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;

cleanup:
    mem_zeroize(word, sizeof(word));
    return status;
}

psa_status_t bip39_mnemonic_to_entropy(const char *mnemonic, uint8_t *entropy_out,
                                       size_t *entropy_out_size)
{
    if (!mnemonic || !entropy_out || !entropy_out_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t bits[BITS_SIZE] = {0};
    uint8_t hash[32] = {0};
    size_t entropy_len = 0;

    psa_status_t status = parse_mnemonic(mnemonic, bits, &entropy_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    if (*entropy_out_size < entropy_len) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }
    status = hash_sha256(bits, entropy_len, hash, sizeof(hash));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    if (((bits[entropy_len] ^ hash[0]) & checksum_mask(entropy_len)) != 0) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    memcpy(entropy_out, bits, entropy_len);
    *entropy_out_size = entropy_len;

cleanup:
    mem_zeroize(bits, sizeof(bits));
    mem_zeroize(hash, sizeof(hash));
    return status;
}

psa_status_t bip39_entropy_to_mnemonic(const uint8_t *entropy, size_t entropy_len,
                                       char *mnemonic_out, size_t mnemonic_out_size)
{
    if (!entropy || !mnemonic_out || !checksum_mask(entropy_len)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // 4 entropy bytes are 3 words, the checksum fills the last one.
    const size_t word_count = entropy_len * 3 / 4;
    uint8_t bits[BITS_SIZE] = {0};
    uint8_t hash[32] = {0};
    size_t size = 1; // the NUL

    memcpy(bits, entropy, entropy_len);
    psa_status_t status = hash_sha256(entropy, entropy_len, hash, sizeof(hash));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    bits[entropy_len] = hash[0] & checksum_mask(entropy_len);

    // Counted first, so a short buffer gets no part of the mnemonic.
    for (size_t i = 0; i < word_count; i++) {
        size += strlen(bip39_wordlist_en[get_word(bits, i)]) + (i ? 1 : 0);
    }
    if (size > mnemonic_out_size) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    char *p = mnemonic_out;
    for (size_t i = 0; i < word_count; i++) {
        const char *word = bip39_wordlist_en[get_word(bits, i)];
        size_t len = strlen(word);

        if (i) {
            *p++ = ' ';
        }
        memcpy(p, word, len);
        p += len;
    }
    *p = '\0';

cleanup:
    mem_zeroize(bits, sizeof(bits));
    mem_zeroize(hash, sizeof(hash));
    return status;
}

psa_status_t bip39_validate_mnemonic(const char *mnemonic)
{
    uint8_t entropy[32];
    size_t entropy_size = sizeof(entropy);
    psa_status_t status = bip39_mnemonic_to_entropy(mnemonic, entropy, &entropy_size);

    mem_zeroize(entropy, sizeof(entropy));
    return status;
}

psa_status_t bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                                    uint8_t seed_out[BIP39_SEED_SIZE])
{
    static const char prefix[] = "mnemonic";
    const size_t prefix_len = sizeof(prefix) - 1;
    uint8_t salt[MAX_SALT_LEN];
    size_t pass_len;

    if (!seed_out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    psa_status_t status = bip39_validate_mnemonic(mnemonic);
    if (status != PSA_SUCCESS) {
        return status;
    }
    pass_len = passphrase ? strlen(passphrase) : 0;
    if (prefix_len + pass_len > sizeof(salt)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    memcpy(salt, prefix, prefix_len);
    if (pass_len) {
        memcpy(salt + prefix_len, passphrase, pass_len);
    }
    status = hash_pbkdf2_hmac_sha512((const uint8_t *)mnemonic, strlen(mnemonic), salt,
                                     prefix_len + pass_len, 2048, seed_out, BIP39_SEED_SIZE);
    if (status != PSA_SUCCESS) {
        mem_zeroize(seed_out, BIP39_SEED_SIZE);
    }
    mem_zeroize(salt, sizeof(salt));
    return status;
}
