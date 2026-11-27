// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "shared/tx_records.h"
#include "shared/wire.h"
#include <string.h>

void tx_put_le32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value & 0xFF);
    dst[1] = (uint8_t)((value >> 8) & 0xFF);
    dst[2] = (uint8_t)((value >> 16) & 0xFF);
    dst[3] = (uint8_t)((value >> 24) & 0xFF);
}

void tx_put_le64(uint8_t *dst, uint64_t value)
{
    for (size_t i = 0; i < 8; i++) {
        dst[i] = (uint8_t)((value >> (8 * i)) & 0xFF);
    }
}

void bitcoin_tx_begin_pack(const bitcoin_tx_begin_t *in, bitcoin_tx_begin_rec_t *out)
{
    wire_w w = wire_writer(out->bytes, sizeof(out->bytes));

    wire_put_le32(&w, in->version);
    wire_put_le32(&w, in->locktime);
    wire_put_le32(&w, in->num_inputs);
    wire_put_le32(&w, in->num_outputs);
    wire_put_le32(&w, in->sighash_type);
}

void bitcoin_tx_begin_unpack(const bitcoin_tx_begin_rec_t *in, bitcoin_tx_begin_t *out)
{
    wire_r r = wire_reader(in->bytes, sizeof(in->bytes));

    out->version = wire_get_le32(&r);
    out->locktime = wire_get_le32(&r);
    out->num_inputs = wire_get_le32(&r);
    out->num_outputs = wire_get_le32(&r);
    out->sighash_type = wire_get_le32(&r);
}

bool bitcoin_tx_output_pack(const bitcoin_tx_output_t *in, bitcoin_tx_output_rec_t *out)
{
    wire_w w = wire_writer(out->bytes, sizeof(out->bytes));

    wire_put_le64(&w, in->amount);
    wire_put_u8(&w, in->script_len);
    wire_put_field(&w, in->script, in->script_len, BITCOIN_TX_SCRIPT_MAX_SIZE);
    return w.ok;
}

bool bitcoin_tx_output_unpack(const bitcoin_tx_output_rec_t *in, bitcoin_tx_output_t *out)
{
    wire_r r = wire_reader(in->bytes, sizeof(in->bytes));

    out->amount = wire_get_le64(&r);
    out->script_len = wire_get_u8(&r);

    // The record comes from NS. A length past the end of the fixed script field is refused here,
    // and all code after this point takes script_len as checked.
    if (out->script_len > BITCOIN_TX_SCRIPT_MAX_SIZE) {
        return false;
    }
    memset(out->script, 0, sizeof(out->script));
    wire_get_field(&r, out->script, out->script_len, BITCOIN_TX_SCRIPT_MAX_SIZE);
    return r.ok;
}

void bitcoin_tx_input_pack(const bitcoin_tx_input_t *in, bitcoin_tx_input_rec_t *out)
{
    wire_w w = wire_writer(out->bytes, sizeof(out->bytes));

    wire_put_field(&w, in->txid, BITCOIN_TXID_SIZE, BITCOIN_TXID_SIZE);
    wire_put_le32(&w, in->vout);
    wire_put_le32(&w, in->sequence);
}

void bitcoin_tx_input_unpack(const bitcoin_tx_input_rec_t *in, bitcoin_tx_input_t *out)
{
    wire_r r = wire_reader(in->bytes, sizeof(in->bytes));

    wire_get_field(&r, out->txid, BITCOIN_TXID_SIZE, BITCOIN_TXID_SIZE);
    out->vout = wire_get_le32(&r);
    out->sequence = wire_get_le32(&r);
}

bool tx_format_btc(uint64_t sats, char *out, size_t out_size)
{
    // "184467440737.09551615" is the longest possible result: 21 chars + NUL.
    char digits[24];
    size_t len = 0;
    uint64_t whole = sats / 100000000ULL;
    uint32_t frac = (uint32_t)(sats % 100000000ULL);

    if (!out) {
        return false;
    }

    // The integer part, built backwards and then reversed.
    // No floating point: a double cannot hold 21e6 BTC in satoshis exactly,
    // and an amount the user approves must not be rounded.
    do {
        digits[len++] = (char)('0' + (whole % 10));
        whole /= 10;
    } while (whole > 0 && len < sizeof(digits));

    // The digits, the point, 8 decimals and the NUL.
    if (out_size < len + 10) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        out[i] = digits[len - 1 - i];
    }

    out[len++] = '.';
    for (int i = 7; i >= 0; i--) {
        out[len + (size_t)i] = (char)('0' + (frac % 10));
        frac /= 10;
    }
    len += 8;
    out[len] = '\0';
    return true;
}
