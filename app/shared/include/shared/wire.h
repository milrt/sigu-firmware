// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// A cursor over a fixed byte buffer:
// the IPC records, the stored records, image headers and the BIP143 preimage.
// Fields are little endian and go in order.
// `ok` is sticky: a step past the end sets it to false and does nothing,
// so the caller checks it once at the end.
// No Zephyr headers, because the SP and MCUboot include this too.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t *p;
    size_t size;
    size_t pos;
    bool ok;
} wire_w;

typedef struct {
    const uint8_t *p;
    size_t size;
    size_t pos;
    bool ok;
} wire_r;

static inline wire_w wire_writer(void *buf, size_t size)
{
    return (wire_w){.p = buf, .size = size, .pos = 0, .ok = true};
}

static inline wire_r wire_reader(const void *buf, size_t size)
{
    return (wire_r){.p = buf, .size = size, .pos = 0, .ok = true};
}

static inline uint8_t *wire_w_take(wire_w *w, size_t n)
{
    if (!w->ok || n > w->size - w->pos) {
        w->ok = false;
        return NULL;
    }
    w->pos += n;
    return &w->p[w->pos - n];
}

static inline const uint8_t *wire_r_take(wire_r *r, size_t n)
{
    if (!r->ok || n > r->size - r->pos) {
        r->ok = false;
        return NULL;
    }
    r->pos += n;
    return &r->p[r->pos - n];
}

static inline void wire_put_le(wire_w *w, uint64_t value, size_t n)
{
    uint8_t *dst = wire_w_take(w, n);

    for (size_t i = 0; dst && i < n; i++) {
        dst[i] = (uint8_t)(value >> (8 * i));
    }
}

static inline uint64_t wire_get_le(wire_r *r, size_t n)
{
    const uint8_t *src = wire_r_take(r, n);
    uint64_t value = 0;

    for (size_t i = 0; src && i < n; i++) {
        value |= (uint64_t)src[i] << (8 * i);
    }
    return value;
}

static inline void wire_put_u8(wire_w *w, uint8_t v)
{
    wire_put_le(w, v, 1);
}
static inline void wire_put_le32(wire_w *w, uint32_t v)
{
    wire_put_le(w, v, 4);
}
static inline void wire_put_le64(wire_w *w, uint64_t v)
{
    wire_put_le(w, v, 8);
}
static inline uint8_t wire_get_u8(wire_r *r)
{
    return (uint8_t)wire_get_le(r, 1);
}
static inline uint32_t wire_get_le32(wire_r *r)
{
    return (uint32_t)wire_get_le(r, 4);
}
static inline uint64_t wire_get_le64(wire_r *r)
{
    return wire_get_le(r, 8);
}

// Writes `len` bytes of `src` into a field of `field` bytes and zero fills the rest.
static inline void wire_put_field(wire_w *w, const void *src, size_t len, size_t field)
{
    uint8_t *dst = (len <= field) ? wire_w_take(w, field) : NULL;

    if (!dst) {
        w->ok = false;
        return;
    }
    memcpy(dst, src, len);
    memset(dst + len, 0, field - len);
}

// Reads the first `len` bytes of a field of `field` bytes and skips the rest.
static inline void wire_get_field(wire_r *r, void *dst, size_t len, size_t field)
{
    const uint8_t *src = (len <= field) ? wire_r_take(r, field) : NULL;

    if (!src) {
        r->ok = false;
        return;
    }
    memcpy(dst, src, len);
}
