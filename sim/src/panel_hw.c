// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The ST7789 is a 240x240 RGB565 framebuffer.
// panel.c sends bands in panel byte order (big endian), so we swap them back.
// The window and the screenshots read a copy under the lock.

#include "drivers/panel.h"
#include "panel_hw.h"
#include "sched.h"
#include "sim.h"
#include <stdio.h>
#include <string.h>

static uint16_t fb[PANEL_W * PANEL_H];
static uint8_t light;
static bool blanked = true;
static uint32_t frames;

void panel_hw_init(void)
{
    sched_lock();
    light = 0;
    blanked = true;
    frames++;
    sched_unlock();
}

void panel_hw_write_window(uint16_t x, uint16_t y, uint16_t w, uint16_t h, const uint16_t *pixels)
{
    sched_lock();
    for (int r = 0; r < h && y + r < PANEL_H; r++) {
        for (int c = 0; c < w && x + c < PANEL_W; c++) {
            fb[(y + r) * PANEL_W + x + c] = __builtin_bswap16(pixels[r * w + c]);
        }
    }
    frames++;
    sched_unlock();
}

void panel_hw_blank(bool on)
{
    sched_lock();
    blanked = on;
    frames++;
    sched_unlock();
}

void panel_hw_backlight(uint8_t percent)
{
    sched_lock();
    light = percent > 100 ? 100 : percent;
    frames++;
    sched_unlock();
}

// The sim has no gamma curve. The window shows the colors as panel.c sends them.
void panel_hw_gamma(uint8_t curve)
{
    (void)curve;
}

uint8_t sim_panel_light(void)
{
    uint8_t v;

    sched_lock();
    v = light;
    sched_unlock();
    return v;
}

uint32_t sim_panel_read(uint16_t *out, uint8_t *out_light, bool *out_blank)
{
    uint32_t n;

    sched_lock();
    memcpy(out, fb, sizeof(fb));
    *out_light = light;
    *out_blank = blanked;
    n = frames;
    sched_unlock();
    return n;
}

// PNG, with stored (uncompressed) deflate blocks. No zlib needed.

static uint32_t crc_table[256];

static uint32_t crc(uint32_t c, const uint8_t *p, size_t n)
{
    if (!crc_table[1]) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t v = i;
            for (int k = 0; k < 8; k++) {
                v = v & 1 ? 0xEDB88320U ^ (v >> 1) : v >> 1;
            }
            crc_table[i] = v;
        }
    }
    c = ~c;
    while (n--) {
        c = crc_table[(c ^ *p++) & 0xFF] ^ (c >> 8);
    }
    return ~c;
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

static bool chunk(FILE *f, const char *type, const uint8_t *data, uint32_t len)
{
    uint8_t hdr[8];
    uint8_t tail[4];
    uint32_t c;

    put32(hdr, len);
    memcpy(hdr + 4, type, 4);
    c = crc(0, hdr + 4, 4);
    c = crc(c, data, len);
    put32(tail, c);
    return fwrite(hdr, 1, 8, f) == 8 && fwrite(data, 1, len, f) == len &&
           fwrite(tail, 1, 4, f) == 4;
}

#define ROW (1 + PANEL_W * 3)
#define RAW (ROW * PANEL_H)
#define BLOCK 65535
#define ZLEN (2 + RAW + 5 * ((RAW + BLOCK - 1) / BLOCK) + 4)

bool sim_panel_png(const char *path)
{
    static const uint8_t sig[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    static uint16_t px[PANEL_W * PANEL_H];
    static uint8_t raw[RAW];
    static uint8_t z[ZLEN];
    uint8_t ihdr[13] = {0};
    uint32_t a = 1;
    uint32_t b = 0;
    size_t zn = 0;
    uint8_t lt;
    bool bl;
    bool ok;
    FILE *f;

    sim_panel_read(px, &lt, &bl);
    for (int y = 0; y < PANEL_H; y++) {
        uint8_t *r = &raw[y * ROW];

        r[0] = 0;
        for (int x = 0; x < PANEL_W; x++) {
            uint16_t p = bl ? 0 : px[y * PANEL_W + x];
            uint8_t r5 = p >> 11, g6 = (p >> 5) & 0x3F, b5 = p & 0x1F;

            r[1 + x * 3] = (r5 << 3) | (r5 >> 2);
            r[2 + x * 3] = (g6 << 2) | (g6 >> 4);
            r[3 + x * 3] = (b5 << 3) | (b5 >> 2);
        }
    }

    z[zn++] = 0x78;
    z[zn++] = 0x01;
    for (size_t off = 0; off < RAW; off += BLOCK) {
        uint16_t n = RAW - off < BLOCK ? RAW - off : BLOCK;

        z[zn++] = off + n == RAW;
        z[zn++] = n;
        z[zn++] = n >> 8;
        z[zn++] = ~n;
        z[zn++] = (uint16_t)~n >> 8;
        memcpy(&z[zn], &raw[off], n);
        zn += n;
    }
    for (size_t i = 0; i < RAW; i++) {
        a = (a + raw[i]) % 65521;
        b = (b + a) % 65521;
    }
    put32(&z[zn], (b << 16) | a);
    zn += 4;

    put32(ihdr, PANEL_W);
    put32(ihdr + 4, PANEL_H);
    ihdr[8] = 8;
    ihdr[9] = 2;

    f = fopen(path, "wb");
    if (!f) {
        return false;
    }
    ok = fwrite(sig, 1, 8, f) == 8 && chunk(f, "IHDR", ihdr, 13) && chunk(f, "IDAT", z, zn) &&
         chunk(f, "IEND", NULL, 0);
    return fclose(f) == 0 && ok;
}
