// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "drivers/panel.h"
#include "panel_hw.h"
#include "shared/mem_util.h"
#include <string.h>

// There is no full framebuffer. 240x240 RGB565 is 115 KB, more than the TF-M SRAM partition has.
// The draw calls are recorded, and the flush replays them into one band at a time.
//
// A band is sent only if its ops differ from the frame the panel shows.
// The ops are compared, not a hash of the pixels.
// The PSBT author picks the address, so they could pick one whose band hashes like the last one,
// and the old address would stay on screen.

#define BAND_H 24
#define OPS_MAX 40
#define TEXT_MAX 512

#define OVERFLOW_BG RGB565(0xE33124)

// Color calibration, fixed at build time.
// Saturation and contrast are percent, 100 leaves the colors as drawn.
// Gamma picks an ST7789 GAMSET curve: 0 is 2.2, 1 is 1.8, 2 is 2.5, 3 is 1.0.
#define CAL_SAT 100
#define CAL_CON 100
#define CAL_GAMMA 0

enum op_kind {
    OP_RECT,
    OP_TEXT,
    OP_MONO,
};

struct op {
    uint8_t kind;
    int16_t x;
    int16_t y;
    int16_t w;
    int16_t h;
    uint16_t color;
    // OP_MONO: the scale.
    uint16_t scale;
    // OP_TEXT: offset in `text`. OP_MONO: offset in `mono`.
    uint16_t text;
    const font_t *font;
};

struct frame {
    struct op ops[OPS_MAX];
    char text[TEXT_MAX];
    uint8_t mono[PANEL_MONO_MAX];
    size_t nops;
    size_t text_len;
    size_t mono_len;
    uint16_t bg;
    // A draw call did not fit. The frame shows as all alert, never with text missing.
    bool overflow;
};

static uint16_t band[PANEL_W * BAND_H];
static struct frame cur;
static struct frame sent;
static bool sent_valid;
static bool dirty;

void panel_init(void)
{
    panel_hw_init();
    panel_hw_blank(false);
    panel_hw_gamma(CAL_GAMMA);
    sent_valid = false;
}

// The text pool may hold seed words, so the old frame is wiped, not only reset.
void panel_clear(uint16_t color)
{
    mem_zeroize(&cur, sizeof(cur));
    cur.bg = color;
    dirty = true;
}

static struct op *add_op(enum op_kind kind, int x, int y, int w, int h)
{
    struct op *o;

    if (cur.nops == OPS_MAX) {
        cur.overflow = true;
        return NULL;
    }

    o = &cur.ops[cur.nops++];
    o->kind = kind;
    o->x = x;
    o->y = y;
    o->w = w;
    o->h = h;
    dirty = true;
    return o;
}

void panel_fill_rect(int x, int y, int w, int h, uint16_t color)
{
    struct op *o = add_op(OP_RECT, x, y, w, h);

    if (o) {
        o->color = color;
    }
}

// The caller's text is often on its stack, so it is copied.
static void add_text(int x, int y, const char *s, size_t n, const font_t *f, uint16_t fg)
{
    struct op *o;

    if (n == 0) {
        return;
    }
    if (cur.text_len + n + 1 > TEXT_MAX) {
        cur.overflow = true;
        return;
    }

    o = add_op(OP_TEXT, x, y, 0, f->line_height);
    if (!o) {
        return;
    }
    o->color = fg;
    o->font = f;
    o->text = cur.text_len;
    memcpy(&cur.text[cur.text_len], s, n);
    cur.text_len += n + 1;
}

// The bits are copied, like text, so the frame on the panel can be compared byte for byte.
void panel_draw_mono(int x, int y, const uint8_t *bits, int w, int h, int scale, uint16_t fg)
{
    size_t n = ((size_t)w * h + 7) / 8;
    struct op *o;

    if (w <= 0 || h <= 0 || scale <= 0) {
        return;
    }
    if (cur.mono_len + n > PANEL_MONO_MAX) {
        cur.overflow = true;
        return;
    }

    o = add_op(OP_MONO, x, y, w * scale, h * scale);
    if (!o) {
        return;
    }
    o->color = fg;
    o->scale = scale;
    o->text = cur.mono_len;
    memcpy(&cur.mono[cur.mono_len], bits, n);
    cur.mono_len += n;
}

void panel_draw_text(int x, int y, const char *s, const font_t *f, uint16_t fg)
{
    add_text(x, y, s, strlen(s), f, fg);
}

static int glyph_id(char c)
{
    unsigned char u = c;

    if (u < FONT_FIRST || u >= FONT_FIRST + FONT_GLYPHS) {
        return -1;
    }
    return u - FONT_FIRST;
}

// The advance in whole pixels, rounded, with the kerning against the next letter.
static int advance(const font_t *f, int g, int next)
{
    int adv = f->glyph[g].adv;

    if (next >= 0) {
        uint8_t l = f->kern_left[g];
        uint8_t r = f->kern_right[next];

        if (l && r) {
            adv += f->kern[(l - 1) * f->kern_right_n + (r - 1)];
        }
    }
    return (adv + 8) >> 4;
}

int panel_text_width(const char *s, const font_t *f)
{
    int w = 0;

    for (; *s; s++) {
        int g = glyph_id(*s);

        if (g >= 0) {
            w += advance(f, g, glyph_id(s[1]));
        }
    }
    return w;
}

// How many chars of `s` fit on a line of `w` px: up to the last space that fits,
// else inside the word, and at least one char.
// Addresses have no spaces, and their end is what makes them that address,
// so they wrap and are never cut.
static size_t line_fit(const char *s, int w, const font_t *f)
{
    size_t space = 0;
    int x = 0;
    size_t i;

    for (i = 0; s[i]; i++) {
        int g = glyph_id(s[i]);

        if (s[i] == ' ') {
            space = i;
        }
        if (g >= 0) {
            x += advance(f, g, glyph_id(s[i + 1]));
        }
        if (x > w) {
            if (space) {
                return space;
            }
            return i ? i : 1;
        }
    }
    return i;
}

int panel_draw_text_wrapped(int x, int y, int w, const char *s, const font_t *f, uint16_t fg)
{
    int h = 0;

    do {
        size_t n = line_fit(s, w, f);

        add_text(x, y + h, s, n, f, fg);
        s += n;
        while (*s == ' ') {
            s++;
        }
        h += f->line_height;
    } while (*s);
    return h;
}

static uint16_t *at(int x, int y, int y0)
{
    if (x < 0 || x >= PANEL_W || y < y0 || y >= y0 + BAND_H) {
        return NULL;
    }
    return &band[(y - y0) * PANEL_W + x];
}

// RGB565 alpha blend for anti-aliased text. The alpha is rounded to steps of 1/32.
static uint16_t mix(uint16_t fg, uint16_t bg, uint8_t a)
{
    uint32_t f;
    uint32_t b;
    uint32_t r;

    if (a == 255) {
        return fg;
    }
    if (a == 0 || fg == bg) {
        return bg;
    }

    a = (a + 4) >> 3;
    f = (fg | ((uint32_t)fg << 16)) & 0x07E0F81F;
    b = (bg | ((uint32_t)bg << 16)) & 0x07E0F81F;
    r = ((((f - b) * a) >> 5) + b) & 0x07E0F81F;
    return (uint16_t)((r >> 16) | r);
}

static int clamp8(int v)
{
    return v < 0 ? 0 : v > 255 ? 255 : v;
}

// Saturation around the luma, then contrast around mid gray, in 8 bits.
// At 100 and 100 this returns `c` unchanged.
static uint16_t cal(uint16_t c)
{
    int r5 = c >> 11;
    int g6 = (c >> 5) & 0x3F;
    int b5 = c & 0x1F;
    int rgb[3] = {(r5 << 3) | (r5 >> 2), (g6 << 2) | (g6 >> 4), (b5 << 3) | (b5 >> 2)};
    int y = (77 * rgb[0] + 150 * rgb[1] + 29 * rgb[2]) >> 8;

    for (int i = 0; i < 3; i++) {
        int v = y + (rgb[i] - y) * CAL_SAT / 100;

        rgb[i] = clamp8((v - 128) * CAL_CON / 100 + 128);
    }
    return (uint16_t)(((rgb[0] >> 3) << 11) | ((rgb[1] >> 2) << 5) | (rgb[2] >> 3));
}

static void draw_rect(const struct op *o, int y0)
{
    uint16_t c = cal(o->color);

    for (int y = o->y; y < o->y + o->h; y++) {
        for (int x = o->x; x < o->x + o->w; x++) {
            uint16_t *p = at(x, y, y0);

            if (p) {
                *p = c;
            }
        }
    }
}

static void draw_glyph(const font_t *f, const font_glyph_t *g, int x, int y, uint16_t fg, int y0)
{
    for (int r = 0; r < g->h; r++) {
        for (int c = 0; c < g->w; c++) {
            uint32_t k = (uint32_t)r * g->w + c;
            uint8_t byte = f->bitmap[g->bitmap + k / 2];
            uint8_t a = (k & 1) ? byte & 0x0F : byte >> 4;
            uint16_t *p = at(x + c, y + r, y0);

            if (p && a) {
                *p = mix(fg, *p, a * 17);
            }
        }
    }
}

static void draw_mono(const struct op *o, int y0)
{
    const uint8_t *bits = &cur.mono[o->text];
    int scale = o->scale;
    int w = o->w / scale;
    uint16_t fg = cal(o->color);

    for (int y = o->y; y < o->y + o->h; y++) {
        for (int x = o->x; x < o->x + o->w; x++) {
            uint32_t i = (uint32_t)((y - o->y) / scale) * w + (x - o->x) / scale;
            uint16_t *p = at(x, y, y0);

            if (p && ((bits[i >> 3] >> (i & 7)) & 1)) {
                *p = fg;
            }
        }
    }
}

// The glyph box hangs from the baseline by its own offset.
static void draw_text(const struct op *o, const char *s, int y0)
{
    const font_t *f = o->font;
    int base = o->y + f->line_height - f->base_line;
    int pen = o->x;
    uint16_t fg = cal(o->color);

    for (; *s; s++) {
        int g = glyph_id(*s);
        const font_glyph_t *gl;

        if (g < 0) {
            continue;
        }
        gl = &f->glyph[g];
        draw_glyph(f, gl, pen + gl->x, base - gl->h - gl->y, fg, y0);
        pen += advance(f, g, glyph_id(s[1]));
    }
}

static bool hits(const struct op *o, int y0)
{
    return o->y < y0 + BAND_H && o->y + o->h > y0;
}

static void render(int y0)
{
    uint16_t bg = cal(cur.overflow ? OVERFLOW_BG : cur.bg);

    for (size_t i = 0; i < PANEL_W * BAND_H; i++) {
        band[i] = bg;
    }
    if (cur.overflow) {
        return;
    }

    for (size_t i = 0; i < cur.nops; i++) {
        const struct op *o = &cur.ops[i];

        if (!hits(o, y0)) {
            continue;
        }
        if (o->kind == OP_TEXT) {
            draw_text(o, &cur.text[o->text], y0);
        } else if (o->kind == OP_MONO) {
            draw_mono(o, y0);
        } else {
            draw_rect(o, y0);
        }
    }
}

static bool same_op(const struct op *a, const struct op *b)
{
    if (a->kind != b->kind || a->x != b->x || a->y != b->y || a->w != b->w || a->h != b->h ||
        a->color != b->color || a->scale != b->scale || a->font != b->font) {
        return false;
    }
    if (a->kind == OP_MONO) {
        size_t n = ((size_t)(a->w / a->scale) * (a->h / a->scale) + 7) / 8;

        return memcmp(&cur.mono[a->text], &sent.mono[b->text], n) == 0;
    }
    return a->kind != OP_TEXT || strcmp(&cur.text[a->text], &sent.text[b->text]) == 0;
}

// True if the band at y0 has the same ops, in the same order, as the frame on the panel.
static bool band_same(int y0)
{
    size_t i = 0;
    size_t j = 0;

    if (!sent_valid || cur.overflow || sent.overflow || cur.bg != sent.bg) {
        return false;
    }

    for (;;) {
        while (i < cur.nops && !hits(&cur.ops[i], y0)) {
            i++;
        }
        while (j < sent.nops && !hits(&sent.ops[j], y0)) {
            j++;
        }
        if (i == cur.nops || j == sent.nops) {
            return i == cur.nops && j == sent.nops;
        }
        if (!same_op(&cur.ops[i], &sent.ops[j])) {
            return false;
        }
        i++;
        j++;
    }
}

static void swap_band(void)
{
    for (size_t i = 0; i < PANEL_W * BAND_H; i++) {
        band[i] = __builtin_bswap16(band[i]);
    }
}

void panel_flush(void)
{
    if (!dirty) {
        return;
    }
    dirty = false;

    for (int y0 = 0; y0 < PANEL_H; y0 += BAND_H) {
        if (band_same(y0)) {
            continue;
        }
        render(y0);
        swap_band();
        panel_hw_write_window(0, y0, PANEL_W, BAND_H, band);
    }

    sent = cur;
    sent_valid = true;
}

void panel_backlight(uint8_t percent)
{
    panel_hw_backlight(percent);
}
