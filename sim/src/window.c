// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The device in an SDL window: the panel, and the three keys under it.
// Click or tap a key, or press A, S or D for the left, middle or right one.
// C takes the SD card out or puts it in.
// On the desktop, W wipes the wallet and closes the sim. The web page has its own R and W.

#include "drivers/input.h"
#include "drivers/panel.h"
#include "sim.h"
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>

// Sizes at zoom 1. Zoom 1 shows each panel pixel as one screen pixel.
#define PAD 10
#define KEY_H 36
#define KEY_R 13
#define FLASH_MS 120

// Left to right. The firmware gives each key its role on the screen, so the sim shows none.
static const struct {
    uint32_t bit;
    SDL_Keycode sym;
} keys[3] = {
    {INPUT_DEL, SDLK_a},
    {INPUT_NEXT, SDLK_s},
    {INPUT_OK, SDLK_d},
};

static SDL_Point key_center(int i, int scale)
{
    int w = PANEL_W / 3;

    return (SDL_Point){(PAD + w * i + w / 2) * scale, (PAD * 2 + PANEL_H + KEY_H / 2) * scale};
}

static void fill_circle(SDL_Renderer *r, SDL_Point c, int rad)
{
    int dx = rad;

    for (int dy = 0; dy <= rad; dy++) {
        while (dx * dx + dy * dy > rad * rad) {
            dx--;
        }
        SDL_RenderDrawLine(r, c.x - dx, c.y - dy, c.x + dx, c.y - dy);
        SDL_RenderDrawLine(r, c.x - dx, c.y + dy, c.x + dx, c.y + dy);
    }
}

// A round push button: a dark rim and a cap. Pressed, the cap sinks and darkens.
static void draw_key(SDL_Renderer *r, SDL_Point c, bool pressed, int z)
{
    SDL_SetRenderDrawColor(r, 0x0E, 0x0F, 0x11, 0xFF);
    fill_circle(r, c, (KEY_R + 2) * z);
    if (pressed) {
        SDL_SetRenderDrawColor(r, 0x2C, 0x2E, 0x33, 0xFF);
        fill_circle(r, c, (KEY_R - 1) * z);
        return;
    }
    SDL_SetRenderDrawColor(r, 0x4A, 0x4D, 0x54, 0xFF);
    fill_circle(r, c, KEY_R * z);
    SDL_SetRenderDrawColor(r, 0x3B, 0x3E, 0x44, 0xFF);
    fill_circle(r, (SDL_Point){c.x, c.y + z}, (KEY_R - 2) * z);
}

static uint32_t key_from_sdl(SDL_Keycode k)
{
    for (int i = 0; i < 3; i++) {
        if (keys[i].sym == k) {
            return keys[i].bit;
        }
    }
    return 0;
}

static int scale;
static SDL_Window *win;
static SDL_Renderer *ren;
static SDL_Texture *tex;
static uint32_t flash_until[3];
static uint32_t seen;

bool sim_window_open(int zoom)
{
    int w = (PANEL_W + 2 * PAD) * zoom;
    int h = (PANEL_H + 3 * PAD + KEY_H) * zoom;

    scale = zoom;
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        fprintf(stderr, "[SIM] SDL_Init: %s\n", SDL_GetError());
        return false;
    }
    win = SDL_CreateWindow("sigu simulator", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, w, h,
                           SDL_WINDOW_ALLOW_HIGHDPI);
    ren = SDL_CreateRenderer(win, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!win || !ren) {
        fprintf(stderr, "[SIM] SDL window: %s\n", SDL_GetError());
        return false;
    }
    SDL_RenderSetLogicalSize(ren, w, h);
    tex = SDL_CreateTexture(ren, SDL_PIXELFORMAT_RGB565, SDL_TEXTUREACCESS_STREAMING, PANEL_W,
                            PANEL_H);
    SDL_SetTextureScaleMode(tex, SDL_ScaleModeNearest);
    return true;
}

static void press(uint32_t bit, uint32_t now)
{
    sim_input_press(bit);
    for (int i = 0; i < 3; i++) {
        if (keys[i].bit == bit) {
            flash_until[i] = now + FLASH_MS;
        }
    }
}

// Returns false once the window was closed.
static bool events(uint32_t now)
{
    SDL_Event e;

    while (SDL_PollEvent(&e)) {
        if (e.type == SDL_QUIT || (e.type == SDL_KEYDOWN && e.key.keysym.sym == SDLK_q &&
                                   (e.key.keysym.mod & KMOD_GUI))) {
            return false;
        }
        if (e.type == SDL_KEYDOWN && !e.key.repeat && e.key.keysym.sym == SDLK_c) {
            sim_card_set(!sim_card_in());
        }
        if (e.type == SDL_KEYDOWN && !e.key.repeat && key_from_sdl(e.key.keysym.sym)) {
            press(key_from_sdl(e.key.keysym.sym), now);
        }
        // The whole strip under the panel is the keys, one third each.
        // A finger is wider than the drawn key.
        if (e.type == SDL_MOUSEBUTTONDOWN && e.button.button == SDL_BUTTON_LEFT &&
            e.button.y >= (PAD + PANEL_H) * scale) {
            int i = (e.button.x / scale - PAD) * 3 / PANEL_W;

            press(keys[i < 0 ? 0 : i > 2 ? 2 : i].bit, now);
        }
    }
    return true;
}

bool sim_window_frame(void)
{
    static uint16_t px[PANEL_W * PANEL_H];
    uint32_t now = SDL_GetTicks();
    SDL_Rect panel = {PAD * scale, PAD * scale, PANEL_W * scale, PANEL_H * scale};
    uint8_t light;
    bool blank;
    uint32_t n;

    if (!events(now)) {
        SDL_Quit();
        return false;
    }

    n = sim_panel_read(px, &light, &blank);
    if (n != seen) {
        SDL_UpdateTexture(tex, NULL, px, PANEL_W * sizeof(px[0]));
        seen = n;
    }
    // Keep a dim panel readable on a monitor. 12% would be too dark to see.
    uint8_t v = blank ? 0 : 70 + light * 185 / 100;
    SDL_SetTextureColorMod(tex, v, v, v);

    SDL_SetRenderDrawColor(ren, 0x1E, 0x1F, 0x22, 0xFF);
    SDL_RenderClear(ren);
    SDL_SetRenderDrawColor(ren, 0, 0, 0, 0xFF);
    SDL_RenderFillRect(ren, &panel);
    if (!blank) {
        SDL_RenderCopy(ren, tex, NULL, &panel);
    }
    for (int i = 0; i < 3; i++) {
        draw_key(ren, key_center(i, scale), now < flash_until[i], scale);
    }
    SDL_RenderPresent(ren);
    return true;
}
