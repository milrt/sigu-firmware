// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "drivers/input.h"
#include <hal/nrf_gpio.h>
#include <stdbool.h>

// The back and next keys are secure pins on P1, in CONFIG_NRF_GPIO1_PIN_MASK_SECURE.
// The select key is P0.4, in the GPIO0 mask.
// NS cannot read them, and it cannot drive them to fake a key press.
// That matters for the select key, because it approves a transaction on the review screen.
// Wired active-low with a pull-up.

#define PIN_DEL NRF_GPIO_PIN_MAP(1, 13)
#define PIN_NEXT NRF_GPIO_PIN_MAP(1, 10)
#define PIN_OK NRF_GPIO_PIN_MAP(0, 4)

static uint32_t prev_del = 1;
static uint32_t prev_next = 1;
static uint32_t prev_ok = 1;

static bool pressed(uint32_t pin, uint32_t *prev)
{
    uint32_t now = nrf_gpio_pin_read(pin);
    bool edge = *prev == 1 && now == 0;

    *prev = now;
    return edge;
}

void input_init(void)
{
    nrf_gpio_cfg_input(PIN_DEL, NRF_GPIO_PIN_PULLUP);
    nrf_gpio_cfg_input(PIN_NEXT, NRF_GPIO_PIN_PULLUP);
    nrf_gpio_cfg_input(PIN_OK, NRF_GPIO_PIN_PULLUP);
}

uint32_t input_poll(void)
{
    uint32_t keys = 0;

    if (pressed(PIN_DEL, &prev_del)) {
        keys |= INPUT_DEL;
    }
    if (pressed(PIN_NEXT, &prev_next)) {
        keys |= INPUT_NEXT;
    }
    if (pressed(PIN_OK, &prev_ok)) {
        keys |= INPUT_OK;
    }
    return keys;
}
