// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "panel_hw.h"
#include <hal/nrf_gpio.h>
#include <hal/nrf_pwm.h>
#include <hal/nrf_spim.h>
#include <stddef.h>
#include <string.h>

// The ST7789V on SPIM22 (8 MHz, mode 0, MSB first, write-only) and the backlight on PWM21 (1 kHz).
//
// The panel is an Adafruit 1.3" 240x240 Wide Angle TFT. Gamma, VCOM and VRH are panel dependent.
// Adafruit's driver writes none of them, so init_seq holds the ST7789V reset defaults.
// VDVVRHEN, VRH and VDV are not sent, so VRH and VDV stay at reset.
// RAMCTRL 00 f0 leaves the ENDIAN bit clear, so the panel reads each pixel MSB first.
// That is why panel.c swaps the band, and this file sends the bytes as they are.

// SPIM22, not SPIM21. Only SPIM20/21 can reach P2, and the NS SD card needs SPIM21 there.
#define SPIM NRF_SPIM22
// SPIM22 runs from 16 MHz, so a divisor of 2 gives 8 MHz.
#define SPIM_PRESCALER 2
// DMA.TX.MAXCNT is 16 bits on the nRF54L.
#define SPIM_MAX_TX 0xffff

#define PIN_RESET NRF_GPIO_PIN_MAP(1, 7)
#define PIN_CS NRF_GPIO_PIN_MAP(1, 8)
#define PIN_DC NRF_GPIO_PIN_MAP(1, 9)
#define PIN_SCK NRF_GPIO_PIN_MAP(1, 11)
#define PIN_MOSI NRF_GPIO_PIN_MAP(1, 12)
#define PIN_BL NRF_GPIO_PIN_MAP(1, 14)

#define BL_PWM NRF_PWM21
// A 1 MHz PWM clock and a top of 1000 give 1 kHz.
#define BL_TOP 1000
// Bit 15 of a sequence value sets the polarity.
// When it is set, the output starts high and falls at the compare value. That is normal polarity.
#define BL_FALLING_EDGE 0x8000

#define CMD_SLPOUT 0x11
#define CMD_DISPOFF 0x28
#define CMD_DISPON 0x29
#define CMD_CASET 0x2a
#define CMD_RASET 0x2b
#define CMD_RAMWR 0x2c
#define CMD_SWRESET 0x01
#define CMD_GAMSET 0x26

#define PARAM_MAX 14

// Each entry is: command, parameter count, parameters.
static const uint8_t init_seq[] = {
    0x28, 0,                                // DISPOFF
    0xdf, 4,  0x5a, 0x69, 0x02, 0x01,       // CMD2EN
    0xb2, 5,  0x0c, 0x0c, 0x00, 0x33, 0x33, // PORCTRL
    0xba, 1,  0x00,                         // DGMEN
    0xc6, 1,  0x0f,                         // FRCTRL2
    0xb7, 1,  0x35,                         // GCTRL
    0xbb, 1,  0x20,                         // VCOMS
    0xd0, 2,  0xa4, 0xa1,                   // PWCTRL1
    0x36, 1,  0x00,                         // MADCTL
    0x3a, 1,  0x55,                         // COLMOD
    0xc0, 1,  0x2c,                         // LCMCTRL
    0x26, 1,  0x01,                         // GAMSET
    0x21, 0,                                // INVON
    0xe0, 14, 0xd0, 0x00, 0x02, 0x07, 0x0a, 0x28, 0x32, 0x44, 0x42, 0x06, 0x0e, 0x12, 0x14,
    0x17, // PVGAMCTRL
    0xe1, 14, 0xd0, 0x00, 0x02, 0x07, 0x0a, 0x28, 0x31, 0x54, 0x47, 0x0e, 0x1c, 0x17, 0x1b,
    0x1e,                       // NVGAMCTRL
    0xb0, 2,  0x00, 0xf0,       // RAMCTRL
    0xb1, 3,  0xcd, 0x08, 0x14, // RGBCTRL
};

// EasyDMA reads the PWM sequence, so it must be in RAM.
static uint16_t bl_value;

// The level is set before the pin turns into an output, so it never glitches low.
static void pin_out_high(uint32_t p)
{
    nrf_gpio_pin_set(p);
    nrf_gpio_cfg_output(p);
}

static void delay_ms(uint32_t ms)
{
    NRFX_DELAY_US(ms * 1000);
}

// SCK keeps its input buffer connected, as the SPIM needs for its clock.
static void spi_init(void)
{
    nrf_gpio_pin_clear(PIN_SCK);
    nrf_gpio_cfg(PIN_SCK, NRF_GPIO_PIN_DIR_OUTPUT, NRF_GPIO_PIN_INPUT_CONNECT, NRF_GPIO_PIN_NOPULL,
                 NRF_GPIO_PIN_S0S1, NRF_GPIO_PIN_NOSENSE);
    nrf_gpio_pin_clear(PIN_MOSI);
    nrf_gpio_cfg_output(PIN_MOSI);

    nrf_spim_pins_set(SPIM, PIN_SCK, PIN_MOSI, NRF_SPIM_PIN_NOT_CONNECTED);
    nrf_spim_prescaler_set(SPIM, SPIM_PRESCALER);
    nrf_spim_configure(SPIM, NRF_SPIM_MODE_0, NRF_SPIM_BIT_ORDER_MSB_FIRST);
    nrf_spim_rx_buffer_set(SPIM, NULL, 0);
    nrf_spim_enable(SPIM);
}

// The pin is driven low until the first playback, so the light stays off.
static void bl_init(void)
{
    uint32_t pins[NRF_PWM_CHANNEL_COUNT] = {PIN_BL, NRF_PWM_PIN_NOT_CONNECTED,
                                            NRF_PWM_PIN_NOT_CONNECTED, NRF_PWM_PIN_NOT_CONNECTED};

    nrf_gpio_pin_clear(PIN_BL);
    nrf_gpio_cfg_output(PIN_BL);

    nrf_pwm_pins_set(BL_PWM, pins);
    nrf_pwm_configure(BL_PWM, NRF_PWM_CLK_1MHz, NRF_PWM_MODE_UP, BL_TOP);
    nrf_pwm_decoder_set(BL_PWM, NRF_PWM_LOAD_COMMON, NRF_PWM_STEP_AUTO);
    nrf_pwm_seq_ptr_set(BL_PWM, 0, &bl_value);
    nrf_pwm_seq_cnt_set(BL_PWM, 0, 1);
    nrf_pwm_seq_refresh_set(BL_PWM, 0, 0);
    nrf_pwm_seq_end_delay_set(BL_PWM, 0, 0);
    nrf_pwm_loop_set(BL_PWM, 0);
    nrf_pwm_shorts_set(BL_PWM, 0);
    nrf_pwm_enable(BL_PWM);
}

// `buf` must be in RAM.
static void spi_tx(const uint8_t *buf, size_t len)
{
    // One EasyDMA transfer per chunk, polled on EVENTS_END.
    while (len) {
        size_t n = len < SPIM_MAX_TX ? len : SPIM_MAX_TX;

        nrf_spim_tx_buffer_set(SPIM, buf, n);
        nrf_spim_event_clear(SPIM, NRF_SPIM_EVENT_END);
        nrf_spim_task_trigger(SPIM, NRF_SPIM_TASK_START);
        while (!nrf_spim_event_check(SPIM, NRF_SPIM_EVENT_END)) {
        }
        buf += n;
        len -= n;
    }
}

// DC is low for the command byte and high for its parameters. CS stays low for both.
// `data` must be in RAM.
static void send(uint8_t c, const void *data, size_t len)
{
    nrf_gpio_pin_clear(PIN_CS);
    nrf_gpio_pin_clear(PIN_DC);
    spi_tx(&c, 1);
    if (len) {
        nrf_gpio_pin_set(PIN_DC);
        spi_tx(data, len);
    }
    nrf_gpio_pin_set(PIN_CS);
}

// EasyDMA cannot read RRAM, so the parameters from init_seq are copied to the stack first.
static void cmd(uint8_t c, const uint8_t *p, size_t n)
{
    uint8_t buf[PARAM_MAX];

    memcpy(buf, p, n);
    send(c, buf, n);
}

static void set_range(uint8_t c, uint16_t start, uint16_t n)
{
    uint16_t end = start + n - 1;
    uint8_t p[4] = {start >> 8, start & 0xff, end >> 8, end & 0xff};

    send(c, p, sizeof(p));
}

void panel_hw_init(void)
{
    bl_init();
    pin_out_high(PIN_CS);
    pin_out_high(PIN_DC);
    pin_out_high(PIN_RESET);
    spi_init();

    delay_ms(120);

    nrf_gpio_pin_clear(PIN_RESET);
    delay_ms(10);
    nrf_gpio_pin_set(PIN_RESET);
    delay_ms(120);

    // Software reset is required for a reliable cold start on this panel.
    send(CMD_SWRESET, NULL, 0);
    delay_ms(150);

    for (size_t i = 0; i < sizeof(init_seq); i += 2 + init_seq[i + 1]) {
        cmd(init_seq[i], &init_seq[i + 2], init_seq[i + 1]);
    }

    send(CMD_SLPOUT, NULL, 0);
    delay_ms(120);
}

void panel_hw_write_window(uint16_t x, uint16_t y, uint16_t w, uint16_t h, const uint16_t *pixels)
{
    set_range(CMD_CASET, x, w);
    set_range(CMD_RASET, y, h);
    send(CMD_RAMWR, pixels, (size_t)w * h * sizeof(*pixels));
}

void panel_hw_blank(bool on)
{
    send(on ? CMD_DISPOFF : CMD_DISPON, NULL, 0);
}

void panel_hw_gamma(uint8_t curve)
{
    uint8_t p = 1u << (curve & 3);

    send(CMD_GAMSET, &p, 1);
}

// Compare 0 is always off, and compare BL_TOP is always on.
// One playback is enough, because the PWM keeps the last value until the next playback.
void panel_hw_backlight(uint8_t percent)
{
    if (percent > 100) {
        percent = 100;
    }
    bl_value = (BL_TOP * percent / 100) | BL_FALLING_EDGE;
    nrf_pwm_task_trigger(BL_PWM, NRF_PWM_TASK_SEQSTART0);
}
