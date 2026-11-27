// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "drivers/tick.h"
#include <hal/nrf_timer.h>

// psa_wait() takes only PSA_BLOCK or PSA_POLL, TF-M ignores any other timeout.
// So the tick is TIMER22, which raises TFM_TIMER22_IRQ_SIGNAL.
#define TICK_TIMER NRF_TIMER22
#define TICK_TIMER_HZ 1000000

// The timer runs free and CC0 moves one period ahead on each tick,
// so the counter keeps the real time. CC1 captures it.
static uint32_t period;
static uint32_t last;

static uint32_t now(void)
{
    nrf_timer_task_trigger(TICK_TIMER, NRF_TIMER_TASK_CAPTURE1);
    return nrf_timer_cc_get(TICK_TIMER, NRF_TIMER_CC_CHANNEL1);
}

void tick_start(uint32_t ms)
{
    uint32_t base = NRF_TIMER_BASE_FREQUENCY_GET(TICK_TIMER);

    period = TICK_TIMER_HZ / 1000 * ms;
    last = 0;
    nrf_timer_mode_set(TICK_TIMER, NRF_TIMER_MODE_TIMER);
    nrf_timer_bit_width_set(TICK_TIMER, NRF_TIMER_BIT_WIDTH_32);
    nrf_timer_prescaler_set(TICK_TIMER, NRF_TIMER_PRESCALER_CALCULATE(base, TICK_TIMER_HZ));
    nrf_timer_cc_set(TICK_TIMER, NRF_TIMER_CC_CHANNEL0, period);
    nrf_timer_event_clear(TICK_TIMER, NRF_TIMER_EVENT_COMPARE0);
    nrf_timer_int_enable(TICK_TIMER, NRF_TIMER_INT_COMPARE0_MASK);
    nrf_timer_task_trigger(TICK_TIMER, NRF_TIMER_TASK_CLEAR);
    nrf_timer_task_trigger(TICK_TIMER, NRF_TIMER_TASK_START);
}

// The loop covers a period that ends between the capture and the new CC0.
// Without it that compare would be missed until the counter wraps.
uint32_t tick_ack(void)
{
    uint32_t n = 0;
    uint32_t passed;

    do {
        nrf_timer_event_clear(TICK_TIMER, NRF_TIMER_EVENT_COMPARE0);
        passed = (now() - last) / period;
        n += passed;
        last += passed * period;
        nrf_timer_cc_set(TICK_TIMER, NRF_TIMER_CC_CHANNEL0, last + period);
    } while (now() - last >= period);
    return n ? n : 1;
}
