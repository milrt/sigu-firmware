// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "drivers/tamper.h"
#include "tfm_log.h"
#include <hal/nrf_glitchdet.h>
#include <hal/nrf_tampc.h>
#include <stddef.h>

// These are on at reset, but not locked, so secure code could turn them off.
// The lock holds until reset.
// The active shield and EXTRESETEN need board routing, so they stay off.
// ERASEPROTECT stays off. ERASEALL wipes RRAM and KMU, so it leaks no secret,
// and with ERASEPROTECT a locked unit could never be recovered.
//
// nrf_tampc.h hides NRF_TAMPC_PROTECT_CRACEN behind an #if on an enum name, which is always false.
// The enum value is the register offset, so we use the offset.
static const nrf_tampc_protect_t locked[] = {
    (nrf_tampc_protect_t)offsetof(NRF_TAMPC_Type, PROTECT.CRACENTAMP),
    NRF_TAMPC_PROTECT_GLITCH_DOMAIN_SLOW,
    NRF_TAMPC_PROTECT_GLITCH_DOMAIN_FAST,
    NRF_TAMPC_PROTECT_RESETEN_INT,
};

void tamper_init(void)
{
    // The define in secure/CMakeLists.txt keeps SystemInit() from turning it off.
    // Turn it on here too, in case an NCS update changes that.
    if (!nrf_glitchdet_enable_check(NRF_GLITCHDET_S)) {
        ERROR("glitch detector was off\n");
        nrf_glitchdet_enable_set(NRF_GLITCHDET_S, true);
    }

    for (size_t i = 0; i < sizeof(locked) / sizeof(locked[0]); i++) {
        nrf_tampc_protector_ctrl_value_set(NRF_TAMPC_S, locked[i], true);
        nrf_tampc_protector_ctrl_lock_set(NRF_TAMPC_S, locked[i], true);
    }

    // No psa_panic(): it halts the chip silently, and a silicon quirk would brick every unit.
    if (!tamper_ok()) {
        ERROR("tamper detectors not locked\n");
    }
}

bool tamper_ok(void)
{
    if (!nrf_glitchdet_enable_check(NRF_GLITCHDET_S)) {
        return false;
    }
    for (size_t i = 0; i < sizeof(locked) / sizeof(locked[0]); i++) {
        if (!nrf_tampc_protector_ctrl_value_get(NRF_TAMPC_S, locked[i]) ||
            !nrf_tampc_protector_ctrl_lock_get(NRF_TAMPC_S, locked[i])) {
            return false;
        }
    }
    return true;
}
