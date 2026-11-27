// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/config.h"
#include "psa/internal_trusted_storage.h"
#include "shared/wire.h"
#include <stddef.h>

// ITS, not PS: ITS is its own partition, so a broken PS table never reaches the panel config,
// and a config write never touches the seed.
// This partition's ITS UIDs are 0x1002xxxx. PS uses 0x1001xxxx (key_storage.c).
#define CONFIG_UID 0x10020010ULL
#define CONFIG_VERSION 1

// version u8, theme u8, seen u8.
#define CONFIG_SIZE 3

bool config_read(config_t *c)
{
    uint8_t buf[CONFIG_SIZE + 1];
    size_t len = 0;
    wire_r r;
    uint8_t seen;

    if (psa_its_get(CONFIG_UID, 0, sizeof(buf), buf, &len) != PSA_SUCCESS || len != CONFIG_SIZE) {
        return false;
    }
    r = wire_reader(buf, len);
    if (wire_get_u8(&r) != CONFIG_VERSION) {
        return false;
    }
    c->theme = wire_get_u8(&r);
    seen = wire_get_u8(&r);
    c->fw_failed_seen = seen == 1;
    return r.ok && seen <= 1;
}

bool config_write(const config_t *c)
{
    uint8_t buf[CONFIG_SIZE];
    wire_w w = wire_writer(buf, sizeof(buf));

    if (c->theme > UINT8_MAX) {
        return false;
    }
    wire_put_u8(&w, CONFIG_VERSION);
    wire_put_u8(&w, (uint8_t)c->theme);
    wire_put_u8(&w, c->fw_failed_seen ? 1 : 0);
    return w.ok && w.pos == sizeof(buf) &&
           psa_its_set(CONFIG_UID, sizeof(buf), buf, PSA_STORAGE_FLAG_NONE) == PSA_SUCCESS;
}

bool config_remove(void)
{
    psa_status_t status = psa_its_remove(CONFIG_UID);

    return status == PSA_SUCCESS || status == PSA_ERROR_DOES_NOT_EXIST;
}
