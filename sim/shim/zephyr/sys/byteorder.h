#pragma once

#include <stdint.h>

static inline uint16_t sys_get_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static inline uint32_t sys_get_le32(const uint8_t *p)
{
    return (uint32_t)sys_get_le16(p) | ((uint32_t)sys_get_le16(p + 2) << 16);
}

static inline uint64_t sys_get_le64(const uint8_t *p)
{
    return (uint64_t)sys_get_le32(p) | ((uint64_t)sys_get_le32(p + 4) << 32);
}

static inline void sys_put_le16(uint16_t v, uint8_t *p)
{
    p[0] = v;
    p[1] = v >> 8;
}

static inline void sys_put_le32(uint32_t v, uint8_t *p)
{
    sys_put_le16(v, p);
    sys_put_le16(v >> 16, p + 2);
}

static inline void sys_put_le64(uint64_t v, uint8_t *p)
{
    sys_put_le32(v, p);
    sys_put_le32(v >> 32, p + 4);
}
