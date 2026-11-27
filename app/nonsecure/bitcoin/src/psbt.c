// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/psbt.h"
#include "bitcoin/psbt_tx.h"
#include "psbt_compactsize.h"
#include "psbt_heap.h"
#include <string.h>

// "psbt" and 0xFF, BIP174.
#define PSBT_MAGIC "\x70\x73\x62\x74\xFF"
#define PSBT_MAGIC_SIZE 5

static void free_kv(psbt_kv_t *kv)
{
    k_heap_free(&psbt_heap, kv->key_data);
    k_heap_free(&psbt_heap, kv->value_data);
    k_heap_free(&psbt_heap, kv);
}

static void free_map(psbt_map_t *map)
{
    psbt_kv_t *kv, *tmp;
    SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&map->kv_list, kv, tmp, node)
    {
        sys_slist_remove(&map->kv_list, NULL, &kv->node);
        free_kv(kv);
    }
}

static void free_maps(psbt_map_t **maps, size_t *num)
{
    if (*maps) {
        for (size_t i = 0; i < *num; i++) {
            free_map(&(*maps)[i]);
        }
        k_heap_free(&psbt_heap, *maps);
        *maps = NULL;
        *num = 0;
    }
}

void psbt_free(psbt_t *psbt)
{
    free_map(&psbt->global);
    free_maps(&psbt->inputs, &psbt->num_inputs);
    free_maps(&psbt->outputs, &psbt->num_outputs);
}

psbt_kv_t *psbt_find_kv(psbt_map_t *map, uint8_t key_type)
{
    psbt_kv_t *kv;
    SYS_SLIST_FOR_EACH_CONTAINER(&map->kv_list, kv, node)
    {
        if (kv->key_type == key_type) {
            return kv;
        }
    }
    return NULL;
}

// Reads records into `map`, up to and with its 0x00 separator. BIP174 ends every map with one.
// The end of the data is not one, or a cut PSBT would parse with empty maps after the cut.
static psbt_result_t parse_map(const uint8_t **data_ptr, size_t *remaining_ptr, psbt_map_t *map)
{
    for (;;) {
        const uint8_t *key;
        const uint8_t *value;
        size_t key_len;
        size_t value_len;

        if (!compactsize_read_bytes(data_ptr, remaining_ptr, &key, &key_len)) {
            return PSBT_READ_ERROR;
        }
        if (key_len == 0) {
            break;
        }
        if (!compactsize_read_bytes(data_ptr, remaining_ptr, &value, &value_len)) {
            return PSBT_READ_ERROR;
        }

        psbt_kv_t *kv = k_heap_alloc(&psbt_heap, sizeof(*kv), K_NO_WAIT);
        if (!kv) {
            return PSBT_OOB_WRITE;
        }

        kv->key_type = key[0];
        kv->key_data_len = key_len - 1;
        if (kv->key_data_len) {
            kv->key_data = k_heap_alloc(&psbt_heap, kv->key_data_len, K_NO_WAIT);
            if (!kv->key_data) {
                k_heap_free(&psbt_heap, kv);
                return PSBT_OOB_WRITE;
            }
            memcpy(kv->key_data, key + 1, kv->key_data_len);
        } else {
            kv->key_data = NULL;
        }

        kv->value_data_len = value_len;
        kv->value_data = k_heap_alloc(&psbt_heap, value_len, K_NO_WAIT);
        if (!kv->value_data) {
            k_heap_free(&psbt_heap, kv->key_data);
            k_heap_free(&psbt_heap, kv);
            return PSBT_OOB_WRITE;
        }
        memcpy(kv->value_data, value, value_len);

        sys_slist_append(&map->kv_list, &kv->node);
    }

    return PSBT_OK;
}

// Allocates `n` maps and parses them.
// All of them are empty before the first parse,
// because psbt_free() walks every map, also the ones after a parse error.
static psbt_result_t parse_maps(const uint8_t **data_ptr, size_t *remaining_ptr, psbt_map_t **maps,
                                size_t n)
{
    *maps = k_heap_alloc(&psbt_heap, n * sizeof(psbt_map_t), K_NO_WAIT);
    if (!*maps) {
        return PSBT_OOB_WRITE;
    }
    for (size_t i = 0; i < n; i++) {
        sys_slist_init(&(*maps)[i].kv_list);
    }
    for (size_t i = 0; i < n; i++) {
        psbt_result_t res = parse_map(data_ptr, remaining_ptr, &(*maps)[i]);
        if (res != PSBT_OK) {
            return res;
        }
    }
    return PSBT_OK;
}

psbt_result_t psbt_create_from_bin(psbt_t *psbt, const uint8_t *data, size_t data_len)
{
    psbt_tx_t tx;

    sys_slist_init(&psbt->global.kv_list);
    psbt->inputs = psbt->outputs = NULL;
    psbt->num_inputs = psbt->num_outputs = 0;

    if (data_len < PSBT_MAGIC_SIZE || memcmp(data, PSBT_MAGIC, PSBT_MAGIC_SIZE) != 0) {
        return PSBT_READ_ERROR;
    }
    const uint8_t *cur = data + PSBT_MAGIC_SIZE;
    size_t rem = data_len - PSBT_MAGIC_SIZE;

    psbt_result_t res = parse_map(&cur, &rem, &psbt->global);
    if (res == PSBT_OK) {
        psbt_kv_t *unsigned_tx = psbt_find_kv(&psbt->global, PSBT_GLOBAL_UNSIGNED_TX);

        res = unsigned_tx ? psbt_tx_create_from_bin(&tx, unsigned_tx->value_data,
                                                    unsigned_tx->value_data_len)
                          : PSBT_READ_ERROR;
    }
    if (res == PSBT_OK) {
        psbt->num_inputs = tx.num_inputs;
        psbt->num_outputs = tx.num_outputs;
        psbt_tx_free(&tx);
        res = parse_maps(&cur, &rem, &psbt->inputs, psbt->num_inputs);
    }
    if (res == PSBT_OK) {
        res = parse_maps(&cur, &rem, &psbt->outputs, psbt->num_outputs);
    }
    if (res == PSBT_OK && rem != 0) {
        res = PSBT_READ_ERROR;
    }
    if (res != PSBT_OK) {
        psbt_free(psbt);
    }
    return res;
}

static bool write_bytes(uint8_t **dest_ptr, size_t *remaining_ptr, const void *src, size_t len)
{
    if (*remaining_ptr < len) {
        return false;
    }
    if (len) {
        memcpy(*dest_ptr, src, len);
    }
    *dest_ptr += len;
    *remaining_ptr -= len;
    return true;
}

// Each record, then the 0x00 separator.
// The key is written in place, with no heap,
// so a PSBT that fills psbt_heap after the signatures were added still writes.
static bool write_map(psbt_map_t *map, uint8_t **dest_ptr, size_t *remaining_ptr)
{
    static const uint8_t separator = 0x00;
    psbt_kv_t *kv;

    SYS_SLIST_FOR_EACH_CONTAINER(&map->kv_list, kv, node)
    {
        if (!compactsize_write(dest_ptr, remaining_ptr, 1 + kv->key_data_len) ||
            !write_bytes(dest_ptr, remaining_ptr, &kv->key_type, 1) ||
            !write_bytes(dest_ptr, remaining_ptr, kv->key_data, kv->key_data_len) ||
            !compactsize_write_bytes(dest_ptr, remaining_ptr, kv->value_data, kv->value_data_len)) {
            return false;
        }
    }
    return write_bytes(dest_ptr, remaining_ptr, &separator, 1);
}

psbt_result_t psbt_to_bin(psbt_t *psbt, uint8_t *out_buf, size_t *out_len)
{
    uint8_t *dest = out_buf;
    size_t remaining = *out_len;
    bool ok = write_bytes(&dest, &remaining, PSBT_MAGIC, PSBT_MAGIC_SIZE) &&
              write_map(&psbt->global, &dest, &remaining);

    for (size_t i = 0; ok && i < psbt->num_inputs; i++) {
        ok = write_map(&psbt->inputs[i], &dest, &remaining);
    }
    for (size_t i = 0; ok && i < psbt->num_outputs; i++) {
        ok = write_map(&psbt->outputs[i], &dest, &remaining);
    }
    if (!ok) {
        return PSBT_OOB_WRITE;
    }
    *out_len = dest - out_buf;
    return PSBT_OK;
}
