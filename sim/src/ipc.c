// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// TF-M's IPC model on sched.h threads. The SP is one thread that sleeps in psa_wait().
// A client call is one message:
// psa_connect(), psa_call() and psa_close() each raise the service signal,
// and block until psa_reply().
// Only one message is in flight, so the SP sees the same order as on the device.
// The SP checks are kept: a bad psa_read/psa_write index is a panic, as in TF-M.

#include "sched.h"
#include "sim.h"
#include <psa/client.h>
#include <psa/service.h>
#include <psa_manifest/sid.h>
#include <psa_manifest/tfm_bitcoin_partition.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MSG_HANDLE ((psa_handle_t)0x40000001)
#define CONNS_MAX 8

struct message {
    psa_signal_t signal;
    psa_msg_t msg;
    const psa_invec *in;
    size_t in_len;
    psa_outvec *out;
    size_t out_len;
    size_t in_off[PSA_MAX_IOVEC];
    size_t out_off[PSA_MAX_IOVEC];
    bool busy;
    bool replied;
    psa_status_t status;
};

static psa_signal_t asserted;
static psa_signal_t irq_enabled;
static bool sp_ready;
static uint32_t ticks;
static struct message cur;
static psa_signal_t conns[CONNS_MAX];

struct sp_job {
    void (*fn)(void *arg);
    void *arg;
    bool done;
};
static struct sp_job *job;

_Noreturn void psa_panic(void)
{
    fprintf(stderr, "[SIM] psa_panic(): the device would halt here\n");
    exit(70);
}

// SP side.

// Runs a queued job on the SP thread, so it never races a message or a tick.
// Called with the lock held.
static void run_job(void)
{
    struct sp_job *j = job;

    sched_unlock();
    j->fn(j->arg);
    sched_lock();
    j->done = true;
    job = NULL;
    sched_wake();
}

psa_signal_t psa_wait(psa_signal_t signal_mask, uint32_t timeout)
{
    psa_signal_t got;

    sched_lock();
    if (!sp_ready) {
        sp_ready = true;
        sched_wake();
    }
    if (job) {
        run_job();
    }
    while (!(asserted & signal_mask) && timeout == PSA_BLOCK) {
        if (job) {
            run_job();
            continue;
        }
        sched_wait();
    }
    got = asserted & signal_mask;
    sched_unlock();
    return got;
}

psa_status_t psa_get(psa_signal_t signal, psa_msg_t *msg)
{
    sched_lock();
    if (!(asserted & signal) || !cur.busy || cur.signal != signal) {
        sched_unlock();
        psa_panic();
    }
    asserted &= ~signal;
    *msg = cur.msg;
    sched_unlock();
    return PSA_SUCCESS;
}

// The caller is blocked until psa_reply(), so the SP may use `cur` without the lock.
static void check_handle(psa_handle_t h)
{
    if (h != MSG_HANDLE || !cur.busy || cur.replied) {
        psa_panic();
    }
}

size_t psa_read(psa_handle_t msg_handle, uint32_t invec_idx, void *buffer, size_t num_bytes)
{
    size_t left;

    check_handle(msg_handle);
    if (invec_idx >= PSA_MAX_IOVEC) {
        psa_panic();
    }
    if (invec_idx >= cur.in_len) {
        return 0;
    }
    left = cur.in[invec_idx].len - cur.in_off[invec_idx];
    if (num_bytes > left) {
        num_bytes = left;
    }
    memcpy(buffer, (const uint8_t *)cur.in[invec_idx].base + cur.in_off[invec_idx], num_bytes);
    cur.in_off[invec_idx] += num_bytes;
    return num_bytes;
}

void psa_write(psa_handle_t msg_handle, uint32_t outvec_idx, const void *buffer, size_t num_bytes)
{
    check_handle(msg_handle);
    if (outvec_idx >= PSA_MAX_IOVEC || outvec_idx >= cur.out_len ||
        num_bytes > cur.out[outvec_idx].len - cur.out_off[outvec_idx]) {
        psa_panic();
    }
    memcpy((uint8_t *)cur.out[outvec_idx].base + cur.out_off[outvec_idx], buffer, num_bytes);
    cur.out_off[outvec_idx] += num_bytes;
}

// The host runs an IPC handler in microseconds.
// On the device a call that derives keys takes tens to hundreds of milliseconds of partition time.
// With a cost set, each psa_call keeps the SP thread that long,
// so a test can see what a busy NS does to the tick.
static uint32_t call_cost_ms;

void sim_ipc_cost(uint32_t ms)
{
    sched_lock();
    call_cost_ms = ms;
    sched_unlock();
}

uint32_t sim_ipc_ticks(void)
{
    uint32_t n;

    sched_lock();
    n = ticks;
    sched_unlock();
    return n;
}

void psa_reply(psa_handle_t msg_handle, psa_status_t status)
{
    check_handle(msg_handle);
    if (call_cost_ms && cur.msg.type >= PSA_IPC_CALL) {
        sched_sleep_ms(call_cost_ms);
    }
    sched_lock();
    cur.status = status;
    cur.replied = true;
    sched_wake();
    sched_unlock();
}

void psa_irq_enable(psa_signal_t irq_signal)
{
    sched_lock();
    irq_enabled |= irq_signal;
    sched_unlock();
}

// The SP calls this right after display_tick(), so it also counts the finished ticks.
void psa_eoi(psa_signal_t irq_signal)
{
    sched_lock();
    asserted &= ~irq_signal;
    ticks++;
    sched_wake();
    sched_unlock();
}

void sim_ipc_wait_ticks(uint32_t n)
{
    sched_lock();
    uint32_t end = ticks + n;
    while ((int32_t)(ticks - end) < 0) {
        sched_wait();
    }
    sched_unlock();
}

void sim_ipc_irq(uint32_t signal)
{
    sched_lock();
    if (irq_enabled & signal) {
        asserted |= signal;
        sched_wake();
    }
    sched_unlock();
}

void sim_ipc_run_on_sp(void (*fn)(void *arg), void *arg)
{
    struct sp_job j = {.fn = fn, .arg = arg, .done = false};

    sched_lock();
    while (job) {
        sched_wait();
    }
    job = &j;
    sched_wake();
    while (!j.done) {
        sched_wait();
    }
    sched_unlock();
}

void sim_ipc_wait_ready(void)
{
    sched_lock();
    while (!sp_ready) {
        sched_wait();
    }
    sched_unlock();
}

// Client side.

static psa_status_t send(psa_signal_t signal, int32_t type, const psa_invec *in, size_t in_len,
                         psa_outvec *out, size_t out_len)
{
    psa_status_t status;

    sched_lock();
    // One message at a time, as TF-M delivers them to the partition.
    while (cur.busy) {
        sched_wait();
    }

    memset(&cur, 0, sizeof(cur));
    cur.signal = signal;
    cur.in = in;
    cur.in_len = in_len;
    cur.out = out;
    cur.out_len = out_len;
    cur.busy = true;
    cur.msg.type = type;
    cur.msg.handle = MSG_HANDLE;
    cur.msg.client_id = -1;
    for (size_t i = 0; i < in_len; i++) {
        cur.msg.in_size[i] = in[i].len;
    }
    for (size_t i = 0; i < out_len; i++) {
        cur.msg.out_size[i] = out[i].len;
    }

    asserted |= signal;
    sched_wake();
    while (!cur.replied) {
        sched_wait();
    }

    // TF-M reports back how much the SP wrote into each outvec.
    for (size_t i = 0; i < out_len; i++) {
        out[i].len = cur.out_off[i];
    }
    status = cur.status;
    cur.busy = false;
    sched_wake();

    sched_unlock();
    return status;
}

static psa_signal_t sid_signal(uint32_t sid, uint32_t version)
{
    if (sid == TFM_BITCOIN_SID && version == TFM_BITCOIN_VERSION) {
        return TFM_BITCOIN_SIGNAL;
    }
#ifdef SIGU_SELFTEST
    if (sid == TFM_BITCOIN_TEST_SID && version == TFM_BITCOIN_TEST_VERSION) {
        return TFM_BITCOIN_TEST_SIGNAL;
    }
#endif
    return 0;
}

static void conn_free(psa_handle_t h);

psa_handle_t psa_connect(uint32_t sid, uint32_t version)
{
    psa_signal_t signal = sid_signal(sid, version);
    psa_handle_t h = PSA_NULL_HANDLE;

    if (!signal) {
        return PSA_ERROR_CONNECTION_REFUSED;
    }

    sched_lock();
    for (int i = 0; i < CONNS_MAX; i++) {
        if (!conns[i]) {
            conns[i] = signal;
            h = i + 1;
            break;
        }
    }
    sched_unlock();
    if (h == PSA_NULL_HANDLE) {
        return PSA_ERROR_CONNECTION_BUSY;
    }

    if (send(signal, PSA_IPC_CONNECT, NULL, 0, NULL, 0) != PSA_SUCCESS) {
        conn_free(h);
        return PSA_ERROR_CONNECTION_REFUSED;
    }
    return h;
}

static void conn_free(psa_handle_t h)
{
    sched_lock();
    conns[h - 1] = 0;
    sched_unlock();
}

static psa_signal_t conn_signal(psa_handle_t h)
{
    if (h < 1 || h > CONNS_MAX || !conns[h - 1]) {
        fprintf(stderr, "[SIM] NS used a bad handle %d\n", (int)h);
        psa_panic();
    }
    return conns[h - 1];
}

psa_status_t psa_call(psa_handle_t handle, int32_t type, const psa_invec *in_vec, size_t in_len,
                      psa_outvec *out_vec, size_t out_len)
{
    psa_signal_t signal = conn_signal(handle);

    if (type < PSA_IPC_CALL || in_len + out_len > PSA_MAX_IOVEC) {
        psa_panic();
    }
    return send(signal, type, in_vec, in_len, out_vec, out_len);
}

void psa_close(psa_handle_t handle)
{
    psa_signal_t signal;

    if (handle == PSA_NULL_HANDLE) {
        return;
    }
    signal = conn_signal(handle);
    send(signal, PSA_IPC_DISCONNECT, NULL, 0, NULL, 0);
    conn_free(handle);
}
