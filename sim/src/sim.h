// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// What the sim parts call on each other. The firmware never sees this file.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// The SP entry point from bitcoin_service.c.
void tfm_bitcoin_init(void);

// ipc.c
// Raises an IRQ signal, as the hardware IRQ would. Dropped until psa_irq_enable().
void sim_ipc_irq(uint32_t signal);
// Blocks until the SP waits in psa_wait() for the first time.
void sim_ipc_wait_ready(void);
// Blocks until the SP has finished `n` more display ticks.
void sim_ipc_wait_ticks(uint32_t n);

// A timing model for the tests:
// each psa_call keeps the SP thread `ms` longer, as a call that derives keys does on the device.
// 0 turns it off.
void sim_ipc_cost(uint32_t ms);
// How many display ticks the SP has finished.
uint32_t sim_ipc_ticks(void);

// Runs `n` display ticks now, without the 20 ms between them.
void sim_tick_burst(uint32_t n);
// Runs `fn` on the SP thread between two messages and blocks until it returns.
// This is the sim's way into SP calls that no opcode reaches.
void sim_ipc_run_on_sp(void (*fn)(void *arg), void *arg);

// ps.c
// Where PS keeps its files. NULL for a temp dir that is removed at exit.
bool sim_ps_init(const char *dir);
// Fault injection: at the `at`-th PS write from now,
// "cut" ends the process before the write lands (a power loss), "cutafter" right after it,
// "fail" makes the write fail. "off" stops it.
void sim_ps_fault(const char *mode, uint32_t at);

// kernel.c. Starts the SP, and the NS threads once the SP waits in psa_wait().
void sim_start(void);
// Parks the NS threads at their next k_msleep(), or lets them run again.
// A script can then act as a malicious NS with no honest NS thread in its way.
void sim_ns_freeze(bool on);

// card.c. `dir` is the folder that stands for the SD card. `in`: the card starts in the slot.
bool sim_card_init(const char *dir, bool in);
const char *sim_card_dir(void);
// Takes the card out of the slot or puts it in. NS sees it within a second.
void sim_card_set(bool in);
bool sim_card_in(void);

// flash.c. Sets which s0/s1 slot runs the bootloader and its b0 version.
void sim_boot_set(bool s0_active, uint32_t version);
// Makes the running app a test image that NS has not confirmed yet.
void sim_boot_unconfirmed(void);
// Makes slot0's trailer say that the last install failed and was swapped back.
void sim_boot_failed(void);
// Writes slot1 to a host file. False on an I/O error.
bool sim_slot1_dump(const char *path);
// Runs one boot of the real MCUboot with our hooks (sim/mcuboot) on the sim's flash.
// With `cut` not 0, the power fails at that flash write (or erase), which lands only in part.
void sim_mcuboot(uint32_t cut);
// Saves all flash, and puts it back.
void sim_flash_snapshot(void);
bool sim_flash_restore(void);
// Writes slot0 to a host file. False on an I/O error.
bool sim_slot0_dump(const char *path);
// A restart that keeps the flash:
// loads every flash area from `dir` (when saved there before), and saves them there at exit.
void sim_flash_keep(const char *dir);
// As a broken NS: requests an install without the panel, or flips a byte of slot1.
void sim_forge_request(bool permanent);
void sim_forge_byte(uint32_t off);
// As a broken NS: writes slot0's trailer as in the middle of a swap.
void sim_forge_resume(void);
// As NS that never requests: removes the request from slot1's trailer.
void sim_forge_clear(void);
// A power loss in the middle of the last install record write of this run.
void sim_forge_tear(void);
// As a malicious NS: writes a host file to the start of slot1. False when it cannot be read.
bool sim_forge_slot1(const char *path);
// A power loss in the SP's next install record write, after `words` 32-bit words.
void sim_forge_auth_cut(int words);
// For firmware_flash.c: true once when such a cut is set, with the word count.
bool sim_auth_cut_take(uint32_t *words);

// panel_hw.c
// Copies the panel into `out` (240*240 RGB565, host byte order). Returns the frame counter.
uint32_t sim_panel_read(uint16_t *out, uint8_t *light, bool *blank);
// The backlight percent now.
uint8_t sim_panel_light(void);
// Writes the panel as a PNG file. False on an I/O error.
bool sim_panel_png(const char *path);

// panel_text.c. The text on the panel now, see there. Call it on the SP thread.
void sim_panel_text(char *out, size_t size);

// input.c
// Queues key presses (INPUT_* bits). The SP reads them on its next tick.
void sim_input_press(uint32_t keys);

// window.c. Opens the window.
// Then the main thread calls sim_window_frame() until it returns false, when the window is closed.
bool sim_window_open(int scale);
bool sim_window_frame(void);

// control.c. Runs one command line, prints the reply. False on "quit".
bool sim_control_line(const char *line);
