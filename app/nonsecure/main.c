// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The SD card runs on its own thread, through K_THREAD_DEFINE.
// A dev build adds the shell thread through SHELL_CMD_REGISTER.
// The panel and the keys belong to TFM_SP_BITCOIN.
int main(void)
{
    return 0;
}
