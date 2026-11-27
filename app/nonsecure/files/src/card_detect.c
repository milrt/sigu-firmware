// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "card_detect.h"

// The board has no card detect pin yet, so we take the card as always in.
// Then a card pulled after boot is not seen.
// With the pin, this returns sdhc_card_present(DEVICE_DT_GET(DT_NODELABEL(sdhc0))) == 1.
bool card_present(void)
{
    return true;
}
