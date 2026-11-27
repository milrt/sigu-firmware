# Third-party software

The sigu firmware is under GPL-3.0-or-later, see [LICENSE](LICENSE). It contains or builds in
the parts below, each under its own license.

## In this repository

| Part | Files | License | Copyright |
|---|---|---|---|
| Montserrat glyph tables | `app/secure/display/src/fonts/montserrat_*.c` | OFL-1.1, see [OFL.txt](app/secure/display/src/fonts/OFL.txt) | 2011 The Montserrat Project Authors |
| Font Awesome Free check mark (U+F00C), in the same tables | as above | OFL-1.1, see [OFL.txt](app/secure/display/src/fonts/OFL.txt) | 2022 Fonticons, Inc. |
| Bech32 / Bech32m | `app/shared/src/segwit_addr.c`, `app/shared/include/shared/segwit_addr.h` | MIT, in the file header | 2017, 2021 Pieter Wuille |
| TF-M patch | `zephyr/patches/tf-m/slot0-ns-read-only.patch` | Apache-2.0, as the patched file | 2025 Nordic Semiconductor ASA, the TrustedFirmware-M Contributors |

`gen_font.py` made the glyph tables from LVGL's `lv_font_montserrat_*.c` (MIT, Copyright (c)
LVGL Kft). The firmware does not use LVGL itself.

## Fetched by west and built in

The revisions are pinned in [west.yml](west.yml). Each project has its full license text in its
own tree.

| Project | Used for | License |
|---|---|---|
| [secp256k1](https://github.com/bitcoin-core/secp256k1) | ECDSA signing, key derivation | MIT |
| [libbase58](https://github.com/bitcoin/libbase58) | Base58Check | MIT |
| [bips](https://github.com/bitcoin/bips) | The BIP39 English word list | MIT |
| [QR-Code-generator](https://github.com/nayuki/QR-Code-generator) | QR codes on the panel | MIT |
| [nRF Connect SDK](https://github.com/nrfconnect/sdk-nrf) | Platform, b0 | LicenseRef-Nordic-5-Clause |
| [Zephyr](https://github.com/zephyrproject-rtos/zephyr) | NS RTOS | Apache-2.0 |
| [Trusted Firmware-M](https://www.trustedfirmware.org/projects/tf-m/) | Secure firmware | BSD-3-Clause, Nordic platform files Apache-2.0 |
| [MCUboot](https://github.com/mcu-tools/mcuboot) | Bootloader | Apache-2.0 |
| oberon-psa-crypto | PSA crypto on the device | LicenseRef-Nordic-5-Clause |
| Mbed TLS, TF-PSA-Crypto | PSA crypto (Mbed TLS 3.6 in the simulator) | Apache-2.0 OR GPL-2.0-or-later |
| nrfx, hal_nordic, nrfxlib | Nordic drivers and libraries | BSD-3-Clause, LicenseRef-Nordic-5-Clause |
| CMSIS | Arm core headers | Apache-2.0 |
| picolibc | C library | BSD-3-Clause and others, see its `COPYING.picolibc` |
| QCBOR, t_cose | Built with TF-M | BSD-3-Clause |
