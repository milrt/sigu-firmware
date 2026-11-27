# Architecture

Runs on the nRF54L15 with TF-M (TrustZone-M). The chip is split in two:

- **The secure partition `TFM_SP_BITCOIN` (SP)** holds the keys, builds the sighash, and owns
  the panel and the three buttons. It is trusted.
- **The non-secure image (NS)** parses PSBTs and runs the SD card. It has no panel and no GPIO.
  It is not trusted: we assume an attacker can run any code there.

NS asks, and the SP checks, shows and signs. The SP cannot call NS, so NS polls it.

## Threat model

Trusted: the SP, the panel, the three buttons, b0, MCUboot, and the two release signing keys.
Not trusted: NS (PSBT parsing, the SD card), the host wallet, the card and every file on it.

| Threat | Mitigation |
|---|---|
| Host, NS or card lies about amounts, change or the tx | The SP checks the tx and shows it. Only OK on the panel approves. |
| Address or xpub substitution | The panel shows addresses, fingerprint and QR from the SP |
| Rogue or old firmware on the card | Signed boot chain, install only after OK, security floor |
| Stolen device | PIN, 10 tries then wipe, auto-lock, storage bound to the chip |
| Debug port, glitching | Debug port locked in release, glitch and tamper detectors on |
| Dev build on a user device | The release build refuses the shell, self-tests and sample keys |

Not covered: a user who approves without reading, coercion, seed backup, supply chain (no
attestation), lab attacks (side channels, advanced fault injection, decapping), theft of the
release signing keys, and any script other than single-sig P2WPKH with `SIGHASH_ALL`.

## Source tree

| Path | What |
|---|---|
| `app/secure/` | The SP. `bitcoin_service.c` is the IPC dispatch and the main loop. |
| `app/secure/bitcoin/` | Sessions, the tx state machine, sighash, scripts, BIP32, BIP39, key storage |
| `app/secure/display/` | Screens and shared entry components (seed, PIN, passphrase) |
| `app/secure/drivers/` | Panel (ST7789), keys, tick timer, tamper and glitch setup |
| `app/secure/files/` | The SP's view of the card and the firmware slots |
| `app/nonsecure/` | PSA client, PSBT parse and sign, SD card thread, install, watchdog |
| `app/shared/` | Built into both: the ABI, wire records, hashes, addresses, image layout, descriptor |
| `app/mcuboot_hooks/` | MCUboot hooks that check every swap against the install record |
| `sim/` | The host simulator, see below |
| `sim/tests/` | The sim tests. `txlab.py` is the test wallet and a reference PSBT signer. |

## SP main loop

One thread handles both IPC and the screen: `psa_wait()`, then the pending messages, then
`display_tick()` (every 20 ms, from TIMER22). IPC handlers and screen callbacks must be short.

## The ABI

`app/shared/include/shared/bitcoin_service_defs.h` defines the service IDs and opcodes.

- No opcode creates, opens, recovers, closes or wipes a wallet. That is panel only, so NS never sees a
  mnemonic, a PIN or a passphrase. There is no `sign_hash`.
- The session is the service ID, never a flag in the payload. Records go through the
  `shared/wire.h` cursor (`tx_records.c`), never packed structs.
- An unknown opcode returns `PSA_ERROR_NOT_SUPPORTED`, and NS input never makes the SP panic.

The release build has one service (`TFM_BITCOIN`). A dev build with `CONFIG_SIGU_SELFTEST`
adds `TFM_BITCOIN_TEST` for the self-tests and an in-RAM test wallet.

## Signing a transaction

```
NS: BEGIN → OUTPUT × n → INPUT × n → CONFIRM → POLL ... → SIGN_INPUT × n
SP:                                  review on the panel → OK
```

A step out of order resets the transaction. The SP trusts nothing NS sends:

- Input amounts come from the previous tx, whose txid must match the outpoint. Output amounts
  are in the BIP143 sighash. The scriptCode comes from the SP's own pubkey.
- Change is only at `m/84'/c'/a'/1/i`, and the SP derives its script again. Any other output is
  shown as a payment.
- The network comes from the coin type in the paths. Each input is signed once.

Approval is only OK on the last review page, 1 s after it opens, bound to the `tx_id` the screen
read. A new tx under an open review ends it. No opcode can approve. Only single-sig P2WPKH with
`SIGHASH_ALL` is signed.

## Wallet storage

The seed is wrapped with a key from the PIN (PBKDF2-HMAC-SHA512) and stored in TF-M Protected
Storage, which encrypts it again with a key bound to the chip. A wrong PIN counts before the
check. Ten wrong PINs wipe the wallet. The wallet locks after 5 minutes with no key press, by
the timer, so NS cannot stretch it.

## The SD card

NS owns the card. One job at a time goes through the SP, and the user starts it on the panel:

| Job | What NS does |
|---|---|
| SIGN | Reads `<name>.psbt`, runs the signing flow, writes `<name>-signed.psbt` |
| EXPORT | Writes `wallet-<fingerprint>.txt`, a BIP380 `wpkh(...)` descriptor |
| INSTALL_APP / INSTALL_BOOT | Copies a signed image from the card to slot1 |
| INSTALL_COMMIT | Asks MCUboot to install slot1 and restarts |

The panel picks a job (`FILES_POLL` hands it to NS) and NS ends it with `FILES_RESULT`. File
names and "saved" are NS claims. What the review, the export QR and the receive screen show
comes from the SP.

## Boot and firmware install

```
b0 (immutable) → MCUboot (s0 or s1) → TF-M + NS (one signed image in slot0)
```

All three are signed with ed25519, and the public keys are in KMU. MCUboot uses swap-using-move.
A new app boots as a test. About 10 s after the start, once the SP has answered and read PS, NS
confirms it. If the app faults or hangs before that, the chip resets (WDT31, 8 s) and MCUboot
swaps the old app back. A bootloader install has no rollback. A new app must read the old app's
PS data, so a format change migrates only after the confirm.

NS can write slot1 and the MCUboot trailers, so MCUboot does not trust them. It swaps only what
the **install record** allows. That is a small partition that only the SP and MCUboot can
write:

1. The user picks a file and presses OK. The SP hashes slot1 itself and writes AUTHORIZED with
   that hash.
2. MCUboot (`app/mcuboot_hooks/hooks.c`) installs only an image with that hash and a security
   counter at or above the floor. It tracks the swap as SWAPPING, then TESTING, then IDLE.
3. Anything else, such as a forged request, revert or resume, closes the trailer, and nothing
   swaps.

The record has two copies with a sequence number and a CRC, so a power loss during a write
keeps the previous copy. The security floor rises only once a new app is kept. The b0 counter
keeps out an older MCUboot.

## Flash layout

From `app/boards/sigu_partitions.dtsi`:

| Region | Owner |
|---|---|
| b0, MCUboot s0/s1 | Boot chain. b0 is write-locked. |
| `sigu_install_partition` (2K) | Install record. SP and MCUboot only. |
| PS, ITS, OTP | TF-M secure storage. Must stay below `slot0_ns`. |
| `slot0` (secure + NS) | The running app. NS can write only the last sector (the trailer). |
| `slot1` | The staged install. NS writes it. |
| Unused (64K, to the end of RRAM) | Nothing. NS has no file system in RRAM. |

Moving PS, ITS, OTP or the start of slot0 needs a full erase, which wipes the wallet.

## Hardware

Board: nRF54L15-DK (`nrf54l15dk/nrf54l15/cpuapp/ns`). The panel and the keys are on secure
pins that NS cannot touch. The SD card is on NS pins.

| Part | Pins |
|---|---|
| Panel, ST7789 240×240, SPI (SPIM22) | RESET P1.7, CS P1.8, DC P1.9, SCK P1.11, MOSI P1.12 |
| Backlight (PWM21) | P1.14 |
| Keys, to GND, internal pull-up | OK P0.4, NEXT P1.10, DEL P1.13 |
| SD card, SPI (SPIM21) | SCK P2.6, MOSI P2.8, MISO P2.9, CS P2.10 |
| NS console (USB VCOM) | P1.4, P1.5 |

There is no card-detect pin yet, so a pulled card is not seen.

## Building

The dev build and flash commands are in the [README](README.md#board).

There are two builds:

- **Release** is the default `west build`. It has no shell and no self-tests, takes input only
  from the SD card, and locks the debug port of both domains on first boot.
- **Dev** adds `-DSB_EXTRA_CONF_FILE=sysbuild_dev.conf -DEXTRA_CONF_FILE=prj_dev.conf`. The
  debug port stays open, the boot chain is signed with the NCS debug keys, and the shell has the
  self-tests (`bitcoin test_secure`, `bitcoin test_nonsecure`).

The release build needs two ed25519 keys of your own, outside the repo, one for b0 and one for
MCUboot (`../external/nrf/scripts/bootloader/keygen.py --private --algorithm ed25519 --out
<file>`). Pass them with absolute paths:

```sh
K=/Volumes/sigu-keys    # for example an encrypted volume
west build -p -b nrf54l15dk/nrf54l15/cpuapp/ns -d app/build_release app -- \
  -DSB_CONFIG_SECURE_BOOT_SIGNING_KEY_FILE=$K/nsib.pem \
  -DSB_CONFIG_BOOT_SIGNATURE_KEY_FILE=$K/mcuboot.pem
```

The build refuses a sample key, a key inside the repo, or the same key twice. `--recover` on the
first flash writes the public keys into KMU. After the first boot the debug port is locked, and
only `nrfutil device recover` (which erases the chip) opens it again.

### Firmware update files

Set the versions before the build: the app in `app/VERSION`, MCUboot in
`CONFIG_FW_INFO_FIRMWARE_VERSION` (`app/sysbuild/mcuboot.conf`) and
`SB_CONFIG_SECURE_BOOT_MCUBOOT_VERSION` (`app/sysbuild.conf`). Raise `--security-counter`
(`prj.conf`) for a security fix or a PS format change, never lower it. b0 starts the higher
MCUboot and has 20 counter slots.

Copy the build outputs to the top of the card, renamed:

| Card file | Build output |
|---|---|
| `sigu-app.bin` | `app/zephyr/zephyr.signed.bin` |
| `sigu-mcuboot-s0.bin` | `signed_by_mcuboot_and_b0_mcuboot.bin` |
| `sigu-mcuboot-s1.bin` | `signed_by_mcuboot_and_b0_mcuboot_s1_variant.bin` |

The app hash on the panel is `shasum -a 256` of `zephyr.signed.bin`.

### Reproducible build

`docker/Dockerfile` pins the toolchain, Debian and the Python packages by SHA-256, for
linux/amd64 and linux/arm64. Both give the same bytes. Source paths end up in the image, so the
build runs with the workspace at `/work` and the repo folder named `sigu-firmware`, as the
`docker run` in the [README](README.md#without-installing-anything) mounts it.

The release config, in the container (CI runs the same):

```sh
cd /work/sigu-firmware
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
umask 022
printf '%s\n' '-----BEGIN PRIVATE KEY-----' \
  'MC4CAQAwBQYDK2VwBCIEIP6tgD72vIcArAkktUk0kOuHI1YA0nDrTAKWWQsin/g2' \
  '-----END PRIVATE KEY-----' >/tmp/nsib.pem
printf '%s\n' '-----BEGIN PRIVATE KEY-----' \
  'MC4CAQAwBQYDK2VwBCIEIHh3Bo1TfJEvBRTE2xbNIX/GJb4lsgx+tMHE5qDQ9P+L' \
  '-----END PRIVATE KEY-----' >/tmp/mcuboot.pem
west build -p -b nrf54l15dk/nrf54l15/cpuapp/ns -d app/build-repro app -- \
  -DSB_CONFIG_SECURE_BOOT_SIGNING_KEY_FILE=\"/tmp/nsib.pem\" \
  -DSB_CONFIG_BOOT_SIGNATURE_KEY_FILE=\"/tmp/mcuboot.pem\"
sha256sum app/build-repro/app/zephyr/zephyr.signed.bin \
  app/build-repro/signed_by_mcuboot_and_b0_mcuboot*.bin
```

TF-M prints its build time at boot, and CMake takes it from `SOURCE_DATE_EPOCH`, so it is the
commit time. The two keys are public throwaway keys (the private key is SHA-256 of "sigu
throwaway <name>"), so these files are for checks only. They are not files in the repo,
because the build refuses a key there. Kconfig strings need the quotes in the value. For the
other architecture, build the image with `docker build --platform linux/amd64` (emulated,
slow). After a change to `docker/requirements.in`, run `docker/lock-requirements.sh`.

## Simulator

`sim/` builds the SP, `shared/`, the NS PSBT and card code, and MCUboot's bootutil with the
hooks for the host, unchanged. See [sim/README.md](sim/README.md).
