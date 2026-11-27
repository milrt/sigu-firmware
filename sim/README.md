# Simulator

The firmware sources built for the host. The panel is a window, the three keys are on the
keyboard, and the SD card is a folder. A PSBT signed here has the same bytes as on the device.

## Build

```sh
brew install cmake sdl2              # macOS
sudo apt install cmake libsdl2-dev   # Debian / Ubuntu

cmake -S sim -B sim/build
cmake --build sim/build -j
```
`external/` from west must sit next to this repo (`../external`), as for the firmware. Pass
`-DEXTERNAL_DIR=...` if it is somewhere else.

## Run
```sh
sim/build/sigu-sim
```

Options:
- `--ephemeral`: a new wallet in a temp folder that is removed at exit.
- `--ps DIR`, `--card DIR`: other folders.
- `--no-card`: start with the card out of the slot.
- `--scale N`: window zoom, 1 to 4. The default 1 shows each panel pixel as one screen pixel.
- `--boot-failed`: start as after a failed install that MCUboot swapped back.
- `--reboot`: keep all flash (slot0, slot1, s0, s1, the install record) in the PS folder across
  runs, and boot the real MCUboot (`sim/mcuboot`) before NS starts. Each run is then one boot of
  the same device. MCUboot checks an image's SHA-256 TLV where the device checks a signature.
- `--headless`: no window, for scripts.

## Scripting

The sim reads one command per line on stdin and answers `ok ...` or `err ...`. It works with
and without the window. The common ones:

```
key a|s|d [count]              press the left, middle or right key
wait <ms>
shot <file.png>                save the panel as a PNG
text                           the text on the panel
card in|out                    put the SD card in, or take it out
wallet setup <pin> <words...>  restore a wallet from a mnemonic (no opcode does this)
wallet open <pin> [passphrase]
quit
```

The full list, with the boot, flash and malicious NS commands the tests use, is at the top of
`src/control.c`.

For example, a wallet with a known seed and a screenshot of the status screen:

```sh
printf '%s\n' "wallet setup 1234 abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  "wallet open 1234" "wait 1200" "shot status.png" quit | sim/build/sigu-sim --headless --ephemeral
```

## Web

The same code builds to WebAssembly with Emscripten.

```sh
brew install emscripten

emcmake cmake -S sim -B sim/build-web
cmake --build sim/build-web -j
python3 -m http.server -d sim/build-web 8000   # then open http://localhost:8000
```

To publish it, copy `index.html`, `sigu-sim.js` and `sigu-sim.wasm` from `sim/build-web` to
any static host. It needs no special headers: the threads are fibers on the one JS thread, not
Web Workers. The wallet and the card are kept in the browser's IndexedDB. The page adds PSBTs to
the card and downloads the signed files. From the browser console, `sigu.command("key d")` takes the same commands as stdin does above.

## Tests

The tests drive the panel with key presses. They sign the example PSBT of `sim/tests/txlab.py`
(the test wallet and a reference signer) from the card and check it against the bytes the
device signed. They need Python 3.10 or newer and `sim/requirements.txt`. The venv from the
[README](../README.md#simulator) has it, or make one:

```sh
python3 -m venv sim/.venv
sim/.venv/bin/pip install -r sim/requirements.txt
sim/.venv/bin/python sim/tests/run.py
SIGU_SIM_WEB=1 sim/.venv/bin/python sim/tests/run.py
```

The last line runs the WebAssembly build in node (`sim/web/node_host.cjs`), with the same
tests. `run.py` runs the tests in parallel, one sim per test, because most of a test is the
sim waiting in real time. It takes about 20 s instead of 3 min. `-j N` sets how many run at
once, and names pick tests (`run.py wipe`). Plain `python -m unittest discover -s sim/tests`
still works, one test after the other.

## Sanitizers and fuzzing

The build fails on any warning in our sources (`-Wall -Wextra -Werror`, sim only).
`-DSIGU_SIM_WERROR=OFF` turns that off for a newer compiler.

The same tests under ASan and UBSan:

```sh
cmake -S sim -B sim/build-asan -DSIGU_SIM_SANITIZE=ON
cmake --build sim/build-asan -j
SIGU_SIM=sim/build-asan/sigu-sim sim/.venv/bin/python sim/tests/run.py
```

`fuzz/` has libFuzzer targets for the code that reads NS input: `fuzz_psbt` (the PSBT parser and
writer), `fuzz_prev_tx` (`prev_tx_output()`), `fuzz_records` (the `tx_records` unpack),
`fuzz_files_set` (the `FILES_SET` handler), `fuzz_tx_session` (the tx session, as a malicious
NS drives it) and `fuzz_install` (the slot1 image and the install record). CI runs each for
60 s. They need clang with libFuzzer (Linux, or
`brew install llvm` and `-DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang`). Apple clang has
none, so there the targets only replay the files they are given.

```sh
cmake -S sim -B sim/build-fuzz -DSIGU_SIM_FUZZ=ON
cmake --build sim/build-fuzz -j
sim/.venv/bin/python sim/fuzz/make_corpus.py sim/build-fuzz/corpus
sim/build-fuzz/fuzz/fuzz_psbt -dict=sim/fuzz/psbt.dict -max_total_time=60 sim/build-fuzz/corpus/fuzz_psbt
sim/build-fuzz/fuzz/fuzz_psbt crash-<hash>     # replay a crash, also with Apple clang
```

## How it works

| Device | Sim |
|---|---|
| TF-M IPC (`psa_wait`, `psa_call`, ...) | `src/ipc.c`: SP and NS are threads, one message at a time |
| Threads | `src/sched_pthread.c` on the desktop, `src/sched_fiber.c` (Asyncify fibers) on the web |
| TIMER22 tick | `src/tick.c`: a thread raises the IRQ signal every 20 ms |
| ST7789 panel | `src/panel_hw.c`: a framebuffer, shown by `src/window.c` (SDL2) |
| GPIO keys | `src/input.c`: a queue of presses from the window, the page or stdin, one per tick |
| Protected Storage | `src/ps.c`: one file per UID |
| Oberon PSA crypto | Mbed TLS 3.6 PSA |
| Zephyr (NS) | `shim/zephyr/`, `src/kernel.c`, `src/heap.c`, `src/card.c` (FAT → folder) |
| RRAM partitions | `src/flash.c`: slot0, slot1, s0, s1 and the install record in RAM, one flash map API |
| MCUboot | the real bootutil from `external/`, with `app/mcuboot_hooks`, in `mcuboot/` |

The SP runs its real `tfm_bitcoin_init()` loop. NS starts when the SP waits in `psa_wait()`,
as on TF-M.
