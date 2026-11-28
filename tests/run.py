# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Runs the wallet tests in parallel, one test per process. Same tests, same checks.

    sim/.venv/bin/python tests/run.py [-j N] [test_name ...]

The tests are end-to-end tests of the wallet firmware.
They run the SP, NS and MCUboot sources on the sim,
drive the panel with key presses, as a user does, and call the SP as a malicious NS.
One test_*.py per feature.
sim.py runs one sim, case.py is the base class and images.py makes the install images.
They use the test wallet and fixtures of sim/txlab.py,
and test_txlab.py checks txlab itself (no sim needed).

Most of a test is the sim waiting in real time, so the tests can share the CPUs.
Each test starts its own sim with its own folders.
`python -m unittest discover -s tests -v` runs them one after the other.
With SIGU_SIM_WEB=1 they run the WebAssembly build (sim/build-web) in node instead.
SIGU_SIM and SIGU_SIM_WEB work as with unittest.
"""

import argparse
import os
import subprocess
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent


def test_ids(suite) -> list[str]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from test_ids(item)
        else:
            yield item.id()


def run_one(test_id: str) -> tuple[str, int, float, str]:
    start = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", test_id],
        cwd=HERE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return test_id, proc.returncode, time.monotonic() - start, proc.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    # The sims mostly sleep, so more tests than CPUs still fit.
    parser.add_argument("-j", type=int, default=2 * (os.cpu_count() or 1), help="tests at once")
    parser.add_argument("names", nargs="*", help="only tests whose name contains one of these")
    args = parser.parse_args()

    # The tests read SIGU_SIM relative to the caller's folder, and each runs in HERE.
    if "SIGU_SIM" in os.environ:
        os.environ["SIGU_SIM"] = str(Path(os.environ["SIGU_SIM"]).resolve())

    ids = list(test_ids(unittest.defaultTestLoader.discover(str(HERE))))
    if args.names:
        ids = [i for i in ids if any(n in i for n in args.names)]

    start = time.monotonic()
    failed = []
    with ThreadPoolExecutor(max_workers=max(1, args.j)) as pool:
        for future in as_completed([pool.submit(run_one, i) for i in ids]):
            test_id, code, secs, out = future.result()
            # test_install.InstallTest.test_x prints as "install  test_x".
            parts = test_id.split(".")
            name = f"{parts[-3].removeprefix('test_'):<16} {parts[-1]}"
            print(f"{'ok  ' if code == 0 else 'FAIL'} {secs:5.1f}s  {name}", flush=True)
            if code != 0:
                failed.append((name, out))

    for name, out in failed:
        print(f"\n===== {name}\n{out}")
    print(f"\n{len(ids) - len(failed)}/{len(ids)} passed in {time.monotonic() - start:.1f}s")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
