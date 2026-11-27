#!/usr/bin/env bash
# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Writes docker/requirements.txt from docker/requirements.in. Every package that NCS pins in
# external/nrf/scripts/requirements-fixed.txt gets that version, dependencies too. The lock
# holds the hashes of every file on PyPI for each version, so it serves amd64 and arm64. It
# runs in the base image, so the markers are resolved for its Python.
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd -P)
ncs=$dir/../../external/nrf/scripts/requirements-fixed.txt
base=$(sed -n 's/^FROM \([^ ]*\) AS base$/\1/p' "$dir/Dockerfile")

# Only the pins, without the Nordic index and the markers.
grep -E '^[A-Za-z0-9_.-]+==' "$ncs" | sed 's/ *;.*//' >"$dir/ncs-constraints.txt"
trap 'rm -f "$dir/ncs-constraints.txt"' EXIT

docker run --rm -v "$dir:/d" -w /d "$base" bash -c '
    apt-get update -qq && apt-get install -y -qq --no-install-recommends python3-venv >/dev/null 2>&1
    python3 -m venv /tmp/v && /tmp/v/bin/pip install -q pip-tools==7.5.1
    /tmp/v/bin/pip-compile -q --generate-hashes --allow-unsafe --strip-extras --no-header \
        -c ncs-constraints.txt --output-file requirements.txt requirements.in'
