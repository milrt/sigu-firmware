# syntax=docker/dockerfile:1
# Copyright (C) 2026 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

# The build environment for the firmware, the sim and the tests, for linux/amd64 and
# linux/arm64. Build it from the repo root:
#   docker build -t sigu-build -f docker/Dockerfile .
#
# Both images give byte identical firmware: the same Zephyr SDK release (gcc 14.3.0 for
# arm-zephyr-eabi, built for each host), the same cmake, ninja and Python packages, and the
# same paths. Every download is checked by SHA-256, apt reads a fixed Debian snapshot, and pip
# installs from docker/requirements.txt with hashes.
#
# Only what a build uses is kept. The SDK host tools (qemu, openocd) and gdb are not
# installed, and of the 18 thumb multilibs only v8-m.main/nofp stays: every image of this
# firmware is cortex-m33 with the soft-float ABI. emsdk keeps only the tools and libraries the
# web sim uses (see the emsdk stage).

FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0 AS base
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
# apt reads snapshot.debian.org as it was at APT_SNAPSHOT, for both architectures. It must not
# be older than the base image. http is enough: apt checks the archive signatures.
ARG APT_SNAPSHOT=20261123T120000Z
RUN sed -i \
      -e "s|http://deb.debian.org/debian-security|http://snapshot.debian.org/archive/debian-security/${APT_SNAPSHOT}|" \
      -e "s|http://deb.debian.org/debian|http://snapshot.debian.org/archive/debian/${APT_SNAPSHOT}|" \
      /etc/apt/sources.list.d/debian.sources \
    && echo 'Acquire::Check-Valid-Until "false";' >/etc/apt/apt.conf.d/50snapshot


FROM base AS fetch
ARG TARGETARCH
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends ca-certificates curl xz-utils python3 \
    && rm -rf /var/lib/apt/lists/*

ARG CMAKE_VERSION=4.2.1
ARG NINJA_VERSION=1.13.2
ARG SDK_VERSION=1.0.1
RUN case "${TARGETARCH}" in \
      amd64) arch=x86_64 ninja=ninja-linux.zip \
             cmake_sha=c059bff1e97a2b6b5b0c0872263627486345ad0ed083298cb21cff2eda883980 \
             ninja_sha=5749cbc4e668273514150a80e387a957f933c6ed3f5f11e03fb30955e2bbead6 \
             sdk_sha=ca9bc0ff66fafca1dac9d592a36d953cf16d096a9d09b1c0357f021cf9f6a7eb \
             tc_sha=21b85981cb5a1818d9bc53d82af80f208946ec038b982ff1907287572ed3a634 ;; \
      arm64) arch=aarch64 ninja=ninja-linux-aarch64.zip \
             cmake_sha=3e178207a2c42af4cd4883127f8800b6faf99f3f5187dccc68bfb2cc7808f5f7 \
             ninja_sha=fd2cacc8050a7f12a16a2e48f9e06fca5c14fc4c2bee2babb67b58be17a607fc \
             sdk_sha=d79c5bfc68e679488659bea289a4026e52a64f03338875c8c9c850fff13cee30 \
             tc_sha=b9805b691f2f0a8926c92694cae378d05ba07b76abca745e216fcc52753cc4d6 ;; \
      *) echo "unsupported arch ${TARGETARCH}"; exit 1 ;; \
    esac \
    && gh=https://github.com \
    && sdk=$gh/zephyrproject-rtos/sdk-ng/releases/download/v${SDK_VERSION} \
    && get() { curl -fsSL -o "$1" "$2" && echo "$3  $1" | sha256sum -c --quiet; } \
    && cd /tmp \
    && get cmake.tar.gz $gh/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-${arch}.tar.gz $cmake_sha \
    && get ninja.zip $gh/ninja-build/ninja/releases/download/v${NINJA_VERSION}/$ninja $ninja_sha \
    && get sdk.tar.xz $sdk/zephyr-sdk-${SDK_VERSION}_linux-${arch}_minimal.tar.xz $sdk_sha \
    && get tc.tar.xz $sdk/toolchain_gnu_linux-${arch}_arm-zephyr-eabi.tar.xz $tc_sha \
    && mkdir -p /opt/cmake /opt/zephyr-sdk/gnu /opt/bin \
    && tar xzf cmake.tar.gz -C /opt/cmake --strip-components=1 \
    && rm -rf /opt/cmake/doc /opt/cmake/man /opt/cmake/share/{bash-completion,emacs,vim,aclocal} \
       /opt/cmake/bin/{cmake-gui,ccmake} \
    && python3 -c 'import zipfile; zipfile.ZipFile("ninja.zip").extract("ninja", "/opt/bin")' \
    && chmod 755 /opt/bin/ninja \
    && tar xJf sdk.tar.xz -C /opt/zephyr-sdk --strip-components=1 --exclude='*/hosttools' \
    && tar xJf tc.tar.xz -C /opt/zephyr-sdk/gnu \
    && rm -f /tmp/*.tar.* /tmp/ninja.zip

# Keep only what a cortex-m33 soft-float build reads. The multilib folders are the same in
# both host builds of the SDK.
RUN t=/opt/zephyr-sdk/gnu/arm-zephyr-eabi \
    && rm -f $t/bin/arm-zephyr-eabi-{gdb,gdb-py,gprof,gprof-py,lto-dump} \
    && rm -rf $t/share/{doc,info,man,gdb,locale} \
    && for lib in $t/arm-zephyr-eabi/lib $t/lib/gcc/arm-zephyr-eabi/*; do \
         rm -rf $lib/arm $lib/space; \
         find $lib/thumb -mindepth 1 -maxdepth 1 ! -name v8-m.main -exec rm -rf {} +; \
         find $lib/thumb/v8-m.main -mindepth 1 -maxdepth 1 ! -name nofp -exec rm -rf {} +; \
       done


# Emscripten for the web sim. It is not on PATH: a web build runs
# `source /opt/emsdk/emsdk_env.sh` first. The library cache must be writable, because the
# container runs as the host user and emcc builds any library it is missing on first use.
FROM base AS emsdk
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends ca-certificates git python3 xz-utils \
    && rm -rf /var/lib/apt/lists/*
ARG EMSDK_VERSION=7.0.0
RUN git clone -q --depth 1 --branch ${EMSDK_VERSION} https://github.com/emscripten-core/emsdk \
       /opt/emsdk \
    && cd /opt/emsdk \
    && ./emsdk install ${EMSDK_VERSION} \
    && ./emsdk activate ${EMSDK_VERSION} \
    && rm -rf downloads .git upstream/emscripten/test

# Keep only what the web sim uses. Gone: clangd, clang-scan-deps, the binaryen tools emcc
# runs only for flags the sim does not use (wasm2js for -sWASM=0, wasm-ctor-eval for
# EVAL_CTORS, wasm-split for SPLIT_MODULE), the fuzz, test and debug tools, emscripten's npm
# dev dependencies, closure (--closure), npm and the node headers. A flag that needs one of
# them needs it back. The library cache ships every variant (threads, wasm workers, GL
# emulation...): it is emptied, and one link with the sim's flags (sim/CMakeLists.txt) builds
# the libraries the sim needs and the SDL2 port. Of the port's source only src/ and include/
# stay, all its build reads: emcc downloads the port again if the folder or its marker is gone.
# Any other library emcc builds on its first use.
RUN cd /opt/emsdk \
    && node=$(echo /opt/emsdk/node/*/bin) \
    && (cd upstream/emscripten \
        && PATH=$node:$PATH npm prune -q --omit=dev --offline --no-audit --no-fund \
        && rm -rf node_modules/google-closure-compiler*) \
    && rm -f upstream/bin/{clangd,clang-scan-deps,llvm-cov,llvm-profdata,llvm-dwp} \
       upstream/bin/{wasm-fuzz-types,wasm-fuzz-lattices,wasm-reduce,wasm-shell,wasm-as,wasm-dis} \
       upstream/bin/{wasm-embed,wasm-merge,wasm-split,wasm2js,wasm-ctor-eval} \
    && rm -rf upstream/emscripten/cache/sysroot/lib/wasm32-emscripten/* \
    && source ./emsdk_env.sh >/dev/null 2>&1 \
    && cd /tmp \
    && printf '#include <SDL.h>\nint main(void) { return SDL_Init(SDL_INIT_VIDEO); }\n' >warm.c \
    && emcc -sUSE_SDL=2 -sASYNCIFY -sASYNCIFY_STACK_SIZE=131072 -sSTACK_SIZE=1048576 \
       -sALLOW_MEMORY_GROWTH -sEXIT_RUNTIME=0 -sENVIRONMENT=web,node \
       -sEXPORTED_FUNCTIONS=_main -sEXPORTED_RUNTIME_METHODS=FS,IDBFS,NODEFS,ccall \
       -lidbfs.js -lnodefs.js warm.c -o warm.js \
    && rm -f warm.* \
    && cd /opt/emsdk/upstream/emscripten/cache \
    && rm -rf build ports/*.zip \
    && find ports/sdl2/SDL-* -mindepth 1 -maxdepth 1 ! -name src ! -name include -exec rm -rf {} + \
    && rm -rf $node/../include $node/../lib/node_modules/{npm,corepack} $node/{npm,npx,corepack} \
    && chmod -R a+rwX /opt/emsdk/upstream/emscripten/cache


FROM base
# Firmware: git (west), dtc and gperf (Zephyr), python3. Sim: gcc, clang and libFuzzer, SDL2,
# make for a cmake without -G Ninja.
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends ca-certificates git python3 python3-venv \
       device-tree-compiler gperf gcc libc6-dev make clang libclang-rt-19-dev libsdl2-dev xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=fetch /opt/cmake /opt/cmake
COPY --from=fetch /opt/bin/ninja /usr/local/bin/ninja
COPY --from=fetch /opt/zephyr-sdk /opt/zephyr-sdk
COPY --from=emsdk /opt/emsdk /opt/emsdk

COPY docker/requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install -q --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

# A user for a dev container: updateRemoteUserUID gives it the host UID on Linux, so files in
# the workspace stay the host user's. CI and plain docker run pass -u instead.
RUN useradd -m -u 1000 -s /bin/bash dev
# Login shells (the Zed terminal) get the PATH from /etc/profile, which drops the one below.
RUN echo 'export PATH=/opt/venv/bin:/opt/cmake/bin:$PATH' >/etc/profile.d/sigu.sh

# The workspace is mounted from the host, so its owner is not the container user. The system
# config holds it, so every user (also -u) reads it.
RUN git config --system --add safe.directory '*'

ENV PATH=/opt/venv/bin:/opt/cmake/bin:$PATH \
    ZEPHYR_SDK_INSTALL_DIR=/opt/zephyr-sdk \
    ZEPHYR_TOOLCHAIN_VARIANT=zephyr

LABEL org.opencontainers.image.description="sigu firmware, sim and test build environment"
CMD ["/bin/bash"]
