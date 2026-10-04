ARG EMSDK_VERSION=6.0.11
# builder: the toolchain. `make docker` builds in it.
FROM emscripten/emsdk:${EMSDK_VERSION} AS builder
ARG MESON_VERSION=1.12.1

RUN echo "## Update and install packages" \
    && apt-get -qq -y update \
    && DEBIAN_FRONTEND="noninteractive" TZ="America/San_Francisco" apt-get -qq install -y --no-install-recommends \
        flex \
        lemon \
        pkg-config \
        ninja-build \
        python3-pip \
        python3-setuptools \
        python3-packaging \
        autoconf \
        automake \
        autopoint \
        libtool \
        libltdl-dev \
    && pip3 install --no-cache-dir --break-system-packages meson==${MESON_VERSION} \
    && apt-get -y clean \
    && apt-get -y autoclean \
    && apt-get -y autoremove \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/debconf/*-old \
    && rm -rf /usr/share/doc/* \
    && rm -rf /usr/share/man/?? \
    && rm -rf /usr/share/man/??_* \
    && echo "## Done"

# deps: builder + every dependency built and installed into /src/built.
# CI tags it with a hash of these inputs and publishes it to GHCR, so builds
# only compile lib/wiregasm (`make -o build/stamp/wireshark.built`).
FROM builder AS deps
WORKDIR /src
COPY Makefile ./
COPY mk mk
COPY patches patches
COPY overlay overlay
COPY scripts/patches.mjs scripts/patches.mjs
RUN make -j"$(nproc)" deps && rm -rf build .cache
