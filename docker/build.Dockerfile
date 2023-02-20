FROM emscripten/emsdk:3.1.31

RUN echo "## Update and install packages" \
    && apt-get -qq -y update \
    && DEBIAN_FRONTEND="noninteractive" TZ="America/San_Francisco" apt-get -qq install -y --no-install-recommends \
        flex \
        lemon \
        pkg-config \
        ninja-build \
        meson \
        autoconf \
        automake \
        autopoint \
        libtool \
        libltdl-dev \
    && apt-get -y clean \
    && apt-get -y autoclean \
    && apt-get -y autoremove \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/debconf/*-old \
    && rm -rf /usr/share/doc/* \
    && rm -rf /usr/share/man/?? \
    && rm -rf /usr/share/man/??_* \
    && echo "## Done"