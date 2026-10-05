# Builder images

`build.Dockerfile` has two stages:

* **`builder`**: the toolchain (emsdk, meson, autotools, lemon). `make docker` builds this stage locally and runs the build inside it, as the calling user.
* **`deps`**: `builder` plus every dependency (glib, Wireshark, ...) built and installed into `/src/built`. CI publishes it as `ghcr.io/good-tools/wiregasm-deps:<hash>`, where the hash covers `build.Dockerfile`, `Makefile`, `mk/`, `patches/`, `overlay/` and `scripts/patches.mjs`. CI then only compiles `lib/wiregasm` against it.

The emsdk and meson versions come from the top-level `Makefile` (`EMSDK_VERSION`, `MESON_VERSION`).

The old `okhalid/wiregasm-builder` image on Docker Hub (emsdk 3.1.31) is superseded and no longer updated.
