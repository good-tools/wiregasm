# Contributing to Wiregasm

## Prerequisites

* Node.js 22 or later
* Docker, for building the WebAssembly module

Nothing else is needed: the toolchain (emsdk, meson, autotools) lives in the builder image.

## Quick start

```sh
npm ci
make docker        # builds the wasm module into built/bin (all dependencies the first time)
npm run build      # builds the TypeScript wrapper into dist/
npm test           # unit tests against built/bin
npm run test:e2e   # the packed package, in Node.js and in Chromium
```

The first `make docker` compiles every dependency (Wireshark, glib, ...), which takes a while. Later builds only rebuild what changed. CI doesn't compile the dependencies at all: it uses a prebuilt image (see [docker/README.md](docker/README.md)).

To build without Docker you need the tools from [docker/build.Dockerfile](docker/build.Dockerfile) and the emsdk version from the `Makefile`; then run `make -j$(nproc)`.

## Lint and format

```sh
npm run lint       # Biome (TS/JS/JSON) and clang-format (C/C++). CI runs exactly this.
npm run fix        # applies both
```

The C++ in `lib/wiregasm` is built with `-Wall -Wextra -Werror`.

## Commits and pull requests

PRs are squash-merged, and the PR title becomes the commit message. Titles must follow [Conventional Commits](https://www.conventionalcommits.org/): `fix:`, `feat:`, `refactor:`, `test:`, `ci:`, `docs:`, `chore:`, ... with `!` (`feat!:`) for breaking changes. [release-please](https://github.com/googleapis/release-please) derives the next version and the changelog from them.

Before opening a PR, run `npm run lint` and `npm test` locally against a fresh build.

## Repository layout

```
src/                 TypeScript wrapper (Wiregasm class, types) and unit tests
lib/wiregasm/        C++ glue between Wireshark's epan and JavaScript (embind)
lib/wiregasm/ext/    JavaScript passed to emscripten (--pre-js, --js-library)
Makefile, mk/        the build: mk/rules.mk for the generic rules, mk/deps/<pkg>.mk per dependency
patches/<pkg>/       one patch per modified upstream file
overlay/<pkg>/       new files copied into an upstream source tree
scripts/             patches.mjs, dep-versions.mjs, size-check.mjs
docker/              builder and deps images
e2e/                 end-to-end tests of the packed package
samples/             captures used by the tests
```

## Changing a dependency

Wireshark and its dependencies need changes to build for WebAssembly. They are kept Brave-style: `patches/<pkg>/<path-with-dashes>.patch` holds one patch per modified upstream file, each starting with a `Why:` line; `overlay/<pkg>/` holds new files. Never edit a `.patch` by hand (except its `Why:` header). Use the tooling:

```sh
make src PKG=wireshark             # build/src/wireshark = upstream + overlay + patches, in git
# edit files under build/src/wireshark (git add any new files), then rebuild with make
make update-patches PKG=wireshark  # write the edits back to patches/ and overlay/
```

Prefer putting logic in `lib/wiregasm` over patching upstream, and keep patches to small hooks.

`make check-patches` checks that every patch still applies (CI runs it, in seconds).

## Bumping Wireshark

Library versions follow the ones Wireshark pins for the release we build (`tools/macos-setup.sh`).

1. `make src PKG=wireshark` (still on the old version)
2. Update `wireshark_VERSION` and `wireshark_SHA512` in `mk/deps/wireshark.mk`
3. `make rebase-patches PKG=wireshark`; fix any conflicts in `build/src/wireshark`, `git add` them and run `git rebase --continue` there
4. `make update-patches PKG=wireshark`
5. `npm run dep-versions` lists the libraries whose pinned version changed; bump them the same way
6. Port `lib/wiregasm` if the epan API changed (Wireshark's `sharkd.c` is the reference)

A bump is done when it builds from clean, `npm test` and `npm run test:e2e` pass, and `npm run size-check` stays within +10% of the latest release.

## Releases

Maintainers release by merging the release PR that release-please keeps open. CI then publishes to npm.
