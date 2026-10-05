# Changelog

## [2.0.0](https://github.com/good-tools/wiregasm/compare/v1.9.1...v2.0.0) (2026-10-05)


### ⚠ BREAKING CHANGES

* the Wiregasm wrapper methods are camelCase (listModules, listPrefs, applyPrefs, setPref, getPref, testFilter, completeFilter, reloadLuaPlugins, addPlugin, isEoTap, isConvTap, listProtocols, setProtocolEnabled, setProtocolEnabledByName, listHeuristicDissectors, setHeuristicEnabled). The snake_case names are removed; the README's upgrade notes map old to new.
* the generated module requires Node.js 22 or later (-sMIN_NODE_VERSION=220000) and Chrome 85 / Firefox 79 / Safari 15. Only documented loader options are read from the object passed to loadWiregasm (emscripten's defaults plus wasmBinary and getPreloadedPackage).

### Features

* add bindings to manage protocols and heuristic dissectors ([#26](https://github.com/good-tools/wiregasm/issues/26)) ([789d97e](https://github.com/good-tools/wiregasm/commit/789d97ed2b43eb29248609748920dbb177ee3d5a))
* build against the dependency versions Wireshark 4.4.5 pins ([#45](https://github.com/good-tools/wiregasm/issues/45)) ([b4e6ff6](https://github.com/good-tools/wiregasm/commit/b4e6ff64fb5a9d5bf90d92dccb49083c851024e7))
* build with Emscripten 6 and target Node.js 22+ ([#44](https://github.com/good-tools/wiregasm/issues/44)) ([a460b9d](https://github.com/good-tools/wiregasm/commit/a460b9df3bcc64b3b21d42b0c2f799384fd886a9))
* camelCase Wiregasm API, free embind objects after use ([#50](https://github.com/good-tools/wiregasm/issues/50)) ([d442f08](https://github.com/good-tools/wiregasm/commit/d442f082deb1b1a7afb9a9e501f9317ed599d8fe))
* Wireshark 4.6.9 ([#46](https://github.com/good-tools/wiregasm/issues/46)) ([3ea9f07](https://github.com/good-tools/wiregasm/commit/3ea9f0768dc2aac1565d877fab858ebccc887409))


### Bug Fixes

* clear error before load(), list tap keys in tap() errors ([#37](https://github.com/good-tools/wiregasm/issues/37)) ([e268d58](https://github.com/good-tools/wiregasm/commit/e268d58289f5d2cf2fb739f2074c4c9b29c04331))
* iograph error paths (crash after a failing graph, large intervals) ([#54](https://github.com/good-tools/wiregasm/issues/54)) ([a827777](https://github.com/good-tools/wiregasm/commit/a8277779be21b6633c5d25126d3638496577eec9))
* prevent decode-as registration growth while preserving defaults ([#29](https://github.com/good-tools/wiregasm/issues/29)) ([77fec7f](https://github.com/good-tools/wiregasm/commit/77fec7f094d3af5e66cf8800273603962fbb871c))
