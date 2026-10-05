# Wiregasm
[![Build & Test](https://github.com/good-tools/wiregasm/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/good-tools/wiregasm/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@goodtools/wiregasm)](https://www.npmjs.com/package/@goodtools/wiregasm)
[![Downloads](https://img.shields.io/npm/dm/@goodtools/wiregasm)](https://www.npmjs.com/package/@goodtools/wiregasm)

Packet analyzer powered by [Wireshark](https://www.wireshark.org/) (4.6) compiled to WebAssembly. Load a capture, list and filter its packets, and get Wireshark's full protocol tree, follow streams, conversations, export objects and IO graphs, in the browser or in Node.js.

Demo it on [good.tools](https://good.tools/packet-dissector).

## Supported environments
* **Node.js** 22 or later (the maintained LTS lines)
* **Browsers** with WebAssembly BigInt integration and bulk memory (Chrome 85+, Firefox 79+, Safari 15+)

## Install

```sh
npm install @goodtools/wiregasm
```

The package ships the wrapper (`dist/main.js`, `dist/module.js`, typings) and the Emscripten build: `dist/wiregasm.js` (loader), `dist/wiregasm.wasm` and `dist/wiregasm.data` (Wireshark's data files), plus `.gz` versions of the last two.

## Usage

The `Wiregasm` class wraps the module and manages one capture at a time:

```javascript
import { Wiregasm } from "@goodtools/wiregasm";
import loadWiregasm from "@goodtools/wiregasm/dist/wiregasm";

const wg = new Wiregasm();

await wg.init(loadWiregasm, {
  // where to fetch wiregasm.wasm and wiregasm.data from (see below)
  locateFile: (path, prefix) => `/assets/wiregasm/${path}`,
  handleStatus: (type, message) => console.log(type, message),
});

const loaded = wg.load("capture.pcap", bytes); // Uint8Array of the capture file
// loaded.code === 0, loaded.summary.packet_count, ...

const list = wg.frames("http", 0, 100); // display filter, skip, limit
const frame = wg.frame(1);              // protocol tree, data sources, follow candidates

wg.destroy();
```

Other methods include `follow`, `tap` (conversations, endpoints, export objects), `download` (export object payloads), `iograph`, `testFilter`, `completeFilter`, the preference methods (`listModules`, `listPrefs`, `getPref`, `setPref`, `applyPrefs`), `listProtocols`/`setProtocolEnabled(ByName)` and `listHeuristicDissectors`/`setHeuristicEnabled`. See `src/index.ts` and the typings for the full API.

### Loading the asset files

The loader needs `wiregasm.wasm` and `wiregasm.data`:

* **Browser:** serve both next to your app and point `locateFile` at them (the data file is requested with an empty prefix, so always return a full URL). To save bandwidth, fetch the `.gz` versions yourself, inflate them, and pass `wasmBinary` and `getPreloadedPackage(name, size)` instead; see [examples/vanilla](examples/vanilla).
* **Node.js:** `locateFile` is required for the data file, which is otherwise looked up in the current working directory:

  ```javascript
  const loadWiregasm = require("@goodtools/wiregasm/dist/wiregasm.js");
  await wg.init(loadWiregasm, {
    locateFile: (file) => require.resolve(`@goodtools/wiregasm/dist/${file}`),
  });
  ```

### Lua dissectors

Add Lua dissectors to the plugins directory before initializing:

```javascript
await wg.init(loadWiregasm, overrides, async (lib) => {
  lib.FS.writeFile(`${lib.getPluginsDirectory()}/dissector.lua`, luaSource);
});
// or, after init: wg.addPlugin("dissector.lua", luaSource); wg.reloadLuaPlugins();
```

### Low-level API

The Emscripten module can also be used directly. Its `DissectSession` is a small subset of `sharkd`'s API (`load`, `getFrames`, `getFrame`, ...):

```javascript
const lib = await loadWiregasm({ locateFile });
lib.init();
lib.FS.writeFile("/uploads/file.pcap", bytes);
const session = new lib.DissectSession("/uploads/file.pcap");
session.load();
const frames = session.getFrames("", 0, 0);
session.delete(); // embind objects live on the wasm heap until deleted
```

### Upgrading from 1.x
* The `Wiregasm` wrapper methods are camelCase:

  | 1.x | 2.x |
  |---|---|
  | `list_modules` | `listModules` |
  | `list_prefs` | `listPrefs` |
  | `apply_prefs` | `applyPrefs` |
  | `set_pref` | `setPref` |
  | `get_pref` | `getPref` |
  | `test_filter` | `testFilter` |
  | `complete_filter` | `completeFilter` |
  | `reload_lua_plugins` | `reloadLuaPlugins` |
  | `add_plugin` | `addPlugin` |
  | `is_eo_tap` | `isEoTap` |
  | `is_conv_tap` | `isConvTap` |
  | `list_protocols` | `listProtocols` |
  | `set_protocol_enabled` | `setProtocolEnabled` |
  | `set_protocol_enabled_by_name` | `setProtocolEnabledByName` |
  | `list_heuristic_dissectors` | `listHeuristicDissectors` |
  | `set_heuristic_enabled` | `setHeuristicEnabled` |

* Node.js older than 22 is no longer supported.
* `vectorToArray(vec)` frees `vec` after copying its elements (embind vectors live on the wasm heap until deleted). Don't use a vector after converting it.
* Only the documented loader options are read from the object passed to `loadWiregasm`: `locateFile`, `print`, `printErr`, `handleStatus`, `wasmBinary` and `getPreloadedPackage`, plus Emscripten's standard ones such as `instantiateWasm`.

## Contributing

Building, testing, the patch workflow and Wireshark upgrades are described in [CONTRIBUTING.md](CONTRIBUTING.md).

## License
Wiregasm is a derivative work of the [Wireshark](https://github.com/wireshark/wireshark) project and, like Wireshark, is licensed under the **GNU General Public License, version 2 or (at your option) any later version** (`GPL-2.0-or-later`). The full GPLv2 text is in [LICENSE](LICENSE), and each source file carries an `SPDX-License-Identifier: GPL-2.0-or-later` header.

The upstream sources that the build downloads and patches (Wireshark, glib and the other dependencies) keep their own licenses; `patches/` and `overlay/` are modifications to them.
