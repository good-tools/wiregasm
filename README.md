# Wiregasm
![Build](https://github.com/good-tools/wiregasm/actions/workflows/ci.yml/badge.svg?branch=master)
![Build](https://img.shields.io/npm/dm/@goodtools/wiregasm)

Packet Analyzer powered by Wireshark compiled for WebAssembly.

Demo it on [good.tools](https://good.tools/packet-dissector).

## Supported environments
* **Node.js** 22 or later (the maintained LTS lines)
* **Browsers** with WebAssembly BigInt integration and bulk memory (Chrome 85+, Firefox 79+, Safari 15+)

The module is built with Emscripten 6.

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
* Only the documented loader options are read from the object passed to `loadWiregasm`: `locateFile`, `print`, `printErr`, `handleStatus`, `wasmBinary` and `getPreloadedPackage`, plus Emscripten's standard ones such as `instantiateWasm`.

## Build
The library can be built in two ways:
1. `npm run build:emscripten` using a docker image with all of the build tools installed
2. `npm run build:emscripten-local` requires the build environment to be set up. A list of the tools and dependencies can be found in the build [Dockerfile](docker/build.Dockerfile)

After the WASM library is built, the wrapper lib can be built using `npm run build`. The `wiregasm.js` output file produced by the emscripten compiler is not processed by `packer` in the build step and gets added directly to `dist`. This is intentional as it provides consumers to use it for any enviornment they wish, be it nodejs or a browser.

See the [Makefile](Makefile) and [mk/](mk) for how dependencies are built: each one is described in `mk/deps/<pkg>.mk`.

### Patches
Cross-compiling Wireshark for Emscripten/WASM needs changes to Wireshark and to some of its dependencies (glib and libffi were ported by [kleisauke](https://github.com/kleisauke) for wasm-vips). They are kept Brave-style:

* `patches/<pkg>/<path-with-dashes>.patch`: one patch per modified upstream file, starting with a `Why:` line
* `overlay/<pkg>/<path>`: new files, copied into the source tree as-is

To change a dependency:

```sh
make src PKG=wireshark             # build/src/wireshark = upstream + overlay + patches, in git
# edit files under build/src/wireshark (git add any new files), then rebuild with make
make update-patches PKG=wireshark  # write the edits back to patches/ and overlay/
```

To move a dependency to a new version:

```sh
make src PKG=wireshark             # still on the old version
# bump wireshark_VERSION and wireshark_SHA512 in mk/deps/wireshark.mk
make rebase-patches PKG=wireshark  # rebase the patches with git; fix any conflicts in build/src/wireshark
make update-patches PKG=wireshark
```

Library versions follow the ones Wireshark pins for the release we build (`npm run dep-versions` checks them). `make check-patches` verifies that every patch still applies.

## Usage
The Wiregasm `Dissect Session` implementation is effectively a tiny subset of `sharkd` APIs.

| **sharkd** | **Wiregasm** |
|------------|--------------|
| load       | load         |
| frames     | getFrames    |
| frame      | getFrame     |

```javascript
import loadWiregasm from '@goodtools/wiregasm/dist/wiregasm'

// override default locateFile to supply paths to data/wasm files
const wg = await loadWiregasm({
  locateFile: (path, prefix) => {
    if (path.endsWith(".data")) return "path/to/wiregasm.data";
    if (path.endsWith(".wasm")) return "path/to/wiregasm.wasm";
    return prefix + path;
  }
});

// initialize prefs and dissectors
wg.init();

// read file from local FS
const data = await fs.readFile("path/to/file.pcap");

// write file to the virtual emscripten FS
wg.FS.writeFile("/uploads/file.pcap", data);

// create a new dissect session
const sess = new wg.DissectSession("/uploads/file.pcap");

// load the file
const ret = sess.load(); // res.code == 0

// load frames
const filter = "";
const skip = 0;
const limit = 0;
const frames = sess.getFrames(filter, skip, limit);

// get all details including protocol tree for frame
const frame = sess.getFrame(1);

// destroy the session
sess.delete();

// destroy the lib
wg.destroy();
```

To add custom Lua dissectors, add your dissectors to the plugins directory
before initializing wiregasm:

```javascript
// read lua file from local FS
const dissector_data = await fs.readFile("path/to/dissector.lua");

// write lua file to the virtual emscripten FS plugin directory
wg.FS.writeFile("/plugins/dissector.lua", dissector_data)

// initialize and use wiregasm as usual
wg.init();
```

## License
Wiregasm is a derivative work of the [Wireshark](https://github.com/wireshark/wireshark) project, hence it is licensed under the same [GNU GPLv2](LICENSE) license.