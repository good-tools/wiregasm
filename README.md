# Wiregasm
![Build](https://github.com/good-tools/wiregasm/actions/workflows/ci.yml/badge.svg?branch=master)
![Build](https://img.shields.io/npm/dm/@goodtools/wiregasm)

Packet Analyzer powered by Wireshark compiled for WebAssembly.

Demo it on [good.tools](https://good.tools/packet-dissector).

## Build
The library can be built in two ways:
1. `npm run build:emscripten` using a docker image with all of the build tools installed
2. `npm run build:emscripten-local` requires the build environment to be set up. A list of the tools and dependencies can be found in the build [Dockerfile](docker/build.Dockerfile)

After the WASM library is built, the wrapper lib can be built using `npm run build`. The `wiregasm.js` output file produced by the emscripten compiler is not processed by `packer` in the build step and gets added directly to `dist`. This is intentional as it provides consumers to use it for any enviornment they wish, be it nodejs or a browser.

See [lib/Makefile](lib/Makefile) for more information on how dependencies are built.

### Patches
Cross-compiling Wireshark for emscripten/WASM isn't straightforward as it also depends on several other libraries to make it work, and those libraries also need to be ported to emscripten.

* libffi
  * https://github.com/libffi/libffi/compare/v3.4.4...kleisauke:wasm-vips.patch by [kleisauke](https://github.com/kleisauke)
* glib
  * https://github.com/GNOME/glib/compare/2.75.0...kleisauke:wasm-vips-2.75.0.patch by [kleisauke](https://github.com/kleisauke)
* wireshark
  * `0001-dont-build-radiotap-lemon.patch`
    * Disables building `Lemon` - Wireshark builds the tool and uses it to process files within the build process. Instead of building it, we provide it externally.
    * Disables building `radiotap` subdir - It has a dependency on `libpcap`
  * `0002-fix-cpu-name-unknown.patch` - Fix compilation error for undefined `model_name` variable
  * `0003-disable-snort-emscripten.patch` - Disable the Snort dissector
  * `0004-export-wireshark-common.patch` - Expose some headers and objects that are not part of `epan`
  * `0005-force-data-dir.patch` - Force `/wireshark` as the data directory. It is needed for loading preferences, profiles and color filters
  * `0006-threadless-registration.patch` - Makes dissector registrations threadless

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

## License
Wiregasm is a derivative work of the [Wireshark](https://github.com/wireshark/wireshark) project, hence it is licensed under the same [GNU GPLv2](LICENSE) license.