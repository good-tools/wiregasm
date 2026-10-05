// SPDX-License-Identifier: GPL-2.0-or-later
// Loads the packed @goodtools/wiregasm in a browser the way an app would,
// dissects samples/http.cap and publishes a summary on window.result.
import { Wiregasm } from "/pkg/dist/module.js";

const toArray = (vec) =>
  Array.from({ length: vec.size() }, (_, i) => vec.get(i));

try {
  const wg = new Wiregasm();
  await wg.init(globalThis.loadWiregasm, {
    locateFile: (path) => `/pkg/dist/${path}`,
    print: () => {},
    printErr: () => {},
    handleStatus: () => {},
  });

  const capture = new Uint8Array(
    await (await fetch("/samples/http.cap")).arrayBuffer()
  );
  const loaded = wg.load("http.cap", capture);
  const frames = wg.frames("", 0, 0);
  const frame = wg.frame(4);

  window.result = {
    version: wg.lib.wiresharkVersion(),
    code: loaded.code,
    packets: loaded.summary.packet_count,
    firstRow: toArray(frames.frames.get(0).columns),
    layers: toArray(frame.tree).map((t) => t.filter),
    httpFrames: wg.frames("http", 0, 0).matched,
  };
} catch (e) {
  window.result = { error: String(e?.stack ?? e) };
}
document.getElementById("out").textContent = JSON.stringify(
  window.result,
  null,
  2
);
