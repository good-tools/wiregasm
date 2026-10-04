// Installs the packed package into a scratch project and uses it the way a
// Node.js consumer would: require() the wrapper and the emscripten loader,
// dissect a capture.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const app = fs.mkdtempSync(path.join(os.tmpdir(), "wiregasm-e2e-"));
fs.writeFileSync(path.join(app, "package.json"), '{"private": true}');
execFileSync(
  "npm",
  [
    "install",
    "--no-audit",
    "--no-fund",
    path.join(root, "e2e/.pkg/package.tgz"),
  ],
  {
    cwd: app,
    stdio: "inherit",
  }
);

fs.writeFileSync(
  path.join(app, "consumer.cjs"),
  `
const fs = require("node:fs");
const { Wiregasm } = require("@goodtools/wiregasm");
const loadWiregasm = require("@goodtools/wiregasm/dist/wiregasm.js");

(async () => {
  const wg = new Wiregasm();
  await wg.init(loadWiregasm, {
    // as documented: point the loader at the package's asset files
    locateFile: (file) => require.resolve("@goodtools/wiregasm/dist/" + file),
    print() {}, printErr() {}, handleStatus() {},
  });
  const loaded = wg.load("http.cap", fs.readFileSync(${JSON.stringify(path.join(root, "samples/http.cap"))}));
  const tree = wg.frame(4).tree;
  const layers = [];
  for (let i = 0; i < tree.size(); i++) layers.push(tree.get(i).filter);
  console.log(JSON.stringify({
    code: loaded.code,
    packets: loaded.summary.packet_count,
    layers,
    httpFrames: wg.frames("http", 0, 0).matched,
  }));
  wg.destroy();
})().catch((e) => { console.error(e); process.exit(1); });
`
);

const result = JSON.parse(
  execFileSync("node", ["consumer.cjs"], { cwd: app, encoding: "utf8" })
);
console.log("node e2e:", result);
assert.equal(result.code, 0);
assert.equal(result.packets, 43);
assert.deepEqual(result.layers.slice(0, 4), ["frame", "eth", "ip", "tcp"]);
assert.ok(result.layers.includes("http"));
assert.ok(result.httpFrames > 0);
fs.rmSync(app, { recursive: true, force: true });
console.log("node e2e: ok");
