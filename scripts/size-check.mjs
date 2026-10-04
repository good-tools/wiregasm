#!/usr/bin/env node
// Fails if built/bin/wiregasm.{wasm,data}, gzipped, grew more than the budget
// compared to the latest release published on npm.
//
//   node scripts/size-check.mjs [budget]   (default 0.10 = +10%)
//
// Prints a markdown table, also appended to $GITHUB_STEP_SUMMARY in CI.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";

const PACKAGE = "@goodtools/wiregasm";
const FILES = ["wiregasm.wasm", "wiregasm.data"];
const budget = Number(process.argv[2] ?? 0.1);

const meta = await (
  await fetch(`https://registry.npmjs.org/${PACKAGE}/latest`)
).json();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wiregasm-size-"));
const tgz = path.join(tmp, "package.tgz");
fs.writeFileSync(
  tgz,
  Buffer.from(await (await fetch(meta.dist.tarball)).arrayBuffer())
);
execFileSync("tar", ["xzf", tgz, "-C", tmp]);

const gzipped = (file) => zlib.gzipSync(fs.readFileSync(file)).length;
const kb = (n) => `${(n / 1024).toFixed(0)} KiB`;
const pct = (a, b) =>
  `${a >= b ? "+" : ""}${(((a - b) / b) * 100).toFixed(1)}%`;

let before = 0;
let after = 0;
const rows = FILES.map((f) => {
  const b = gzipped(path.join(tmp, "package", "dist", f));
  const a = gzipped(path.join("built", "bin", f));
  before += b;
  after += a;
  return `| ${f} | ${kb(b)} | ${kb(a)} | ${pct(a, b)} |`;
});

const ok = after <= before * (1 + budget);
const report = [
  `### Wasm size (gzipped) vs ${PACKAGE}@${meta.version}`,
  "",
  "| file | release | this build | change |",
  "|---|---|---|---|",
  ...rows,
  `| **total** | ${kb(before)} | ${kb(after)} | **${pct(after, before)}** |`,
  "",
  ok
    ? `Within the +${budget * 100}% budget.`
    : `**Over the +${budget * 100}% budget.** Raise it in this PR only with a reason.`,
  "",
].join("\n");

console.log(report);
if (process.env.GITHUB_STEP_SUMMARY) {
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, report);
}
fs.rmSync(tmp, { recursive: true, force: true });
process.exit(ok ? 0 : 1);
