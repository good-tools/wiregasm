#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// Checks that mk/deps/*.mk use the library versions Wireshark itself pins for
// its macOS builds (the prebuilt libraries in cmake/modules/FetchArtifacts.cmake,
// at the Wireshark version or commit we build).
//
//   node scripts/dep-versions.mjs          exit 1 on any mismatch
//
// Lua is fetched by Wireshark's own build (FETCH_lua), and libffi is not pinned
// by Wireshark, so neither is checked. gpg-error, pcre2 and libxml2 come inside
// other bundles (or the OS) on macOS, so Wireshark pins no version for them.

import fs from "node:fs";

// Wireshark's artifact path prefix -> our package name in mk/deps/
const PINS = {
  "glib/glib-bundle-": "glib",
  "c-ares/c-ares-": "c-ares",
  "libgcrypt/libgcrypt-bundle-": "gcrypt",
  "nghttp2/nghttp2-": "nghttp2",
};

const read = (pkg, variable) => {
  const mk = fs.readFileSync(`mk/deps/${pkg}.mk`, "utf8");
  return mk.match(new RegExp(`^${pkg}_${variable}\\s*:=\\s*(\\S+)`, "m"))?.[1];
};
const ours = (pkg) => read(pkg, "VERSION");

const wireshark = ours("wireshark");
const ref = read("wireshark", "COMMIT") ?? `v${wireshark}`;
const url = `https://gitlab.com/wireshark/wireshark/-/raw/${ref}/cmake/modules/FetchArtifacts.cmake`;
const res = await fetch(url);
if (!res.ok) {
  console.error(`dep-versions: cannot fetch ${url}: ${res.status}`);
  process.exit(1);
}
const artifacts = await res.text();

let ok = true;
console.log(`Dependency versions vs Wireshark ${wireshark} (${ref}):`);
for (const [prefix, pkg] of Object.entries(PINS)) {
  // e.g. add_artifact(glib/glib-bundle-2.88.3-1-macos-universal.tar.xz <sha256>)
  const escaped = prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pinned = artifacts.match(
    new RegExp(`add_artifact\\(${escaped}([0-9][0-9.]*)-\\d+-macos`)
  )?.[1];
  const have = ours(pkg);
  const same = pinned === have;
  ok &&= same;
  console.log(
    `  ${same ? "ok  " : "DIFF"} ${pkg.padEnd(10)} ours ${have}  wireshark ${pinned}`
  );
}
process.exit(ok ? 0 : 1);
