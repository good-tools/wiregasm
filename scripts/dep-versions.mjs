#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-or-later
// Checks that mk/deps/*.mk use the library versions Wireshark itself pins
// (tools/macos-setup.sh at the tag of the Wireshark version we build).
//
//   node scripts/dep-versions.mjs          exit 1 on any mismatch
//
// Lua is fetched by Wireshark's own build (FETCH_lua), and libffi is not pinned
// by Wireshark, so neither is checked.

import fs from "node:fs";

// Wireshark's variable name -> our package name in mk/deps/
const PINS = {
  GLIB_VERSION: "glib",
  CARES_VERSION: "c-ares",
  LIBGCRYPT_VERSION: "gcrypt",
  LIBGPG_ERROR_VERSION: "gpg-error",
  PCRE2_VERSION: "pcre",
  NGHTTP2_VERSION: "nghttp2",
  LIBXML2_VERSION: "libxml2",
};

const ours = (pkg) => {
  const mk = fs.readFileSync(`mk/deps/${pkg}.mk`, "utf8");
  return mk.match(new RegExp(`^${pkg}_VERSION\\s*:=\\s*(\\S+)`, "m"))?.[1];
};

const wireshark = ours("wireshark");
const url = `https://gitlab.com/wireshark/wireshark/-/raw/v${wireshark}/tools/macos-setup.sh`;
const res = await fetch(url);
if (!res.ok) {
  console.error(`dep-versions: cannot fetch ${url}: ${res.status}`);
  process.exit(1);
}
const script = await res.text();

let ok = true;
console.log(`Dependency versions vs Wireshark ${wireshark}:`);
for (const [variable, pkg] of Object.entries(PINS)) {
  const pinned = script.match(new RegExp(`^${variable}=(\\S+)`, "m"))?.[1];
  const have = ours(pkg);
  const same = pinned === have;
  ok &&= same;
  console.log(
    `  ${same ? "ok  " : "DIFF"} ${pkg.padEnd(10)} ours ${have}  wireshark ${pinned}`
  );
}
process.exit(ok ? 0 : 1);
