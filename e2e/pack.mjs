// SPDX-License-Identifier: GPL-2.0-or-later
// npm pack the package (as it would be published) into e2e/.pkg and unpack it.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const dir = path.resolve(import.meta.dirname, ".pkg");
fs.rmSync(dir, { recursive: true, force: true });
fs.mkdirSync(dir);
const [{ filename }] = JSON.parse(
  execFileSync("npm", ["pack", "--json", "--pack-destination", dir], {
    encoding: "utf8",
  })
);
execFileSync("tar", ["xzf", path.join(dir, filename), "-C", dir]);
fs.renameSync(path.join(dir, filename), path.join(dir, "package.tgz"));
console.log(`packed ${filename}`);
