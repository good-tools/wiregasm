#!/usr/bin/env node
// Applies wiregasm's changes to an upstream source tarball.
//
//   patches.mjs prepare <pkg> <tarball> <dest>
//
// The tarball is extracted into <dest> and committed to a fresh git repo
// (tag `upstream`). Then overlay/<pkg>/ is copied in, every
// patches/<pkg>/*.patch is applied with `git apply`, and the result is
// committed (tag `patched`). Every failing patch is reported, not just the
// first one.
//
// Runs on the Node bundled with emsdk (14.x), so it only uses old APIs.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(
  path.dirname(new URL(import.meta.url).pathname),
  ".."
);

function git(cwd, ...args) {
  return execFileSync(
    "git",
    [
      "-c",
      "user.name=wiregasm",
      "-c",
      "user.email=wiregasm@localhost",
      ...args,
    ],
    { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
  );
}

function die(msg) {
  console.error(`patches: ${msg}`);
  process.exit(1);
}

function copyTree(src, dest) {
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const from = path.join(src, entry.name);
    const to = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      fs.mkdirSync(to, { recursive: true });
      copyTree(from, to);
    } else {
      fs.copyFileSync(from, to);
    }
  }
}

function prepare(pkg, tarball, dest) {
  // Refuse to throw away edits that haven't been exported to patches yet.
  if (fs.existsSync(path.join(dest, ".git"))) {
    const dirty = git(dest, "status", "--porcelain", "--untracked-files=no");
    if (dirty.trim()) {
      die(
        `${dest} has unexported changes:\n${dirty}` +
          `Export them with \`make update-patches PKG=${pkg}\`, or discard with \`rm -rf ${dest}\`.`
      );
    }
  }

  fs.rmSync(dest, { recursive: true, force: true });
  fs.mkdirSync(dest, { recursive: true });
  execFileSync("tar", ["xf", tarball, "-C", dest, "--strip-components=1"]);

  git(dest, "init", "-q");
  // -f: tarballs ship files their own .gitignore excludes (generated sources).
  git(dest, "add", "-A", "-f");
  git(dest, "commit", "-q", "--no-verify", "-m", "upstream");
  git(dest, "tag", "upstream");

  const overlay = path.join(root, "overlay", pkg);
  if (fs.existsSync(overlay)) copyTree(overlay, dest);

  const patchDir = path.join(root, "patches", pkg);
  const patches = fs.existsSync(patchDir)
    ? fs
        .readdirSync(patchDir)
        .filter((f) => f.endsWith(".patch"))
        .sort()
    : [];
  const failed = [];
  for (const p of patches) {
    try {
      git(dest, "apply", "--whitespace=nowarn", path.join(patchDir, p));
    } catch (e) {
      failed.push(`  ${p}\n${String(e.stderr).replace(/^/gm, "    ")}`);
    }
  }
  if (failed.length) {
    die(
      `${failed.length}/${patches.length} patches failed for ${pkg}:\n${failed.join("\n")}`
    );
  }

  git(dest, "add", "-A", "-f");
  git(dest, "commit", "-q", "--no-verify", "--allow-empty", "-m", "patched");
  git(dest, "tag", "patched");
  console.log(`patches: ${pkg} prepared (${patches.length} patches)`);
}

const [cmd, ...args] = process.argv.slice(2);
if (cmd === "prepare" && args.length === 3) {
  prepare(...args);
} else {
  die("usage: patches.mjs prepare <pkg> <tarball> <dest>");
}
