#!/usr/bin/env node
// Manages wiregasm's changes to upstream sources, Brave-style: one patch per
// modified upstream file in patches/<pkg>/, new files verbatim in overlay/<pkg>/.
//
//   patches.mjs prepare <pkg> <tarball> <dest>
//     Extract the tarball into <dest> and commit it to a fresh git repo (tag
//     `upstream`). Copy overlay/<pkg>/ in, apply every patches/<pkg>/*.patch
//     with `git apply`, and commit the result (tag `patched`). Every failing
//     patch is reported, not just the first one.
//
//   patches.mjs rebase <pkg> <new-tarball> <dest>
//     Move a prepared <dest> to a new upstream version: commit the new tarball
//     as the new `upstream` and rebase our changes onto it with git. On
//     conflicts, fix them in <dest>, `git add` them and `git rebase
//     --continue`, then run `update`.
//
//   patches.mjs update <pkg> <dest>
//     Regenerate patches/<pkg>/ and overlay/<pkg>/ from <dest>: one patch per
//     file modified since `upstream`, and a copy of every file added since
//     `upstream` (new files must be `git add`ed). The text above the first
//     `diff --git` line of an existing patch (its rationale) is kept.
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
      // The tree may be owned by another user (e.g. root inside `make docker`).
      "-c",
      "safe.directory=*",
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

// Pinned so the output is the same on every machine, whatever the user's
// git config says.
const DIFF_ARGS = [
  "-c",
  "diff.algorithm=histogram",
  "-c",
  "core.quotePath=false",
  "diff",
  "--no-ext-diff",
  "--no-color",
  "--no-renames",
  "--src-prefix=a/",
  "--dst-prefix=b/",
  "--full-index",
  "upstream",
];

function update(pkg, dest) {
  if (!fs.existsSync(path.join(dest, ".git"))) {
    die(`${dest} is not prepared; run \`make src PKG=${pkg}\` first`);
  }
  // Include new files that were `git add`ed but not committed.
  const changed = (filter) =>
    git(
      dest,
      "diff",
      "--name-only",
      "--no-renames",
      `--diff-filter=${filter}`,
      "upstream"
    )
      .split("\n")
      .filter(Boolean);

  const deleted = changed("D");
  if (deleted.length) {
    die(`deleting upstream files is not supported:\n  ${deleted.join("\n  ")}`);
  }

  const patchDir = path.join(root, "patches", pkg);
  const headers = new Map();
  if (fs.existsSync(patchDir)) {
    for (const f of fs
      .readdirSync(patchDir)
      .filter((f) => f.endsWith(".patch"))) {
      const text = fs.readFileSync(path.join(patchDir, f), "utf8");
      const i = text.indexOf("diff --git ");
      if (i > 0) headers.set(f, text.slice(0, i));
      fs.unlinkSync(path.join(patchDir, f));
    }
  }

  const modified = changed("M");
  if (modified.length) fs.mkdirSync(patchDir, { recursive: true });
  for (const file of modified) {
    const name = `${file.replace(/\//g, "-")}.patch`;
    const diff = git(dest, ...DIFF_ARGS, "--", file);
    fs.writeFileSync(
      path.join(patchDir, name),
      (headers.get(name) || "") + diff
    );
  }

  const overlay = path.join(root, "overlay", pkg);
  fs.rmSync(overlay, { recursive: true, force: true });
  const added = changed("A");
  for (const file of added) {
    fs.mkdirSync(path.dirname(path.join(overlay, file)), { recursive: true });
    fs.copyFileSync(path.join(dest, file), path.join(overlay, file));
  }

  // The tree now matches patches/ and overlay/ again.
  git(dest, "add", "-u");
  git(dest, "commit", "-q", "--no-verify", "--allow-empty", "-m", "patched");
  git(dest, "tag", "-f", "patched");

  console.log(
    `patches: ${pkg}: ${modified.length} patches, ${added.length} overlay files`
  );
}

function rebase(pkg, tarball, dest) {
  if (!fs.existsSync(path.join(dest, ".git"))) {
    die(
      `${dest} is not prepared; run \`make src PKG=${pkg}\` before bumping the version`
    );
  }
  if (git(dest, "status", "--porcelain", "--untracked-files=no").trim()) {
    die(
      `${dest} has unexported changes; run \`make update-patches PKG=${pkg}\` first`
    );
  }

  git(dest, "checkout", "-q", "-B", "wiregasm", "patched");
  git(dest, "checkout", "-q", "--detach", "upstream");
  for (const entry of fs.readdirSync(dest)) {
    if (entry !== ".git")
      fs.rmSync(path.join(dest, entry), { recursive: true, force: true });
  }
  execFileSync("tar", ["xf", tarball, "-C", dest, "--strip-components=1"]);
  git(dest, "add", "-A", "-f");
  git(
    dest,
    "commit",
    "-q",
    "--no-verify",
    "--allow-empty",
    "-m",
    "upstream (new)"
  );
  const newUpstream = git(dest, "rev-parse", "HEAD").trim();
  const oldUpstream = git(dest, "rev-parse", "upstream").trim();
  // From here on, `update` diffs against the new version.
  git(dest, "tag", "-f", "upstream", newUpstream);

  git(dest, "checkout", "-q", "wiregasm");
  try {
    git(dest, "rebase", "-q", "--onto", newUpstream, oldUpstream, "wiregasm");
  } catch {
    const conflicts = git(
      dest,
      "diff",
      "--name-only",
      "--diff-filter=U"
    ).trim();
    die(
      `conflicts rebasing ${pkg} onto the new version:\n  ${conflicts.split("\n").join("\n  ")}\n` +
        `Fix them in ${dest}, \`git add\` them and run \`git rebase --continue\` there,\n` +
        `then \`make update-patches PKG=${pkg}\`.`
    );
  }
  git(dest, "tag", "-f", "patched");
  console.log(
    `patches: ${pkg} rebased cleanly; now run \`make update-patches PKG=${pkg}\``
  );
}

const [cmd, ...args] = process.argv.slice(2);
if (cmd === "prepare" && args.length === 3) {
  prepare(...args);
} else if (cmd === "rebase" && args.length === 3) {
  rebase(...args);
} else if (cmd === "update" && args.length === 2) {
  update(...args);
} else {
  die(
    "usage: patches.mjs prepare <pkg> <tarball> <dest>\n       patches.mjs rebase <pkg> <new-tarball> <dest>\n       patches.mjs update <pkg> <dest>"
  );
}
