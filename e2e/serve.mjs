// SPDX-License-Identifier: GPL-2.0-or-later
// Minimal static server for the browser e2e test, on 127.0.0.1 only:
//   /            -> e2e/
//   /pkg/...     -> the packed package (e2e/.pkg/package)
//   /samples/... -> samples/
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const port = Number(process.env.PORT ?? 4173);
const MOUNTS = [
  ["/pkg/", path.join(root, "e2e/.pkg/package")],
  ["/samples/", path.join(root, "samples")],
  ["/", path.join(root, "e2e")],
];
const TYPES = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".wasm": "application/wasm",
};

// Resolve a request path inside its mount; null if it would escape it.
function resolve(urlPath) {
  for (const [prefix, base] of MOUNTS) {
    if (!urlPath.startsWith(prefix)) continue;
    const file = path.resolve(base, `.${urlPath.slice(prefix.length - 1)}`);
    const rel = path.relative(base, file);
    if (rel.startsWith("..") || path.isAbsolute(rel)) return null;
    return rel === "" ? path.join(base, "index.html") : file;
  }
  return null;
}

http
  .createServer((req, res) => {
    let file;
    try {
      file = resolve(decodeURIComponent(new URL(req.url, "http://x").pathname));
    } catch {
      file = null;
    }
    if (!file || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, {
      "content-type": TYPES[path.extname(file)] ?? "application/octet-stream",
    });
    fs.createReadStream(file).pipe(res);
  })
  .listen(port, "127.0.0.1", () =>
    console.log(`e2e server on http://127.0.0.1:${port}`)
  );
