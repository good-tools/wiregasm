// Minimal static server for the browser e2e test:
//   /            -> e2e/
//   /pkg/...     -> the packed package (e2e/.pkg/package)
//   /samples/... -> samples/
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const port = Number(process.env.PORT ?? 4173);
const TYPES = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".wasm": "application/wasm",
  ".data": "application/octet-stream",
  ".cap": "application/octet-stream",
};

http
  .createServer((req, res) => {
    const url = decodeURIComponent(new URL(req.url, "http://x").pathname);
    let file;
    if (url.startsWith("/pkg/"))
      file = path.join(root, "e2e/.pkg/package", url.slice(5));
    else if (url.startsWith("/samples/")) file = path.join(root, url);
    else file = path.join(root, "e2e", url === "/" ? "index.html" : url);
    if (
      !file.startsWith(root) ||
      !fs.existsSync(file) ||
      fs.statSync(file).isDirectory()
    ) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, {
      "content-type": TYPES[path.extname(file)] ?? "application/octet-stream",
    });
    fs.createReadStream(file).pipe(res);
  })
  .listen(port, () => console.log(`e2e server on http://localhost:${port}`));
