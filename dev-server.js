const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const root = process.cwd();
const port = Number(process.argv[2]) || 8015;

const MIME = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function safeJoin(base, target) {
  const targetPath = path.join(base, target);
  const normal = path.normalize(targetPath);
  if (!normal.startsWith(base)) return null; // prevent path traversal
  return normal;
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url);
  let pathname = decodeURIComponent(parsed.pathname || '/');
  if (pathname.endsWith('/')) pathname += 'index.html';

  let filePath = safeJoin(root, pathname);
  if (!filePath) { res.statusCode = 403; res.end('Forbidden'); return; }

  fs.stat(filePath, (err, stat) => {
    if (err) {
      res.statusCode = 404;
      res.end('Not found');
      return;
    }
    if (stat.isDirectory()) {
      filePath = path.join(filePath, 'index.html');
    }
    fs.readFile(filePath, (err2, data) => {
      if (err2) {
        res.statusCode = 404;
        res.end('Not found');
        return;
      }
      const ext = path.extname(filePath).toLowerCase();
      res.setHeader('Content-Type', MIME[ext] || 'application/octet-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.end(data);
    });
  });
});

server.listen(port, () => {
  console.log(`Static server running at http://localhost:${port}/`);
});