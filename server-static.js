const http = require('http');
const fs = require('fs');
const path = require('path');

const root = __dirname;
const port = process.env.PORT ? Number(process.env.PORT) : 5500;

const mime = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain'
};

function send(res, status, content, type) {
  res.writeHead(status, { 'Content-Type': type || 'text/plain' });
  res.end(content);
}

const server = http.createServer((req, res) => {
  try {
    let reqPath = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    if (reqPath.endsWith('/')) reqPath += 'index.html';
    const filePath = path.join(root, reqPath);
    // Prevent path traversal outside root
    if (!filePath.startsWith(root)) return send(res, 403, 'Forbidden');
    fs.stat(filePath, (err, stat) => {
      if (err || !stat.isFile()) return send(res, 404, 'Not Found');
      const ext = path.extname(filePath).toLowerCase();
      const type = mime[ext] || 'application/octet-stream';
      fs.readFile(filePath, (err2, data) => {
        if (err2) return send(res, 500, 'Server Error');
        send(res, 200, data, type);
      });
    });
  } catch (e) {
    send(res, 500, 'Server Error');
  }
});

server.listen(port, () => {
  console.log(`Static server running at http://localhost:${port}/`);
});