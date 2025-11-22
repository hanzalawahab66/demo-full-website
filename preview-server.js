const http = require('http');
const fs = require('fs');
const path = require('path');

const root = process.cwd();
const port = process.env.PORT ? Number(process.env.PORT) : 5510;

const mime = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon'
};

const server = http.createServer((req, res) => {
  try {
    let urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
    if (urlPath === '/') urlPath = '/home.html';
    const safePath = urlPath.replace(/^[\\/]+/, '');
    const filePath = path.join(root, safePath);
    if (!filePath.startsWith(root)) {
      res.writeHead(403);
      return res.end('Forbidden');
    }
    fs.stat(filePath, (err, stat) => {
      if (err) {
        // Extensionless fallback: try adding .html for routes like /inventory
        if (!path.extname(filePath)) {
          const htmlFallback = `${filePath}.html`;
          return fs.stat(htmlFallback, (err2, stat2) => {
            if (err2 || !stat2 || !stat2.isFile()) {
              res.writeHead(404);
              return res.end('Not found');
            }
            fs.readFile(htmlFallback, (readErr, data) => {
              if (readErr) {
                res.writeHead(500);
                return res.end('Server error');
              }
              res.writeHead(200, { 'Content-Type': mime['.html'] });
              return res.end(data);
            });
          });
        }
        res.writeHead(404);
        return res.end('Not found');
      }
      if (stat.isDirectory()) {
        const indexHtml = path.join(filePath, 'index.html');
        fs.readFile(indexHtml, (e, data) => {
          if (e) {
            res.writeHead(404);
            return res.end('Not found');
          }
          res.writeHead(200, { 'Content-Type': mime['.html'] });
          res.end(data);
        });
      } else {
        fs.readFile(filePath, (e, data) => {
          if (e) {
            res.writeHead(500);
            return res.end('Server error');
          }
          const ext = path.extname(filePath).toLowerCase();
          res.writeHead(200, { 'Content-Type': mime[ext] || 'application/octet-stream' });
          res.end(data);
        });
      }
    });
  } catch (e) {
    res.writeHead(500);
    res.end('Server error');
  }
});

server.listen(port, () => {
  console.log(`Preview at http://localhost:${port}/`);
});