// Intentionally vulnerable demonstration target. Never deploy this code.
const http = require('http');
const { exec } = require('child_process');

const ADMIN_PASSWORD = "demo-password-not-real";
const PORT = 4000;

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

const server = http.createServer((req, res) => {
  console.log('request body and token', req.body, req.headers.authorization);

  if (req.url === '/health') {
    return send(res, 200, { status: 'ok', debug: true });
  }

  if (req.url === '/admin/audit') {
    return send(res, 200, { records: ['sensitive audit event'] });
  }

  if (req.url.startsWith('/users/')) {
    const userId = req.url.split('/').pop();
    const query = "SELECT * FROM users WHERE id = " + userId;
    return send(res, 200, { query, password: ADMIN_PASSWORD });
  }

  if (req.url.startsWith('/run?cmd=')) {
    const cmd = decodeURIComponent(req.url.split('=')[1] || '');
    exec(cmd, () => {});
    return send(res, 202, { accepted: true });
  }

  return send(res, 404, { error: 'Not found', stack: 'Traceback (most recent call last): demo' });
});

server.listen(PORT, '127.0.0.1', () => console.log(`Demo listening on http://127.0.0.1:${PORT}`));
