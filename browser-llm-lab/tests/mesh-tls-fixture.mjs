// Local-only TLS transport fixture shared by native and protocol acceptance.
// Test certificates and private keys are deleted by close().
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { resolve, extname, join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execute = promisify(execFile);
export async function createMeshTLSFixture({ root, names = ['gateway-a', 'gateway-b'] }) {
  if (!Array.isArray(names) || !names.length || names.length > 8 || names.some(n => !/^[a-z0-9-]+$/u.test(n))) throw new Error('Invalid fixture hosts');
  const directory = await mkdtemp('/tmp/cypher-mesh-tls-'), hosts = names.map(n => n + '.example.org');
  const gateways = new Map(), sockets = new Set(); let server;
  try {
    await execute('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(directory, 'tls.key'), '-out', join(directory, 'tls.crt'), '-days', '1', '-subj', '/CN=*.example.org', '-addext', 'subjectAltName=' + hosts.map(h => 'DNS:' + h).join(',')], { timeout: 20000 });
    server = https.createServer({ key: await readFile(join(directory, 'tls.key')), cert: await readFile(join(directory, 'tls.crt')) });
    server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
    server.on('request', async (req, res) => {
      const gateway = gateways.get(req.headers.host); if (!gateway) { res.writeHead(404); res.end(); return; }
      if (req.url.startsWith('/relay/')) {
        const upstream = http.request({ hostname: '127.0.0.1', port: gateway.server.address().port, path: req.url, method: req.method, headers: req.headers }, response => { res.writeHead(response.statusCode, response.headers); response.pipe(res); });
        upstream.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); }); req.pipe(upstream); return;
      }
      try {
        const path = new URL(req.url, 'https://' + req.headers.host).pathname;
        if (path === '/') { res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><title>Mesh TLS acceptance</title><body>Independent browser mesh acceptance</body>'); return; }
        const file = resolve(root, 'public', '.' + path); if (!file.startsWith(resolve(root, 'public') + '/')) throw new Error('path');
        const raw = await readFile(file); res.setHeader('Content-Type', extname(file) === '.js' ? 'text/javascript' : 'text/plain'); res.setHeader('Cache-Control', 'no-store'); res.end(raw);
      } catch { res.writeHead(404); res.end(); }
    });
    server.on('upgrade', (req, socket, head) => {
      const gateway = gateways.get(req.headers.host); if (!gateway) { socket.destroy(); return; }
      const upstream = net.connect(gateway.server.address().port, '127.0.0.1'); sockets.add(upstream); upstream.on('close', () => sockets.delete(upstream));
      upstream.on('connect', () => { upstream.write(`${req.method} ${req.url} HTTP/${req.httpVersion}\r\n` + req.rawHeaders.reduce((text, key, i, all) => i % 2 ? text : text + `${key}: ${all[i + 1]}\r\n`, '') + '\r\n'); if (head.length) upstream.write(head); socket.pipe(upstream).pipe(socket); });
      upstream.on('error', () => socket.destroy()); socket.on('error', () => upstream.destroy()); socket.on('close', () => upstream.destroy());
    });
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    const origins = hosts.map(h => `https://${h}:${server.address().port}`);
    let closed = false;
    return { origins, directory, hostResolverRules: hosts.map(h => 'MAP ' + h + ' 127.0.0.1').join(','),
      addGateway(index, gateway) { if (!origins[index] || !gateway.server.address()) throw new Error('Gateway must listen before attaching'); gateways.set(new URL(origins[index]).host, gateway); },
      async close() { if (closed) return; closed = true; for (const socket of sockets) socket.destroy(); await new Promise(r => server.close(r)); await rm(directory, { recursive: true, force: true }); } };
  } catch (error) { for (const socket of sockets) socket.destroy(); if (server?.listening) await new Promise(r => server.close(r)); await rm(directory, { recursive: true, force: true }); throw error; }
}
