/**
 * SIH26145 AI Threat Detector — Local Dev Server
 * Serves frontend on http://localhost:8080
 * Provides /api/ endpoints with in-memory storage
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');

const PORT = 8080;
const ROOT_DIR = __dirname;  // project root — index.html lives here alongside this file

// ── In-Memory Data Store ──────────────────────────────────────
const db = {
  events: [],
  alerts: [
    { id: randomUUID(), severity: 'critical', title: 'Ransomware C2 beacon detected', source: '10.24.18.42 -> finance-api', status: 'open', ts: new Date(Date.now() - 2 * 60000).toISOString() },
    { id: randomUUID(), severity: 'high', title: 'Unusual outbound data transfer', source: '10.24.33.18 -> external IP', status: 'open', ts: new Date(Date.now() - 18 * 60000).toISOString() },
    { id: randomUUID(), severity: 'medium', title: 'Suspicious authentication pattern', source: 'admin@cloudguard.io', status: 'open', ts: new Date(Date.now() - 42 * 60000).toISOString() },
    { id: randomUUID(), severity: 'high', title: 'Phishing payload blocked', source: 'mail-gateway -> inbox', status: 'resolved', ts: new Date(Date.now() - 3600000).toISOString() },
    { id: randomUUID(), severity: 'medium', title: 'Port scan anomaly detected', source: '172.16.0.88 -> core-vpc', status: 'resolved', ts: new Date(Date.now() - 7200000).toISOString() }
  ],
  devices: [
    { id: 'dev-01', name: 'k8s-prod-worker-01', type: 'server', role: 'Kubernetes Worker Node', ip: '10.0.12.4', mac: '02:42:0a:00:0c:04', vpc: 'prod-vpc-us-east', zone: 'us-east-1a', proto: 'TCP / 10250', in_mb: 412.8, out_mb: 189.4, pps: 2450, status: 'online', os: 'Ubuntu 22.04 LTS (K8s v1.29)', isolated: false },
    { id: 'dev-02', name: 'api-gateway-prod', type: 'gateway', role: 'Envoy Edge API Gateway', ip: '10.0.1.10', mac: '02:42:0a:00:01:0a', vpc: 'dmz-vpc-us-east', zone: 'us-east-1a', proto: 'HTTPS / 443', in_mb: 890.2, out_mb: 742.1, pps: 4890, status: 'online', os: 'Alpine Linux (Envoy Proxy)', isolated: false },
    { id: 'dev-03', name: 'postgres-primary-db', type: 'database', role: 'PostgreSQL DB Primary', ip: '10.0.8.25', mac: '02:42:0a:00:08:19', vpc: 'data-vpc-us-east', zone: 'us-east-1b', proto: 'TCP / 5432', in_mb: 674.3, out_mb: 891.0, pps: 3720, status: 'high-traffic', os: 'Debian 12 (PostgreSQL 16)', isolated: false },
    { id: 'dev-04', name: 'redis-cache-cluster-01', type: 'database', role: 'Redis Cache Cluster', ip: '10.0.4.88', mac: '02:42:0a:00:04:58', vpc: 'data-vpc-us-east', zone: 'us-east-1b', proto: 'TCP / 6379', in_mb: 320.1, out_mb: 210.5, pps: 3100, status: 'online', os: 'Alpine Linux (Redis 7.2)', isolated: false },
    { id: 'dev-05', name: 'auth-service-pod-3b', type: 'server', role: 'Auth Microservice Pod', ip: '10.244.3.15', mac: '02:42:0a:f4:03:0f', vpc: 'prod-vpc-us-east', zone: 'us-east-1a', proto: 'gRPC / 50051', in_mb: 154.6, out_mb: 98.2, pps: 1420, status: 'online', os: 'Go Container (Distroless)', isolated: false },
    { id: 'dev-06', name: 'edge-load-balancer-us', type: 'gateway', role: 'Global Cloud Load Balancer', ip: '192.168.1.1', mac: '52:54:00:12:34:56', vpc: 'edge-anycast-net', zone: 'global-edge', proto: 'HTTP2 / 443', in_mb: 1240.5, out_mb: 1180.2, pps: 6900, status: 'high-traffic', os: 'EdgeOS / Cloudflare Node', isolated: false },
    { id: 'dev-07', name: 'bastion-jump-host', type: 'security', role: 'SSH Bastion Jump Host', ip: '10.0.99.2', mac: '02:42:0a:00:63:02', vpc: 'mgmt-vpc-us-east', zone: 'us-east-1c', proto: 'SSH / 22', in_mb: 45.3, out_mb: 38.1, pps: 410, status: 'online', os: 'Hardened Alpine Linux', isolated: false },
    { id: 'dev-08', name: 'secops-analyst-laptop', type: 'workstation', role: 'Security Analyst Endpoint', ip: '192.168.50.12', mac: 'a4:83:e7:21:bc:44', vpc: 'corp-vpn-pool', zone: 'remote-office', proto: 'HTTPS / 443', in_mb: 68.4, out_mb: 32.7, pps: 580, status: 'online', os: 'macOS Sonoma (SecOps)', isolated: false },
    { id: 'dev-09', name: 'corp-vpn-gateway', type: 'gateway', role: 'WireGuard VPN Gateway', ip: '172.16.0.1', mac: '02:42:ac:10:00:01', vpc: 'vpn-vpc-us-east', zone: 'us-east-1a', proto: 'UDP / 51820', in_mb: 290.4, out_mb: 280.9, pps: 2150, status: 'online', os: 'Linux Kernel (WireGuard)', isolated: false },
    { id: 'dev-10', name: 'iot-telemetry-collector', type: 'security', role: 'IoT Fleet Telemetry Node', ip: '10.0.35.80', mac: '02:42:0a:00:23:50', vpc: 'iot-vpc-us-east', zone: 'us-east-1c', proto: 'MQTT / 8883', in_mb: 185.0, out_mb: 42.1, pps: 1890, status: 'suspicious', os: 'FreeBSD 14 / Mosquitto', isolated: false }
  ],
  reports: [],
  audit: []
};

// ── MIME Types ────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon'
};

// ── Helpers ───────────────────────────────────────────────────
function json(res, status, data) {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => data += chunk);
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); }
      catch { resolve({}); }
    });
  });
}

function serveStatic(res, filePath) {
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404); res.end('Not found');
    } else {
      const ext = path.extname(filePath);
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
      res.end(content);
    }
  });
}

// ── Request Router ────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  const method = req.method;

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,PATCH', 'Access-Control-Allow-Headers': 'Content-Type' });
    return res.end();
  }

  // ── API Routes ──────────────────────────────────────────────
  if (url.startsWith('/api/')) {

    if (url === '/api/health' && method === 'GET') {
      return json(res, 200, { status: 'ok', mode: 'local-memory', timestamp: new Date() });
    }

    if (url === '/api/events' && method === 'GET') {
      return json(res, 200, db.events.slice(-200).reverse());
    }
    if (url === '/api/events' && method === 'POST') {
      const body = await readBody(req);
      const evt = { id: randomUUID(), ...body, ts: new Date().toISOString() };
      db.events.push(evt);
      return json(res, 201, evt);
    }

    if (url === '/api/alerts' && method === 'GET') {
      return json(res, 200, [...db.alerts].reverse());
    }
    if (url === '/api/alerts' && method === 'POST') {
      const body = await readBody(req);
      const alert = { id: randomUUID(), status: 'open', ts: new Date().toISOString(), ...body };
      db.alerts.push(alert);
      return json(res, 201, alert);
    }
    const resolveMatch = url.match(/^\/api\/alerts\/([^/]+)\/resolve$/);
    if (resolveMatch && method === 'PATCH') {
      const found = db.alerts.find(a => a.id === resolveMatch[1]);
      if (!found) return json(res, 404, { error: 'Not found' });
      found.status = 'resolved'; found.resolved_at = new Date().toISOString();
      return json(res, 200, found);
    }

    if (url === '/api/reports' && method === 'GET') {
      return json(res, 200, db.reports.map(r => ({ id: r.id, title: r.title, threat_count: r.threat_count, event_count: r.event_count, model: r.model, created_at: r.created_at })));
    }
    if (url === '/api/reports' && method === 'POST') {
      const body = await readBody(req);
      const report = { id: randomUUID(), created_at: new Date().toISOString(), ...body };
      db.reports.push(report);
      return json(res, 201, report);
    }

    if (url === '/api/audit' && method === 'GET') {
      return json(res, 200, [...db.audit].reverse().slice(0, 500));
    }
    if (url === '/api/audit' && method === 'POST') {
      const body = await readBody(req);
      const entry = { id: randomUUID(), ts: new Date().toISOString(), ...body };
      db.audit.push(entry);
      return json(res, 201, entry);
    }

    if (url === '/api/devices' && method === 'GET') {
      return json(res, 200, db.devices);
    }
    const devMatch = url.match(/^\/api\/devices\/([^/]+)$/);
    if (devMatch && method === 'PATCH') {
      const dev = db.devices.find(d => d.id === devMatch[1]);
      if (!dev) return json(res, 404, { error: 'Device not found' });
      const body = await readBody(req);
      Object.assign(dev, body);
      db.audit.push({
        id: randomUUID(),
        category: 'analyst',
        msg: `Device ${dev.name} (${dev.ip}) updated: ${dev.isolated ? 'ISOLATED' : dev.status.toUpperCase()}`,
        ts: new Date().toISOString()
      });
      return json(res, 200, dev);
    }

    if (url === '/api/stats' && method === 'GET') {
      return json(res, 200, {
        total_events: db.events.length,
        open_alerts: db.alerts.filter(a => a.status === 'open').length,
        active_threats: db.alerts.filter(a => ['critical', 'high'].includes(a.severity) && a.status === 'open').length,
        connected_devices: db.devices.length,
        online_devices: db.devices.filter(d => !d.isolated).length
      });
    }

    return json(res, 404, { error: 'Unknown API route' });
  }

  // ── Static File Serving ─────────────────────────────────────
  if (url.startsWith('/section/')) {
    return serveStatic(res, path.join(ROOT_DIR, 'index.html'));
  }
  let filePath = path.join(ROOT_DIR, url === '/' ? 'index.html' : url);
  // Security: prevent path traversal
  if (!filePath.startsWith(ROOT_DIR)) {
    res.writeHead(403); return res.end('Forbidden');
  }
  serveStatic(res, filePath);
});

server.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════════╗');
  console.log('  ║   🛡  SIH26145 AI Threat Detector Server     ║');
  console.log('  ║                                              ║');
  console.log(`  ║   → http://localhost:${PORT}                   ║`);
  console.log('  ║                                              ║');
  console.log('  ║   API + Frontend running (in-memory DB)      ║');
  console.log('  ║   Press Ctrl+C to stop                       ║');
  console.log('  ╚══════════════════════════════════════════════╝');
  console.log('');
});
