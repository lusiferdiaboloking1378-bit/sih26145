/* ============================================================
   CloudGuard AI — Real-Time Monitoring Engine
   ============================================================ */

'use strict';

// ── CloudGuard Cloud API ───────────────────────────────────
// Silently syncs data to the backend REST API / PostgreSQL DB.
// All calls are fire-and-forget: they never block the UI.
const CloudGuardAPI = (() => {
  const BASE = '/api';
  const post = (path, body) =>
    fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }).catch(() => { }); // silent — backend may be offline in standalone mode

  const patch = (path) =>
    fetch(`${BASE}${path}`, { method: 'PATCH' }).catch(() => { });

  const get = (path) =>
    fetch(`${BASE}${path}`).then(r => r.ok ? r.json() : []).catch(() => []);

  return {
    /** Save a threat event to the database */
    saveEvent(type, protocol, ip_address, message, score, model) {
      post('/events', { type, protocol, ip_address, message, score, model });
    },
    /** Save an alert/incident to the database, returns a Promise<{id}> */
    saveAlert(severity, title, source) {
      return fetch(`${BASE}/alerts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ severity, title, source })
      }).then(r => r.ok ? r.json() : null).catch(() => null);
    },
    /** Resolve an alert by its DB UUID */
    resolveAlert(dbId) {
      patch(`/alerts/${dbId}/resolve`);
    },
    /** Load alerts from the database */
    loadAlerts() {
      return get('/alerts');
    },
    /** Save an audit log entry */
    saveAudit(category, message) {
      post('/audit', { category, message });
    },
    /** Save a report snapshot */
    saveReport(title, threat_count, event_count, model, payload) {
      post('/reports', { title, threat_count, event_count, model, payload });
    },
    /** Load connected devices from DB/API */
    loadDevices() {
      return get('/devices');
    },
    /** Update connected device status/isolation */
    updateDevice(id, data) {
      return fetch(`${BASE}/devices/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      }).then(r => r.ok ? r.json() : null).catch(() => null);
    },
    /** Check if backend is reachable */
    async isOnline() {
      try {
        const r = await fetch(`${BASE}/health`);
        return r.ok;
      } catch { return false; }
    }
  };
})();

// ── Constants ──────────────────────────────────────────────
const NAV_TITLES = {
  overview: 'Security overview',
  detection: 'Threat detection',
  traffic: 'Network traffic',
  devices: 'Connected cloud devices & infrastructure',
  threatmap: 'Global threat map',
  alerts: 'Security alerts',
  fileupload: 'File upload & threat analysis',
  auditlog: 'Audit log',
  reports: 'Reports & analytics'
};

const MODEL_LABELS = {
  rf: 'Random Forest v2.4',
  svm: 'SVM v1.9',
  xgb: 'XGBoost v3.1',
  iso: 'Isolation Forest v1.2'
};

const MODEL_ACCURACY = { rf: 98.7, svm: 96.1, xgb: 99.1, iso: 94.3 };

const GEO_SOURCES = [
  { city: 'Moscow', country: 'Russia', lat: 55.75, lng: 37.62, flag: '🇷🇺' },
  { city: 'Beijing', country: 'China', lat: 39.90, lng: 116.40, flag: '🇨🇳' },
  { city: 'Seoul', country: 'South Korea', lat: 37.56, lng: 126.97, flag: '🇰🇷' },
  { city: 'Tehran', country: 'Iran', lat: 35.69, lng: 51.39, flag: '🇮🇷' },
  { city: 'Bucharest', country: 'Romania', lat: 44.43, lng: 26.10, flag: '🇷🇴' },
  { city: 'Lagos', country: 'Nigeria', lat: 6.45, lng: 3.39, flag: '🇳🇬' },
  { city: 'São Paulo', country: 'Brazil', lat: -23.54, lng: -46.63, flag: '🇧🇷' },
  { city: 'Amsterdam', country: 'Netherlands', lat: 52.37, lng: 4.90, flag: '🇳🇱' },
  { city: 'Minsk', country: 'Belarus', lat: 53.90, lng: 27.56, flag: '🇧🇾' },
  { city: 'Pyongyang', country: 'North Korea', lat: 39.02, lng: 125.75, flag: '🇰🇵' },
  { city: 'Caracas', country: 'Venezuela', lat: 10.48, lng: -66.87, flag: '🇻🇪' },
  { city: 'Jakarta', country: 'Indonesia', lat: -6.21, lng: 106.84, flag: '🇮🇩' }
];

const TARGETS = {
  'aws-us-east-1': { lat: 39.04, lng: -77.49, label: 'AWS us-east-1 (N. Virginia)', provider: 'AWS' },
  'gcp-us-central1': { lat: 41.26, lng: -95.86, label: 'GCP us-central1 (Iowa)', provider: 'GCP' },
  'azure-westeurope': { lat: 52.37, lng: 4.90, label: 'Azure westeurope (Amsterdam)', provider: 'Azure' },
  'ap-northeast-1': { lat: 35.68, lng: 139.76, label: 'AWS ap-northeast-1 (Tokyo)', provider: 'AWS' }
};
let TARGET = TARGETS['aws-us-east-1'];

const EVENT_TEMPLATES = [
  { type: 'safe', proto: 'HTTPS', msg: 'Normal flow rate · benign HTTPS', score: () => rnd(0.01, 0.09) },
  { type: 'safe', proto: 'DNS', msg: 'Standard DNS query frequency', score: () => rnd(0.02, 0.07) },
  { type: 'safe', proto: 'TCP', msg: 'Typical baseline SYN rate observed', score: () => rnd(0.03, 0.11) },
  { type: 'suspicious', proto: 'TCP', msg: 'High SYN arrival rate · possible scan', score: () => rnd(0.75, 0.89) },
  { type: 'suspicious', proto: 'UDP', msg: 'Unidirectional UDP spike · suspicious flow', score: () => rnd(0.71, 0.85) },
  { type: 'suspicious', proto: 'ICMP', msg: 'Elevated ICMP ping volume', score: () => rnd(0.68, 0.82) },
  { type: 'threat', proto: 'TCP', msg: 'DDoS Anomaly detected via Volumetric Flow rate', score: () => rnd(0.91, 0.99) },
  { type: 'threat', proto: 'TCP', msg: 'Port Scanning probe identified (Unidirectional)', score: () => rnd(0.88, 0.98) },
  { type: 'threat', proto: 'UDP', msg: 'Suspected C2 Beaconing pattern (frequency)', score: () => rnd(0.85, 0.97) },
  { type: 'threat', proto: 'DNS', msg: 'DNS Tunneling activity via frequency analysis', score: () => rnd(0.86, 0.99) },
  { type: 'threat', proto: 'ICMP', msg: 'Unidirectional ICMP Flood Attack', score: () => rnd(0.90, 0.99) }
];

const PROTOCOLS = ['HTTPS', 'DNS', 'SSH', 'HTTP', 'TLS', 'TCP', 'UDP', 'SMTP', 'RDP'];

// ── Helpers ────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const rnd = (a, b) => +(Math.random() * (b - a) + a).toFixed(3);
const rndI = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const pick = arr => arr[rndI(0, arr.length - 1)];
const fmtN = n => Number(n).toLocaleString('en-US');
const fmtT = d => new Intl.DateTimeFormat('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(d);
const fmtRel = d => {
  const s = Math.floor((Date.now() - d) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
};
const randIP = () => `10.${rndI(0, 255)}.${rndI(0, 255)}.${rndI(1, 254)}`;

// ── State ──────────────────────────────────────────────────
const state = {
  incidents: [
    { id: 1, severity: 'critical', title: 'Ransomware C2 beacon detected', source: '10.24.18.42 → finance-api', ts: new Date(Date.now() - 2 * 60000), status: 'open' },
    { id: 2, severity: 'high', title: 'Unusual outbound data transfer', source: '10.24.33.18 → external IP', ts: new Date(Date.now() - 18 * 60000), status: 'open' },
    { id: 3, severity: 'medium', title: 'Suspicious authentication pattern', source: 'admin@cloudguard.io', ts: new Date(Date.now() - 42 * 60000), status: 'open' },
    { id: 4, severity: 'high', title: 'Phishing payload blocked', source: 'mail-gateway → inbox', ts: new Date(Date.now() - 3600000), status: 'resolved' },
    { id: 5, severity: 'medium', title: 'Port scan anomaly detected', source: '172.16.0.88 → core-vpc', ts: new Date(Date.now() - 7200000), status: 'resolved' }
  ],
  nextId: 6,
  events: 2481920,
  threats: 27,
  activeModel: 'rf',
  streamPaused: false,
  settings: { pushNotif: false, sound: false, autoResolve: 60, maxFeed: 20, threshold: 75 },
  notifications: [],
  auditLog: [],
  attackVectors: [],
  countryHits: {},
  throughputHistory: { inbound: Array(30).fill(0), outbound: Array(30).fill(0) },
  activityHistory: Array(24).fill(0).map(() => rndI(5, 85)),
  eventsPerMinBucket: [],
  suspiciousCount: 0,
  totalFeedCount: 0,
  theme: 'dark',
  hackerMode: false,
  uploadLog: [],
  // ── Connected Devices Inventory ──
  devices: [
    { id: 'dev-01', name: 'k8s-prod-worker-01', type: 'server', role: 'Kubernetes Worker Node', ip: '10.0.12.4', mac: '02:42:0a:00:0c:04', vpc: 'prod-vpc-us-east', zone: 'us-east-1a', proto: 'TCP / 10250', in_mb: 412.8, out_mb: 189.4, pps: 2450, status: 'online', os: 'Ubuntu 22.04 LTS (K8s v1.29)', isolated: false, icon: '🖥️' },
    { id: 'dev-02', name: 'api-gateway-prod', type: 'gateway', role: 'Envoy Edge API Gateway', ip: '10.0.1.10', mac: '02:42:0a:00:01:0a', vpc: 'dmz-vpc-us-east', zone: 'us-east-1a', proto: 'HTTPS / 443', in_mb: 890.2, out_mb: 742.1, pps: 4890, status: 'online', os: 'Alpine Linux (Envoy Proxy)', isolated: false, icon: '🌐' },
    { id: 'dev-03', name: 'postgres-primary-db', type: 'database', role: 'PostgreSQL DB Primary', ip: '10.0.8.25', mac: '02:42:0a:00:08:19', vpc: 'data-vpc-us-east', zone: 'us-east-1b', proto: 'TCP / 5432', in_mb: 674.3, out_mb: 891.0, pps: 3720, status: 'high-traffic', os: 'Debian 12 (PostgreSQL 16)', isolated: false, icon: '🗄️' },
    { id: 'dev-04', name: 'redis-cache-cluster-01', type: 'database', role: 'Redis Cache Cluster', ip: '10.0.4.88', mac: '02:42:0a:00:04:58', vpc: 'data-vpc-us-east', zone: 'us-east-1b', proto: 'TCP / 6379', in_mb: 320.1, out_mb: 210.5, pps: 3100, status: 'online', os: 'Alpine Linux (Redis 7.2)', isolated: false, icon: '⚡' },
    { id: 'dev-05', name: 'auth-service-pod-3b', type: 'server', role: 'Auth Microservice Pod', ip: '10.244.3.15', mac: '02:42:0a:f4:03:0f', vpc: 'prod-vpc-us-east', zone: 'us-east-1a', proto: 'gRPC / 50051', in_mb: 154.6, out_mb: 98.2, pps: 1420, status: 'online', os: 'Go Container (Distroless)', isolated: false, icon: '📦' },
    { id: 'dev-06', name: 'edge-load-balancer-us', type: 'gateway', role: 'Global Cloud Load Balancer', ip: '192.168.1.1', mac: '52:54:00:12:34:56', vpc: 'edge-anycast-net', zone: 'global-edge', proto: 'HTTP2 / 443', in_mb: 1240.5, out_mb: 1180.2, pps: 6900, status: 'high-traffic', os: 'EdgeOS / Cloudflare Node', isolated: false, icon: '🌍' },
    { id: 'dev-07', name: 'bastion-jump-host', type: 'security', role: 'SSH Bastion Jump Host', ip: '10.0.99.2', mac: '02:42:0a:00:63:02', vpc: 'mgmt-vpc-us-east', zone: 'us-east-1c', proto: 'SSH / 22', in_mb: 45.3, out_mb: 38.1, pps: 410, status: 'online', os: 'Hardened Alpine Linux', isolated: false, icon: '🔒' },
    { id: 'dev-08', name: 'secops-analyst-laptop', type: 'workstation', role: 'Security Analyst Endpoint', ip: '192.168.50.12', mac: 'a4:83:e7:21:bc:44', vpc: 'corp-vpn-pool', zone: 'remote-office', proto: 'HTTPS / 443', in_mb: 68.4, out_mb: 32.7, pps: 580, status: 'online', os: 'macOS Sonoma (SecOps)', isolated: false, icon: '💻' },
    { id: 'dev-09', name: 'corp-vpn-gateway', type: 'gateway', role: 'WireGuard VPN Gateway', ip: '172.16.0.1', mac: '02:42:ac:10:00:01', vpc: 'vpn-vpc-us-east', zone: 'us-east-1a', proto: 'UDP / 51820', in_mb: 290.4, out_mb: 280.9, pps: 2150, status: 'online', os: 'Linux Kernel (WireGuard)', isolated: false, icon: '🛡️' },
    { id: 'dev-10', name: 'iot-telemetry-collector', type: 'security', role: 'IoT Fleet Telemetry Node', ip: '10.0.35.80', mac: '02:42:0a:00:23:50', vpc: 'iot-vpc-us-east', zone: 'us-east-1c', proto: 'MQTT / 8883', in_mb: 185.0, out_mb: 42.1, pps: 1890, status: 'suspicious', os: 'FreeBSD 14 / Mosquitto', isolated: false, icon: '📡' }
  ],
  deviceFilter: 'all',
  deviceSearch: '',
  deviceInspected: null,
  prevInbound: 45.2,
  prevOutbound: 22.8,
  prevPps: 3400,
  mapSeverity: 'all',
  mapStreamPaused: false
};

// ── Audit Logger ───────────────────────────────────────────
function audit(category, msg) {
  state.auditLog.unshift({ ts: new Date(), category, msg });
  if (state.auditLog.length > 200) state.auditLog.pop();
  if ($('auditlog') && $('auditlog').classList.contains('active')) renderAuditLog('all');
  // ── Persist audit entry to DB ───────────────────────────────
  CloudGuardAPI.saveAudit(category, msg);
}

// ── Toast ──────────────────────────────────────────────────
function showToast(text, type = 'info') {
  const t = $('toast');
  t.textContent = text;
  t.className = `toast show toast-${type}`;
  clearTimeout(t._to);
  t._to = setTimeout(() => t.classList.remove('show'), 3000);
}

// ── Clock ──────────────────────────────────────────────────
function setClock() {
  $('clock').textContent = new Intl.DateTimeFormat('en-US', {
    weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit'
  }).format(new Date());
}

// ── Navigation & Section Routing ────────────────────────────
function switchView(view, updateUrl = true) {
  if (!NAV_TITLES[view]) view = 'overview';

  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === view));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  $('pageTitle').textContent = NAV_TITLES[view] || view;
  window.scrollTo({ top: 0, behavior: 'smooth' });

  if (updateUrl) {
    const targetHash = `#/section/${view}`;
    if (window.location.hash !== targetHash) {
      history.pushState({ view }, '', targetHash);
    }
  }

  if (view === 'threatmap' && !mapState.initialized) initMap();
  if (view === 'traffic') updateTrafficView();
  if (view === 'devices' || view === 'traffic') renderDevices();
  if (view === 'auditlog') renderAuditLog('all');
}

function getViewFromURL() {
  const hash = window.location.hash || '';
  const hashMatch = hash.match(/^#\/?(?:section\/)?([a-z0-9_-]+)/i);
  if (hashMatch && NAV_TITLES[hashMatch[1].toLowerCase()]) {
    return hashMatch[1].toLowerCase();
  }

  const path = window.location.pathname || '';
  const pathMatch = path.match(/^\/?(?:section\/)([a-z0-9_-]+)/i);
  if (pathMatch && NAV_TITLES[pathMatch[1].toLowerCase()]) {
    return pathMatch[1].toLowerCase();
  }

  return 'overview';
}

// ── Incidents & Alerts ─────────────────────────────────────
function renderIncidents() {
  $('incidentList').innerHTML = state.incidents
    .filter(i => i.status === 'open')
    .slice(0, 4)
    .map(item => `<div class="incident">
      <i class="severity ${item.severity}"></i>
      <div><strong>${item.title}</strong><small>${item.source}</small></div>
      <time>${fmtRel(item.ts)}</time>
    </div>`).join('');
  $('alertBadge').textContent = state.incidents.filter(i => i.status === 'open').length;
}

function renderAlerts(filter = 'all') {
  const rows = state.incidents.filter(i =>
    filter === 'all' ? true :
      filter === 'resolved' ? i.status === 'resolved' :
        i.severity === filter
  );
  $('alertRows').innerHTML = rows.length
    ? rows.map(i => `<div class="alert-row">
        <span class="badge ${i.severity}">${i.severity.toUpperCase()}</span>
        <strong>${i.title}</strong>
        <span class="source">${i.source}</span>
        <time>${fmtRel(i.ts)}</time>
        <span class="status-pill ${i.status}">${i.status === 'open' ? '● OPEN' : '✓ RESOLVED'}</span>
        ${i.status === 'open'
        ? `<button class="resolve" data-id="${i.id}">Resolve</button>`
        : '<span></span>'}
      </div>`).join('')
    : '<div class="empty-result"><span>✓</span><div><h3>No matching alerts</h3><p>Your filter has no incidents at this time.</p></div></div>';
}

function addIncident(severity, title, source) {
  const inc = { id: state.nextId++, severity, title, source, ts: new Date(), status: 'open', dbId: null };
  state.incidents.unshift(inc);
  state.threats++;
  $('threatCount').textContent = state.threats;
  $('threatDelta').textContent = state.threats - 27;
  renderIncidents();
  renderAlerts(document.querySelector('.filter.active')?.dataset.filter || 'all');
  pushNotification(`🚨 ${severity.toUpperCase()}: ${title}`, severity);
  audit('alert', `New ${severity} alert: "${title}" from ${source}`);
  // ── Persist to DB ──────────────────────────────────────────
  CloudGuardAPI.saveAlert(severity, title, source).then(saved => {
    if (saved) inc.dbId = saved.id; // store DB UUID for later resolve
  });
}

// ── Notification Center ────────────────────────────────────
function pushNotification(text, sev = 'info') {
  const n = { id: Date.now(), text, sev, ts: new Date() };
  state.notifications.unshift(n);
  if (state.notifications.length > 30) state.notifications.pop();
  renderNotifications();
  $('notifDot').style.display = 'block';
  if (state.settings.pushNotif && 'Notification' in window && Notification.permission === 'granted') {
    new Notification('CloudGuard AI', { body: text });
  }
}

function renderNotifications() {
  const list = $('notifList');
  if (!state.notifications.length) {
    list.innerHTML = '<p class="notif-empty">No notifications</p>';
    return;
  }
  list.innerHTML = state.notifications.slice(0, 15).map(n =>
    `<div class="notif-item notif-${n.sev}">
      <span class="notif-text">${n.text}</span>
      <time>${fmtRel(n.ts)}</time>
    </div>`
  ).join('');
}

// ── Live Event Feed ────────────────────────────────────────
function appendFeed() {
  if (state.streamPaused) return;
  const tpl = pick(EVENT_TEMPLATES);
  const ip = randIP();
  const score = tpl.score();
  const ts = fmtT(new Date());
  const feed = $('eventFeed');
  const line = document.createElement('div');
  line.className = tpl.type;
  line.textContent = `${ts}  [${tpl.proto}]  ${ip}  ${tpl.msg}  ·  score ${score.toFixed(2)}`;
  feed.appendChild(line);

  state.eventsPerMinBucket.push(Date.now());
  state.totalFeedCount++;
  if (tpl.type !== 'safe') state.suspiciousCount++;

  const max = state.settings.maxFeed;
  while (feed.children.length > max) feed.removeChild(feed.firstChild);
  feed.scrollTop = feed.scrollHeight;

  // Update stats
  const oneMin = Date.now() - 60000;
  state.eventsPerMinBucket = state.eventsPerMinBucket.filter(t => t > oneMin);
  $('eventsPerMin').textContent = state.eventsPerMinBucket.length;
  const rate = state.totalFeedCount > 0 ? Math.round(state.suspiciousCount / state.totalFeedCount * 100) : 0;
  $('suspiciousRate').textContent = rate + '%';

  // ── Persist event to DB (threat & suspicious only, to keep volume low) ──
  if (tpl.type !== 'safe') {
    CloudGuardAPI.saveEvent(tpl.type, tpl.proto, ip, tpl.msg, score, MODEL_LABELS[state.activeModel]);
  }

  // Randomly escalate threat to incident
  if (tpl.type === 'threat' && Math.random() < 0.18) {
    const sev = score > 0.93 ? 'critical' : 'high';
    addIncident(sev, tpl.msg, `${ip} → core-vpc`);
    // trigger pipeline alert state
    pipelineFlash();
  }
}

function pipelineFlash() {
  const icon = $('pipelineAlert');
  if (!icon) return;
  icon.textContent = '●';
  icon.style.color = 'var(--orange)';
  setTimeout(() => { icon.textContent = '○'; icon.style.color = ''; }, 2500);
}

// ── Scan ──────────────────────────────────────────────────
function runScan(label = 'Live traffic', parsedRows = null) {
  const model = state.activeModel;
  const acc = MODEL_ACCURACY[model];
  const conf = (acc - 1 + Math.random() * 2).toFixed(1);
  const threat = pick(['Credential access', 'Lateral movement', 'Data exfiltration', 'C2 beacon', 'Privilege escalation']);
  const score = rnd(0.82, 0.99);

  state.events += rndI(250, 900);
  $('eventCount').textContent = fmtN(state.events);

  let parsedHtml = '';
  if (parsedRows) {
    parsedHtml = `<div class="parsed-rows"><p class="eyebrow">PARSED FEATURES · ${parsedRows} rows</p></div>`;
  }

  $('scanResult').innerHTML = `<div class="scan-result">
    <div class="verdict">
      <span class="risk">!</span>
      <div>
        <p class="eyebrow">CLASSIFICATION COMPLETE · ${MODEL_LABELS[model]}</p>
        <h3>${threat} detected in ${label}</h3>
        <p>Behavioural pattern consistent with ${threat.toLowerCase()}. Score: ${score} · Confidence: ${conf}%</p>
        ${parsedHtml}
      </div>
    </div>
    <div class="confidence"><b>${conf}%</b><span>model confidence</span><small class="muted" style="display:block;margin-top:5px">Threshold: ${state.settings.threshold}%</small></div>
  </div>`;

  appendFeed();
  showToast('Scan complete — detection result updated', 'success');
  audit('analyst', `Manual scan run on "${label}" using ${MODEL_LABELS[model]}`);
  addIncident('high', `${threat} detected in ${label}`, `${randIP()} → cloud-infra`);
}

// ── File Upload & CSV Parsing ──────────────────────────────
function handleFileUpload(file) {
  if (!file) return;
  $('fileStatus').textContent = `${file.name} · ${Math.ceil(file.size / 1024)} KB`;
  audit('analyst', `Log file uploaded: ${file.name} (${Math.ceil(file.size / 1024)} KB)`);

  const ext = file.name.split('.').pop().toLowerCase();
  if (ext === 'csv' || ext === 'txt') {
    Papa.parse(file, {
      header: true,
      skipEmptyLines: true,
      complete: result => {
        const rows = result.data.length;
        const cols = result.meta.fields || [];
        const summary = $('parsedSummary');
        summary.hidden = false;
        summary.innerHTML = `<p class="eyebrow">PARSED</p>
          <strong>${fmtN(rows)} rows</strong>
          <small>${cols.slice(0, 5).join(', ')}${cols.length > 5 ? '…' : ''}</small>`;
        showToast(`Parsed ${fmtN(rows)} rows from ${file.name}`, 'success');
        runScan(file.name, rows);
      },
      error: () => runScan(file.name)
    });
  } else {
    runScan(file.name);
  }
}

// ── Chart.js — Activity Chart (Overview) ──────────────────
let activityChartInstance = null;
function initActivityChart() {
  const ctx = $('activityChart');
  if (!ctx) return;
  const labels = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}:00`);
  activityChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Threats',
        data: state.activityHistory,
        backgroundColor: state.activityHistory.map(v => v > 75
          ? 'rgba(255,173,82,0.7)'
          : 'rgba(90,228,210,0.55)'),
        borderColor: state.activityHistory.map(v => v > 75
          ? 'rgba(255,173,82,1)'
          : 'rgba(90,228,210,0.9)'),
        borderWidth: 1,
        borderRadius: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }, tooltip: {
          callbacks: {
            label: c => ` ${c.raw} events`
          }
        }
      },
      scales: {
        x: { grid: { color: 'rgba(158,217,205,0.06)' }, ticks: { color: '#718c87', font: { family: 'DM Mono', size: 9 }, maxTicksLimit: 7 } },
        y: { grid: { color: 'rgba(158,217,205,0.06)' }, ticks: { color: '#718c87', font: { family: 'DM Mono', size: 9 } }, beginAtZero: true }
      }
    }
  });
}

function updateActivityChart(range) {
  if (!activityChartInstance) return;
  const data = range === '7 days'
    ? Array.from({ length: 7 }, () => rndI(20, 150))
    : state.activityHistory;
  const labels = range === '7 days'
    ? ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    : Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}:00`);
  activityChartInstance.data.labels = labels;
  activityChartInstance.data.datasets[0].data = data;
  activityChartInstance.data.datasets[0].backgroundColor = data.map(v =>
    v > 75 ? 'rgba(255,173,82,0.7)' : 'rgba(90,228,210,0.55)');
  activityChartInstance.data.datasets[0].borderColor = data.map(v =>
    v > 75 ? 'rgba(255,173,82,1)' : 'rgba(90,228,210,0.9)');
  activityChartInstance.update('none');
  $('chartTotal').textContent = range === '7 days' ? data.reduce((a, b) => a + b, 0) : state.threats;
}

// ── Chart.js — Throughput Chart (Traffic) ─────────────────
let throughputChartInstance = null;
function initThroughputChart() {
  const ctx = $('throughputChart');
  if (!ctx || throughputChartInstance) return;
  const labels = Array.from({ length: 30 }, (_, i) => `-${29 - i}s`);
  throughputChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        { label: 'Inbound', data: [...state.throughputHistory.inbound], borderColor: 'rgba(90,228,210,0.85)', backgroundColor: 'rgba(90,228,210,0.08)', fill: true, tension: 0.4, pointRadius: 0 },
        { label: 'Outbound', data: [...state.throughputHistory.outbound], borderColor: 'rgba(255,173,82,0.85)', backgroundColor: 'rgba(255,173,82,0.08)', fill: true, tension: 0.4, pointRadius: 0 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { labels: { color: '#8ba49f', font: { family: 'Manrope', size: 11 }, boxWidth: 10 } } },
      scales: {
        x: { grid: { color: 'rgba(158,217,205,0.06)' }, ticks: { color: '#718c87', font: { family: 'DM Mono', size: 9 }, maxTicksLimit: 6 } },
        y: { grid: { color: 'rgba(158,217,205,0.06)' }, ticks: { color: '#718c87', font: { family: 'DM Mono', size: 9 }, callback: v => v + ' MB' }, beginAtZero: true }
      }
    }
  });
}

// ── Chart.js — Weekly Chart (Reports) ────────────────────
let weeklyChartInstance = null;
function initWeeklyChart() {
  const ctx = $('weeklyChart');
  if (!ctx || weeklyChartInstance) return;
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const data = [24, 38, 45, 27, 62, 48, state.threats];
  weeklyChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels: days,
      datasets: [{
        label: 'Threats detected',
        data,
        borderColor: 'rgba(168,148,255,0.9)',
        backgroundColor: 'rgba(168,148,255,0.08)',
        fill: true,
        tension: 0.4,
        pointBackgroundColor: 'rgba(168,148,255,1)',
        pointRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(158,217,205,0.06)' }, ticks: { color: '#718c87', font: { family: 'DM Mono' } } },
        y: { grid: { color: 'rgba(158,217,205,0.06)' }, ticks: { color: '#718c87', font: { family: 'DM Mono' } }, beginAtZero: true }
      }
    }
  });
}

// ── Network Traffic View ───────────────────────────────────
const PROTO_WEIGHTS = { HTTPS: 0.42, DNS: 0.18, SSH: 0.10, HTTP: 0.08, TLS: 0.09, TCP: 0.06, UDP: 0.04, SMTP: 0.02, RDP: 0.01 };
let trafficInterval = null;

function updateTrafficView() {
  initThroughputChart();
  const inb = rnd(12, 95);
  const out = rnd(5, 60);
  const pps = rndI(1200, 8500);
  const anomaly = rnd(0.01, 0.35);

  state.throughputHistory.inbound.push(inb);
  state.throughputHistory.inbound.shift();
  state.throughputHistory.outbound.push(out);
  state.throughputHistory.outbound.shift();

  $('inboundRate').textContent = inb.toFixed(1) + ' MB/s';
  $('outboundRate').textContent = out.toFixed(1) + ' MB/s';
  $('ppsRate').textContent = fmtN(pps);
  $('anomalyScore').textContent = anomaly.toFixed(2);
  $('anomalyScore').className = anomaly > 0.6 ? 'warning' : anomaly > 0.3 ? '' : 'positive';

  if (throughputChartInstance) {
    throughputChartInstance.data.datasets[0].data = [...state.throughputHistory.inbound];
    throughputChartInstance.data.datasets[1].data = [...state.throughputHistory.outbound];
    throughputChartInstance.update('none');
  }

  // Protocol breakdown
  $('protoList').innerHTML = Object.entries(PROTO_WEIGHTS)
    .sort((a, b) => b[1] - a[1])
    .map(([p, w]) => {
      const pct = Math.round(w * 100);
      const color = p === 'RDP' || p === 'SMTP' ? 'var(--orange)' : 'var(--cyan)';
      return `<div class="proto-row">
        <span class="proto-name">${p}</span>
        <div class="proto-bar-wrap"><div class="proto-bar" style="width:${pct}%;background:${color}"></div></div>
        <span class="proto-pct">${pct}%</span>
      </div>`;
    }).join('');

  // Top talkers
  const talkers = Array.from({ length: 5 }, () => ({
    ip: randIP(), bytes: rndI(50, 980), proto: pick(PROTOCOLS), risk: Math.random() > 0.75 ? 'high' : 'low'
  })).sort((a, b) => b.bytes - a.bytes);
  $('topTalkers').innerHTML = talkers.map(t => `<div class="talker-row">
    <span class="talker-ip">${t.ip}</span>
    <span class="proto-badge">${t.proto}</span>
    <div class="talker-bar-wrap"><div class="talker-bar" style="width:${t.bytes / 10}%;background:${t.risk === 'high' ? 'var(--orange)' : 'var(--cyan)'}"></div></div>
    <span class="talker-bytes">${t.bytes} MB</span>
    <span class="talker-risk ${t.risk}">${t.risk === 'high' ? '⚠ HIGH' : '✓ OK'}</span>
  </div>`).join('');
}

// ── Connected Devices Registry ──────────────────────────────
function renderDevices() {
  const listEl = $('deviceList');
  const trafficListEl = $('trafficDeviceList');
  if (!listEl && !trafficListEl) return;

  const q = (state.deviceSearch || '').trim().toLowerCase();
  const filter = state.deviceFilter || 'all';

  const filtered = state.devices.filter(d => {
    if (filter === 'isolated' && !d.isolated) return false;
    if (filter !== 'all' && filter !== 'isolated' && d.type !== filter) return false;

    if (q) {
      const match = (
        (d.name && d.name.toLowerCase().includes(q)) ||
        (d.ip && d.ip.toLowerCase().includes(q)) ||
        (d.mac && d.mac.toLowerCase().includes(q)) ||
        (d.vpc && d.vpc.toLowerCase().includes(q)) ||
        (d.role && d.role.toLowerCase().includes(q)) ||
        (d.os && d.os.toLowerCase().includes(q)) ||
        (d.proto && d.proto.toLowerCase().includes(q)) ||
        (d.zone && d.zone.toLowerCase().includes(q))
      );
      if (!match) return false;
    }
    return true;
  });

  const totalCount = state.devices.length;
  const onlineCount = state.devices.filter(d => !d.isolated && d.status === 'online').length;
  const flaggedCount = state.devices.filter(d => !d.isolated && (d.status === 'suspicious' || d.status === 'high-traffic')).length;
  const isolatedCount = state.devices.filter(d => d.isolated).length;

  if ($('totalDevCount')) $('totalDevCount').textContent = totalCount;
  if ($('onlineDevCount')) $('onlineDevCount').textContent = onlineCount;
  if ($('flaggedDevCount')) $('flaggedDevCount').textContent = flaggedCount;
  if ($('isolatedDevCount')) $('isolatedDevCount').textContent = isolatedCount;
  if ($('deviceBadge')) $('deviceBadge').textContent = totalCount;
  if ($('overviewDevCount')) $('overviewDevCount').textContent = `${totalCount} nodes`;
  if ($('overviewDevSub')) {
    $('overviewDevSub').textContent = `● ${onlineCount} online · ${flaggedCount} flagged`;
  }
  if ($('quarantineSub')) {
    $('quarantineSub').textContent = isolatedCount > 0 ? `⚠ ${isolatedCount} isolated from network` : 'No devices isolated';
    $('quarantineSub').className = isolatedCount > 0 ? 'warning' : 'positive';
  }

  const html = filtered.length === 0 ? `
    <div style="padding: 32px 16px; text-align: center; color: var(--muted); font-size: 13px;">
      No devices found matching "${q || filter}".
    </div>
  ` : filtered.map(dev => {
    const isIso = dev.isolated;
    const maxBw = 1500;
    const bwPct = Math.min(100, Math.round(((dev.in_mb + dev.out_mb) / maxBw) * 100));

    return `
      <div class="device-row ${isIso ? 'isolated' : ''}">
        <!-- 1. Device Hostname & OS -->
        <div class="dev-cell-name">
          <div class="dev-icon-badge">${dev.icon || '🖥️'}</div>
          <div class="dev-name-text">
            <span class="dev-name-title">${dev.name}</span>
            <span class="dev-name-sub" title="${dev.os}">${dev.os}</span>
          </div>
        </div>

        <!-- 2. Role / Category -->
        <div>
          <span class="dev-role-badge">${dev.role}</span>
        </div>

        <!-- 3. IP Address & Port -->
        <div class="dev-ip-cell">
          <strong style="color:var(--cyan);font-family:'DM Mono'">${dev.ip}</strong>
          <div style="font-size:10px;color:var(--muted);font-family:'DM Mono'">${dev.proto}</div>
        </div>

        <!-- 4. MAC / NIC -->
        <div class="dev-mac-cell">
          <span>${dev.mac}</span>
        </div>

        <!-- 5. Connected Network / VPC -->
        <div class="dev-vpc-cell">
          <span class="dev-vpc-badge">☁ ${dev.vpc}</span>
          <span class="dev-vpc-zone">${dev.zone || 'us-east-1'}</span>
        </div>

        <!-- 6. Live Bandwidth -->
        <div class="dev-bw-cell">
          <span class="dev-bw-text">↓${dev.in_mb.toFixed(1)}M  ↑${dev.out_mb.toFixed(1)}M</span>
          <div class="dev-bw-bar"><div class="dev-bw-fill" style="width:${bwPct}%;background:${dev.status === 'high-traffic' ? 'var(--orange)' : dev.status === 'suspicious' ? 'var(--red)' : 'var(--cyan)'}"></div></div>
        </div>

        <!-- 7. Packets -->
        <div class="dev-packets-cell">
          ${fmtN(dev.pps)} pps
        </div>

        <!-- 8. Status -->
        <div>
          <span class="dev-status-pill ${isIso ? 'isolated' : dev.status}">
            ● ${isIso ? 'ISOLATED' : dev.status.toUpperCase()}
          </span>
        </div>

        <!-- 9. Quarantine Action -->
        <div class="dev-actions">
          <button class="dev-btn-isolate ${isIso ? 'reconnect' : ''}" onclick="toggleDeviceIsolation('${dev.id}')">
            ${isIso ? '✓ Reconnect' : '🔒 Isolate'}
          </button>
        </div>
      </div>
    `;
  }).join('');

  if (listEl) listEl.innerHTML = html;
  if (trafficListEl) trafficListEl.innerHTML = html;
}

window.toggleDeviceIsolation = function (id) {
  const dev = state.devices.find(d => d.id === id);
  if (!dev) return;

  dev.isolated = !dev.isolated;
  const act = dev.isolated ? 'QUARANTINED / ISOLATED' : 'RECONNECTED';
  showToast(`${dev.isolated ? '🔒' : '✓'} Device "${dev.name}" (${dev.ip}) is now ${act}`, dev.isolated ? 'warning' : 'success');
  audit('analyst', `Device ${dev.name} [${dev.ip}] was ${act} on network ${dev.vpc}`);

  CloudGuardAPI.updateDevice(id, { isolated: dev.isolated });
  renderDevices();
};

function scanDevices() {
  const btn = $('scanDevicesBtn');
  if (btn) {
    btn.innerHTML = '<span class="spin">⟳</span> Scanning subnets...';
    btn.disabled = true;
  }
  showToast('📡 Broadcasting ARP ping across all VPC networks & subnets...', 'info');

  setTimeout(() => {
    state.devices.forEach(d => {
      d.in_mb = Math.max(10, +(d.in_mb + rnd(-20, 35)).toFixed(1));
      d.out_mb = Math.max(5, +(d.out_mb + rnd(-15, 25)).toFixed(1));
      d.pps = Math.max(200, rndI(d.pps - 200, d.pps + 300));
    });

    renderDevices();
    showToast(`✓ Network ARP scan completed: ${state.devices.length} endpoints responding`, 'success');
    audit('system', `Network discovery scan completed on ${state.devices.length} nodes`);

    if (btn) {
      btn.innerHTML = '<span>⟳</span> Scan network (ARP)';
      btn.disabled = false;
    }
  }, 900);
}

// ── Leaflet Threat Map ─────────────────────────────────────
const mapState = { initialized: false, map: null, markers: [], arcLayer: null };

function initMap() {
  if (mapState.initialized) return;
  mapState.initialized = true;

  const container = $('threatMapContainer');
  container.style.height = '420px';

  mapState.map = L.map('threatMapContainer', {
    center: [20, 10],
    zoom: 2,
    zoomControl: true,
    attributionControl: false
  });

  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '© OpenStreetMap contributors © CARTO',
    subdomains: 'abcd',
    maxZoom: 19
  }).addTo(mapState.map);

  // Target marker
  const targetIcon = L.divIcon({ className: '', html: '<div class="map-marker map-target">🛡</div>', iconSize: [30, 30], iconAnchor: [15, 15] });
  L.marker([TARGET.lat, TARGET.lng], { icon: targetIcon }).addTo(mapState.map).bindPopup(`<b>${TARGET.label}</b><br>Your protected infrastructure`);

  // Initial attack markers
  GEO_SOURCES.forEach(src => addAttackMarker(src));

  // Periodic new attacks
  setInterval(() => {
    const src = pick(GEO_SOURCES);
    addAttackMarker(src);
    updateCountryHits(src);
    updateAttackVectors(src);
  }, 4000);

  renderCountryList();
}

function addAttackMarker(src) {
  const sev = Math.random() > 0.6 ? 'critical' : Math.random() > 0.5 ? 'high' : 'suspicious';
  const color = sev === 'critical' ? '#ff7070' : sev === 'high' ? '#ffad52' : '#5ae4d2';
  const icon = L.divIcon({ className: '', html: `<div class="map-marker" style="background:${color};box-shadow:0 0 12px ${color}"></div>`, iconSize: [12, 12], iconAnchor: [6, 6] });
  const marker = L.marker([src.lat + rnd(-1, 1), src.lng + rnd(-1, 1)], { icon })
    .addTo(mapState.map)
    .bindPopup(`<b>${src.city}, ${src.country}</b><br>Severity: ${sev}<br>Protocol: ${pick(PROTOCOLS)}`);

  // Draw arc to target
  const arcPoints = createArc([src.lat, src.lng], [TARGET.lat, TARGET.lng]);
  const polyline = L.polyline(arcPoints, { color, weight: 1, opacity: 0.5, dashArray: '4,6' }).addTo(mapState.map);

  // Fade and remove after 8s
  setTimeout(() => {
    mapState.map.removeLayer(marker);
    mapState.map.removeLayer(polyline);
  }, 8000);

  updateCountryHits(src);
}

function createArc(from, to, steps = 30) {
  const points = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const lat = from[0] + (to[0] - from[0]) * t;
    const lng = from[1] + (to[1] - from[1]) * t;
    const arc = Math.sin(Math.PI * t) * 20;
    points.push([lat + arc, lng]);
  }
  return points;
}

function updateCountryHits(src) {
  state.countryHits[src.country] = (state.countryHits[src.country] || 0) + 1;
  renderCountryList();
}

function renderCountryList() {
  const sorted = Object.entries(state.countryHits)
    .sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = sorted[0]?.[1] || 1;
  $('countryList').innerHTML = sorted.map(([country, count]) => {
    const src = GEO_SOURCES.find(s => s.country === country);
    const pct = Math.round(count / max * 100);
    return `<div class="country-row">
      <span>${src?.flag || '🌍'} ${country}</span>
      <div class="country-bar-wrap"><div class="country-bar" style="width:${pct}%"></div></div>
      <span class="country-count">${count}</span>
    </div>`;
  }).join('');
}

function updateAttackVectors(src) {
  state.attackVectors.unshift({ src, ts: new Date(), proto: pick(PROTOCOLS), score: rnd(0.6, 0.99) });
  if (state.attackVectors.length > 8) state.attackVectors.pop();
  $('attackVectors').innerHTML = state.attackVectors.map(v => `<div class="vector-row">
    <div class="vector-from">${v.src.flag} ${v.src.city}</div>
    <div class="vector-arrow">→ ${TARGET.label}</div>
    <div class="vector-meta">${v.proto} · ${fmtRel(v.ts)} · <span class="warning">${v.score.toFixed(2)}</span></div>
  </div>`).join('');
}

// ── Audit Log ─────────────────────────────────────────────
function renderAuditLog(filter) {
  document.querySelectorAll('.audit-filter').forEach(b => b.classList.toggle('active', b.dataset.afilter === filter));
  const logs = filter === 'all' ? state.auditLog : state.auditLog.filter(l => l.category === filter);
  $('auditTable').innerHTML = logs.length
    ? logs.map(l => `<div class="audit-row">
        <span class="audit-cat audit-${l.category}">${l.category.toUpperCase()}</span>
        <span class="audit-msg">${l.msg}</span>
        <time class="audit-ts">${fmtT(l.ts)}</time>
      </div>`).join('')
    : '<p class="muted" style="padding:20px">No log entries for this filter.</p>';
}

// ── Settings ──────────────────────────────────────────────
function openSettings() {
  $('settingsOverlay').hidden = false;
  $('pushNotifToggle').checked = state.settings.pushNotif;
  $('soundToggle').checked = state.settings.sound;
  $('autoResolve').value = state.settings.autoResolve;
  $('maxFeed').value = state.settings.maxFeed;
  $('confidenceThreshold').value = state.settings.threshold;
  $('thresholdLabel').textContent = state.settings.threshold + '%';
}
function saveSettings() {
  state.settings.pushNotif = $('pushNotifToggle').checked;
  state.settings.sound = $('soundToggle').checked;
  state.settings.autoResolve = Number($('autoResolve').value);
  state.settings.maxFeed = Number($('maxFeed').value);
  state.settings.threshold = Number($('confidenceThreshold').value);

  // Safely request push notification permission — the Notification API
  // can throw SecurityError on file:// protocol or in restricted contexts.
  if (state.settings.pushNotif) {
    try {
      if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission().catch(() => {
          // Permission denied silently — that's fine
        });
      } else if (!('Notification' in window)) {
        // Browser doesn't support notifications — disable the toggle silently
        state.settings.pushNotif = false;
        $('pushNotifToggle').checked = false;
      }
    } catch (e) {
      // SecurityError on file:// or other restricted origin — disable gracefully
      state.settings.pushNotif = false;
      $('pushNotifToggle').checked = false;
      console.warn('Push notifications not available in this context:', e.message);
    }
  }

  $('settingsOverlay').hidden = true;
  showToast('Settings saved ✓', 'success');
  audit('analyst', 'Settings updated');
}

// ── Theme Toggle ──────────────────────────────────────────
function toggleTheme() {
  state.theme = state.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', state.theme);
  $('themeToggle').textContent = state.theme === 'dark' ? '☾' : '☀';
  audit('analyst', `Theme switched to ${state.theme} mode`);
}

// ── Auto-refresh ──────────────────────────────────────────
let refreshInterval = null;
function setRefreshInterval(ms) {
  if (refreshInterval) clearInterval(refreshInterval);
  if (ms === 0) return;
  refreshInterval = setInterval(() => {
    state.activityHistory.push(rndI(5, 90));
    state.activityHistory.shift();
    updateActivityChart($('chartRange').value);
    updateTrafficMetrics();
    renderIncidents();
  }, ms);
}

function updateTrafficMetrics() {
  const active = document.querySelector('.view.active')?.id;
  if (active === 'traffic') updateTrafficView();
}

// ── Report Download ────────────────────────────────────────
function downloadReport() {
  const report = {
    generatedAt: new Date().toISOString(),
    project: 'CloudGuard AI Threat Detection',
    model: MODEL_LABELS[state.activeModel],
    settings: state.settings,
    metrics: { eventsAnalyzed: state.events, threatsDetected: state.threats, detectionAccuracy: MODEL_ACCURACY[state.activeModel] + '%', responseTime: '1.8 min' },
    incidents: state.incidents.map(i => ({ ...i, ts: i.ts.toISOString() })),
    threatsByCountry: state.countryHits,
    auditSummary: { totalActions: state.auditLog.length, analystActions: state.auditLog.filter(l => l.category === 'analyst').length }
  };
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  link.download = `cloudguard-report-${Date.now()}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
  showToast('Security report downloaded', 'success');
  audit('analyst', 'Full security report exported');
  // ── Persist report snapshot to DB ─────────────────────────
  CloudGuardAPI.saveReport(
    `CloudGuard Report ${new Date().toLocaleDateString()}`,
    state.threats,
    state.events,
    MODEL_LABELS[state.activeModel],
    report
  );
}

// ── Drag & Drop ────────────────────────────────────────────
function initDropzone() {
  const zone = $('dropzone');
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) { $('fileInput').files = e.dataTransfer.files; handleFileUpload(file); }
  });
}

// ── Seeding the feed ──────────────────────────────────────
function seedFeed() {
  const feed = $('eventFeed');
  EVENT_TEMPLATES.slice(0, 6).forEach(tpl => {
    const line = document.createElement('div');
    line.className = tpl.type;
    line.textContent = `${fmtT(new Date())}  [${tpl.proto}]  ${randIP()}  ${tpl.msg}  ·  score ${tpl.score().toFixed(2)}`;
    feed.appendChild(line);
  });
}

// ── Initial audit entries ──────────────────────────────────
function seedAuditLog() {
  const seed = [
    { category: 'system', msg: 'CloudGuard AI started — Random Forest v2.4 loaded' },
    { category: 'system', msg: 'Live event stream connected · 14,320 events/min' },
    { category: 'system', msg: 'Geo-IP database loaded · 32M records' },
    { category: 'alert', msg: 'Critical alert: Ransomware C2 beacon detected on 10.24.18.42' },
    { category: 'alert', msg: 'High alert: Unusual outbound data transfer from 10.24.33.18' },
    { category: 'analyst', msg: 'Analyst Sayyad Ibrahim resolved incident #4 (Phishing payload)' },
    { category: 'analyst', msg: 'Analyst Sayyad Ibrahim resolved incident #5 (Port scan anomaly)' }
  ];
  seed.forEach((e, i) => {
    state.auditLog.push({ ts: new Date(Date.now() - (seed.length - i) * 300000), ...e });
  });
}

// ── Event Wiring ──────────────────────────────────────────
function wireEvents() {
  // Navigation
  document.querySelectorAll('.nav-item').forEach(btn =>
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      switchView(btn.dataset.view, true);
      if (btn.dataset.view === 'reports') { initWeeklyChart(); }
    })
  );
  document.querySelectorAll('[data-go]').forEach(btn =>
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      switchView(btn.dataset.go, true);
    })
  );

  window.addEventListener('hashchange', () => {
    const v = getViewFromURL();
    switchView(v, false);
  });
  window.addEventListener('popstate', (e) => {
    const v = (e.state && e.state.view) || getViewFromURL();
    switchView(v, false);
  });

  // Scan button
  $('scanButton').addEventListener('click', () => {
    runScan('live cloud traffic');
    if (!$('detection').classList.contains('active')) switchView('detection');
  });

  // File upload
  $('chooseFile').addEventListener('click', () => $('fileInput').click());
  $('fileInput').addEventListener('change', e => handleFileUpload(e.target.files[0]));

  // Model selector
  $('modelSelect').addEventListener('change', e => {
    state.activeModel = e.target.value;
    $('activeModelLabel').textContent = MODEL_LABELS[state.activeModel];
    const acc = MODEL_ACCURACY[state.activeModel];
    $('accuracyVal').textContent = acc + '%';
    audit('analyst', `ML model switched to ${MODEL_LABELS[state.activeModel]}`);
    showToast(`Model switched to ${MODEL_LABELS[state.activeModel]}`, 'info');
  });

  // Chart range
  $('chartRange').addEventListener('change', e => updateActivityChart(e.target.value));

  // Alert filters
  document.querySelectorAll('.filter').forEach(btn =>
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderAlerts(btn.dataset.filter);
    })
  );

  // Resolve incident
  $('alertRows').addEventListener('click', e => {
    const id = Number(e.target.dataset.id);
    if (!id) return;
    const inc = state.incidents.find(i => i.id === id);
    if (!inc) return;
    inc.status = 'resolved';
    renderAlerts(document.querySelector('.filter.active').dataset.filter);
    renderIncidents();
    showToast('Incident marked as resolved', 'success');
    audit('analyst', `Incident #${id} resolved: "${inc.title}"`);
  });

  // Download report
  $('downloadReport').addEventListener('click', downloadReport);

  // Notifications
  $('notifBtn').addEventListener('click', () => {
    const dd = $('notifDropdown');
    const open = !dd.hidden;
    dd.hidden = open;
    $('notifBtn').setAttribute('aria-expanded', !open);
    if (!open) { $('notifDot').style.display = 'none'; renderNotifications(); }
  });
  $('clearNotifs').addEventListener('click', () => {
    state.notifications = [];
    renderNotifications();
  });
  document.addEventListener('click', e => {
    if (!$('notifWrap').contains(e.target)) $('notifDropdown').hidden = true;
  });

  // Theme
  $('themeToggle').addEventListener('click', toggleTheme);

  // Settings
  $('settingsBtn').addEventListener('click', openSettings);
  $('closeSettings').addEventListener('click', () => $('settingsOverlay').hidden = true);
  $('saveSettings').addEventListener('click', saveSettings);
  $('settingsOverlay').addEventListener('click', e => { if (e.target === $('settingsOverlay')) $('settingsOverlay').hidden = true; });
  $('confidenceThreshold').addEventListener('input', e => $('thresholdLabel').textContent = e.target.value + '%');

  // Pause stream
  $('pauseStream').addEventListener('click', () => {
    state.streamPaused = !state.streamPaused;
    $('pauseStream').textContent = state.streamPaused ? '▶ Resume' : '⏸ Pause';
    $('streamStatus').innerHTML = state.streamPaused
      ? '<i style="background:var(--orange)"></i> PAUSED'
      : '<i></i> ACTIVE';
    audit('analyst', state.streamPaused ? 'Event stream paused' : 'Event stream resumed');
  });

  // Audit filters
  document.querySelectorAll('.audit-filter').forEach(btn =>
    btn.addEventListener('click', () => renderAuditLog(btn.dataset.afilter))
  );

  // Export audit
  $('exportAudit').addEventListener('click', () => {
    const csv = ['Timestamp,Category,Message',
      ...state.auditLog.map(l => `"${l.ts.toISOString()}","${l.category}","${l.msg}"`)
    ].join('\n');
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    link.download = `cloudguard-audit-${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(link.href);
    showToast('Audit log exported as CSV', 'success');
  });

  // Refresh rate
  $('refreshRate').addEventListener('change', e => {
    setRefreshInterval(Number(e.target.value));
    audit('analyst', `Auto-refresh interval set to ${e.target.value === '0' ? 'off' : e.target.value + 'ms'}`);
  });

  // Device search & filters
  const devSearch = $('deviceSearch');
  if (devSearch) {
    devSearch.addEventListener('input', e => {
      state.deviceSearch = e.target.value;
      renderDevices();
    });
  }

  document.querySelectorAll('.dev-filter').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.dev-filter').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.deviceFilter = btn.dataset.devfilter;
      renderDevices();
    });
  });

  const scanDevBtn = $('scanDevicesBtn');
  if (scanDevBtn) {
    scanDevBtn.addEventListener('click', scanDevices);
  }
}


// ══════════════════════════════════════════════════════════
//  FILE UPLOAD MODULE — Capstone Demo
//  Implements Secure Mode (Branch A) and Hacker Mode (Branch B)
// ══════════════════════════════════════════════════════════

// ── Magic Byte Signatures (first bytes of real file types) ─
const MAGIC_SIGNATURES = {
  'image/jpeg': [[0xFF, 0xD8, 0xFF]],
  'image/png': [[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]],
  'application/pdf': [[0x25, 0x50, 0x44, 0x46]]  // %PDF
};

const ALLOWED_SECURE_MIMES = new Set(['image/jpeg', 'image/png', 'application/pdf']);
const MAX_SECURE_SIZE = 5 * 1024 * 1024; // 5 MB

// ── Generate a cryptographically unpredictable filename ────
function generateSecureId() {
  // crypto.randomUUID() is available in all modern browsers
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  // Fallback: hex from getRandomValues
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return [...buf].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Read first 8 bytes and match magic signatures ──────────
function verifyMagicBytes(file) {
  return new Promise(resolve => {
    const reader = new FileReader();
    reader.onload = e => {
      const bytes = new Uint8Array(e.target.result);
      for (const [mime, signatures] of Object.entries(MAGIC_SIGNATURES)) {
        for (const sig of signatures) {
          if (sig.every((byte, i) => bytes[i] === byte)) {
            return resolve(mime);
          }
        }
      }
      resolve(null); // no matching signature — unknown/spoofed
    };
    reader.onerror = () => resolve(null);
    reader.readAsArrayBuffer(file.slice(0, 8));
  });
}

// ── Simulate upload progress animation ────────────────────
function simulateProgress(onComplete) {
  const wrap = $('uploadProgressWrap');
  const bar = $('uploadProgressBar');
  const lbl = $('uploadProgressLabel');
  wrap.hidden = false;
  bar.style.width = '0%';
  lbl.textContent = 'Processing…';
  let pct = 0;
  const tick = setInterval(() => {
    pct += Math.random() * 22 + 8;
    if (pct >= 100) {
      pct = 100;
      clearInterval(tick);
      lbl.textContent = 'Complete';
      setTimeout(() => { wrap.hidden = true; bar.style.width = '0%'; onComplete(); }, 600);
    }
    bar.style.width = pct + '%';
  }, 120);
}

// ── Core Upload Controller ─────────────────────────────────
async function fileUploadController(file) {
  const hackerMode = state.hackerMode;
  const ts = new Date();
  const fileId = generateSecureId().slice(0, 8).toUpperCase();

  simulateProgress(async () => {
    let entry;

    if (!hackerMode) {
      // ══ BRANCH A — SECURE MODE ══════════════════════════
      // 1. Size check
      if (file.size > MAX_SECURE_SIZE) {
        showToast(`❌ REJECTED — File exceeds 5 MB limit (${(file.size / 1024 / 1024).toFixed(2)} MB)`, 'error');
        audit('upload', `[SECURE] File rejected — size ${(file.size / 1024 / 1024).toFixed(2)} MB exceeds limit: "${file.name}"`);
        renderUploadLog();
        return;
      }

      // 2. Magic-byte MIME verification (do NOT trust extension)
      const detectedMime = await verifyMagicBytes(file);
      if (!detectedMime || !ALLOWED_SECURE_MIMES.has(detectedMime)) {
        const reason = detectedMime ? `invalid type ${detectedMime}` : 'unrecognised magic bytes / spoofed extension';
        showToast(`❌ REJECTED — ${reason}`, 'error');
        audit('upload', `[SECURE] File rejected — ${reason}: "${file.name}"`);
        renderUploadLog();
        return;
      }

      // 3. Cryptographic filename randomisation
      const ext = detectedMime.split('/')[1].replace('jpeg', 'jpg');
      const storedName = `${generateSecureId()}.${ext}`;

      entry = {
        fileId,
        storedName,
        originalName: file.name,
        detectedMime,
        status: 'CLEANED',
        ts
      };

      showToast(`✅ SECURE — "${file.name}" sanitised & stored as ${storedName.slice(0, 18)}…`, 'success');
      audit('upload', `[SECURE] File accepted — MIME ${detectedMime} verified, stored as ${storedName}: original "${file.name}"`);

    } else {
      // ══ BRANCH B — HACKER MODE (BYPASS ALL FILTERS) ═════
      // No size check. No magic-byte check. Preserve original filename.
      entry = {
        fileId,
        storedName: file.name,   // dangerous: original name kept, could be .php/.js etc.
        originalName: file.name,
        detectedMime: 'BYPASSED',
        status: 'VULNERABLE INJECTION',
        ts
      };

      showToast(`⚠ HACKER MODE — "${file.name}" stored WITHOUT sanitisation!`, 'error');
      audit('upload', `[HACKER] All filters BYPASSED — file stored as-is: "${file.name}" — VULNERABLE INJECTION`);
      // Simulate a new critical incident in the dashboard
      addIncident('critical', `Unsanitised file upload — possible injection: ${file.name}`, 'File Upload Module');
    }

    // Write to metadata audit trail
    state.uploadLog.unshift(entry);
    if (state.uploadLog.length > 50) state.uploadLog.pop();
    renderUploadLog();
  });
}

// ── Render Upload Audit Log Table ──────────────────────────
function renderUploadLog() {
  const container = $('uploadLogRows');
  if (!container) return;
  if (!state.uploadLog.length) {
    container.innerHTML = '<div class="upload-log-empty">No files uploaded yet — use the zone above.</div>';
    return;
  }
  container.innerHTML = state.uploadLog.map(e => {
    const isVuln = e.status === 'VULNERABLE INJECTION';
    const badge = isVuln
      ? '<span class="status-badge vuln">⚠ VULNERABLE INJECTION</span>'
      : '<span class="status-badge cleaned">✓ CLEANED</span>';
    const storedDisplay = isVuln
      ? `<span class="vuln-name">${e.storedName}</span>`
      : `<span class="safe-name" title="${e.storedName}">${e.storedName.slice(0, 28)}…</span>`;
    return `<div class="upload-log-row ${isVuln ? 'row-vuln' : 'row-clean'}">
      <span class="log-id">#${e.fileId}</span>
      ${storedDisplay}
      <span>${e.originalName}</span>
      <span class="log-mime">${e.detectedMime}</span>
      ${badge}
      <span class="log-ts">${new Intl.DateTimeFormat('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(e.ts)}</span>
    </div>`;
  }).join('');
}

// ── Hacker Mode Toggle UI Updates ─────────────────────────
function applyHackerModeUI(on) {
  const card = $('uploadCard');
  const banner = $('demoBanner');
  const icon = $('demoBannerIcon');
  const title = $('demoBannerTitle');
  const desc = $('demoBannerDesc');
  const zoneTitle = $('uploadZoneTitle');
  const zoneSub = $('uploadZoneSub');
  const fileInput = $('uploadFileInput');

  if (on) {
    // HACKER MODE — red, no restrictions
    card.classList.add('hacker-mode-active');
    banner.classList.add('banner-hacker');
    banner.classList.remove('banner-secure');
    icon.textContent = '☠';
    title.textContent = 'HACKER MODE — ALL FILTERS BYPASSED';
    desc.textContent = 'No size limit · No MIME check · Original filename preserved · Simulates vulnerable server';
    zoneTitle.textContent = 'Drop ANY file — no restrictions';
    zoneSub.textContent = 'All file types accepted · Simulating vulnerable upload endpoint';
    fileInput.removeAttribute('accept');
  } else {
    // SECURE MODE — green, strict validation
    card.classList.remove('hacker-mode-active');
    banner.classList.remove('banner-hacker');
    banner.classList.add('banner-secure');
    icon.textContent = '🔒';
    title.textContent = 'SECURE MODE ACTIVE';
    desc.textContent = 'Magic-byte MIME verification · 5 MB limit · UUID filename randomisation';
    zoneTitle.textContent = 'Drag & drop file here';
    zoneSub.textContent = 'Allowed: JPG, PNG, PDF · Max 5 MB';
    fileInput.setAttribute('accept', '.jpg,.jpeg,.png,.pdf,image/jpeg,image/png,application/pdf');
  }
}

// ── Wire Upload Module Events ──────────────────────────────
function initUploadModule() {
  applyHackerModeUI(false); // start in secure mode

  const zone = $('uploadZone');
  const fileInput = $('uploadFileInput');
  const browseBtn = $('uploadBrowseBtn');
  const toggle = $('hackerModeToggle');
  const clearBtn = $('clearUploadLog');

  // Browse button
  browseBtn.addEventListener('click', () => fileInput.click());

  // File input change
  fileInput.addEventListener('change', e => {
    const file = e.target.files[0];
    if (file) fileUploadController(file);
    fileInput.value = ''; // reset so same file can be re-uploaded
  });

  // Drag & Drop
  zone.addEventListener('dragover', e => {
    e.preventDefault();
    zone.classList.add('drag-over');
  });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) fileUploadController(file);
  });

  // Hacker Mode Toggle
  toggle.addEventListener('change', () => {
    state.hackerMode = toggle.checked;
    applyHackerModeUI(state.hackerMode);
    if (state.hackerMode) {
      showToast('⚠ HACKER MODE ON — All upload filters disabled!', 'error');
      audit('analyst', 'Demo Presentation Mode ENABLED — upload filters bypassed (HACKER MODE)');
    } else {
      showToast('🔒 SECURE MODE restored', 'success');
      audit('analyst', 'Demo Presentation Mode DISABLED — secure upload restored');
    }
  });

  // Clear log
  clearBtn.addEventListener('click', () => {
    state.uploadLog = [];
    renderUploadLog();
    showToast('Upload log cleared', 'info');
    audit('analyst', 'Upload audit log cleared');
  });
}

// ── Bootstrap ─────────────────────────────────────────────
async function bootstrap() {
  setClock();
  setInterval(setClock, 1000);
  seedFeed();
  seedAuditLog();
  renderIncidents();
  renderAlerts();
  renderDevices();
  initActivityChart();
  initDropzone();
  initUploadModule();
  wireEvents();

  // Route to section specified in URL
  const initialView = getViewFromURL();
  if (initialView && initialView !== 'overview') {
    switchView(initialView, false);
  } else if (!window.location.hash) {
    history.replaceState({ view: 'overview' }, '', '#/section/overview');
  }

  // Live API Polling Loop (Replaces the mock appendFeed simulation)
  setInterval(() => {
    if (state.streamPaused) return;
    fetch('/api/events').then(r => r.json()).then(events => {
      const feed = $('eventFeed');
      if (!feed) return;
      feed.innerHTML = '';
      const toShow = events.slice(0, state.settings.maxFeed).reverse();
      toShow.forEach(evt => {
        const line = document.createElement('div');
        line.className = evt.type || 'safe';
        const ts = new Intl.DateTimeFormat('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(evt.ts || Date.now()));
        line.textContent = `${ts}  [${evt.protocol || 'TCP'}]  ${evt.ip_address || 'LOCAL'}  ${evt.message || ''}  ·  score ${Number(evt.score || 0).toFixed(2)}`;
        feed.appendChild(line);
      });
      feed.scrollTop = feed.scrollHeight;
    }).catch(e => console.error("Error polling events:", e));

    // Also sync alerts from Python ML
    fetch('/api/alerts').then(r => r.json()).then(dbAlerts => {
      let changed = false;
      dbAlerts.forEach(a => {
        if (!state.incidents.find(i => Boolean(i.dbId && i.dbId === a.id))) {
          state.incidents.push({
            id: state.nextId++,
            dbId: a.id,
            severity: a.severity,
            title: a.title,
            source: a.source || 'unknown',
            ts: new Date(a.ts),
            status: a.status
          });
          changed = true;
          pushNotification(`🚨 NEW ${a.severity.toUpperCase()} ALERT: ${a.title}`, a.severity);
        }
      });
      if (changed) {
        state.incidents.sort((a, b) => b.ts - a.ts);
        renderIncidents();
        const activeFilter = document.querySelector('.filter.active');
        renderAlerts(activeFilter ? activeFilter.dataset.filter : 'all');
      }
    }).catch(e => console.error("Error polling alerts:", e));
  }, 2000);

  // Default auto-refresh
  setRefreshInterval(15000);

  // Seed initial notifications
  setTimeout(() => pushNotification('🚨 CRITICAL: Ransomware C2 beacon on 10.24.18.42', 'critical'), 1500);
  setTimeout(() => pushNotification('⚠ HIGH: Unusual outbound transfer detected', 'high'), 3000);
  setTimeout(() => pushNotification('ℹ System: Model Random Forest v2.4 loaded & healthy', 'info'), 4500);

  // Seed country hits
  GEO_SOURCES.slice(0, 5).forEach(s => {
    state.countryHits[s.country] = rndI(1, 12);
  });

  audit('system', 'CloudGuard AI dashboard initialised successfully');

  // ── Load persisted alerts from DB (if backend is available) ──
  const online = await CloudGuardAPI.isOnline();
  if (online) {
    showToast('☁ Connected to CloudGuard cloud storage', 'success');
    const dbAlerts = await CloudGuardAPI.loadAlerts();
    if (dbAlerts.length) {
      // Merge DB alerts, avoiding duplicates by title+source
      const existing = new Set(state.incidents.map(i => i.title + i.source));
      dbAlerts.forEach(a => {
        const key = a.title + (a.source || '');
        if (!existing.has(key)) {
          state.incidents.push({
            id: state.nextId++,
            dbId: a.id,
            severity: a.severity,
            title: a.title,
            source: a.source || 'unknown',
            ts: new Date(a.ts),
            status: a.status
          });
          existing.add(key);
        }
      });
      renderIncidents();
      renderAlerts();
    }

    const dbDevices = await CloudGuardAPI.loadDevices();
    if (dbDevices && Array.isArray(dbDevices) && dbDevices.length) {
      state.devices = dbDevices;
      renderDevices();
    }
  } else {
    showToast('ℹ Running in standalone mode (no DB)', 'info');
  }
}

bootstrap();
