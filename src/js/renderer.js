const api = window.electronAPI;

let selectedServerId = null;
let securityStatus = null;
let bootstrapStatus = null;
let vpnConnected = false;
let connections = [];
let classifiedConnections = [];
let geoCache = {};
let logLines = [];
let lastProcesses = [];
let activeProtection = { enabled: false, blockedIps: [] };
let protectionAlerts = [];

window.addEventListener('DOMContentLoaded', async () => {
  setupWindowControls();
  setupNavigation();
  setupFilters();
  setupProcessScanner();
  setupVPNActions();
  setupAssistant();
  setupSettings();

  const settings = await api.loadSettings();
  document.getElementById('scan-interval').value = String(settings.scanIntervalMs || 4000);
  document.getElementById('config-path').textContent = settings.vpnConfigDir;
  activeProtection = await api.getActiveProtectionStatus();
  renderActiveProtection();

  const sysInfo = await api.getSystemInfo();
  renderSystemGlance(sysInfo);

  const myIp = await api.getMyIp();
  document.getElementById('my-ip').textContent = myIp || 'N/A';
  document.getElementById('vpn-current-ip').textContent = myIp || 'N/A';

  bootstrapStatus = await api.getBootstrapStatus();
  renderBootstrapStatus(bootstrapStatus);

  await Promise.all([loadVpnServers(), refreshSecurityStatus()]);

  if (!bootstrapStatus.bootstrapCompletedAt || !bootstrapStatus.wireguardInstalled) {
    addLog('Primo avvio o componenti mancanti: avvio preparazione automatica.', 'warn');
    await runBootstrap(true);
  } else {
    addLog('Applicazione avviata: controlli locali attivi.', 'ok');
  }

  api.onNetworkUpdate(handleNetworkUpdate);

  document.getElementById('refresh-btn').addEventListener('click', () => renderMonitorTable(classifiedConnections));
  document.getElementById('refresh-security-btn').addEventListener('click', refreshSecurityStatus);
  document.getElementById('open-vpn-dir-btn').addEventListener('click', () => api.openPath(document.getElementById('config-path').textContent));
  document.getElementById('bootstrap-btn').addEventListener('click', () => runBootstrap(false));
  document.getElementById('active-protection-toggle').addEventListener('change', async (event) => {
    activeProtection = await api.setActiveProtection(event.target.checked);
    renderActiveProtection();
    addLog(`Protezione attiva ${activeProtection.enabled ? 'abilitata' : 'disabilitata'}.`, activeProtection.enabled ? 'ok' : 'warn');
  });
});

function setupWindowControls() {
  document.getElementById('tb-min').onclick = () => api.minimize();
  document.getElementById('tb-max').onclick = () => api.maximize();
  document.getElementById('tb-close').onclick = () => api.close();
}

function setupNavigation() {
  document.querySelectorAll('.nav-btn').forEach((button) => {
    button.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((section) => section.classList.remove('active'));
      document.querySelectorAll('.nav-btn').forEach((entry) => entry.classList.remove('active'));
      document.getElementById(`tab-${button.dataset.tab}`)?.classList.add('active');
      button.classList.add('active');
    });
  });
}

function setupFilters() {
  document.getElementById('ip-filter').addEventListener('input', () => renderMonitorTable(classifiedConnections));
  document.getElementById('show-suspicious-only').addEventListener('change', () => renderMonitorTable(classifiedConnections));
}

async function runBootstrap(silent) {
  const button = document.getElementById('bootstrap-btn');
  button.disabled = true;
  button.textContent = 'Preparazione...';

  const result = await api.runBootstrap();
  bootstrapStatus = result.status;
  renderBootstrapResult(result);
  renderBootstrapStatus(bootstrapStatus);
  await refreshSecurityStatus();

  if (!silent) {
    addLog(result.note, result.success ? 'ok' : 'warn');
  }

  button.disabled = false;
  button.textContent = 'Installa e prepara';
}

function renderBootstrapStatus(status) {
  const summary = document.getElementById('bootstrap-summary');
  if (!status) {
    summary.textContent = 'Stato bootstrap non disponibile.';
    return;
  }

  if (status.wireguardInstalled) {
    summary.textContent = status.vpnConfigCount > 0
      ? `Sistema preparato. WireGuard installato e ${status.vpnConfigCount} configurazioni VPN presenti.`
      : 'WireGuard installato. Manca ancora almeno un file .conf del provider VPN.';
  } else {
    summary.textContent = 'WireGuard non ancora installato. Ion Security puo installarlo automaticamente.';
  }
}

function renderBootstrapResult(result) {
  const steps = document.getElementById('bootstrap-steps');
  steps.innerHTML = result.steps.map((step) => `
    <div class="issue-row ${step.ok ? 'success' : ''}">
      <strong>${step.name}</strong>: ${escapeHtml(step.details)}
    </div>
  `).join('');
}

function renderActiveProtection() {
  const toggle = document.getElementById('active-protection-toggle');
  const label = document.getElementById('active-protection-label');
  const copy = document.getElementById('active-protection-copy');
  toggle.checked = Boolean(activeProtection.enabled);
  label.textContent = activeProtection.enabled ? 'Protezione attiva ON' : 'Protezione attiva OFF';
  copy.textContent = activeProtection.enabled
    ? `Ion Security blocca automaticamente gli IP remoti classificati ad alto rischio. IP bloccati: ${activeProtection.blockedIps.length}.`
    : 'Quando e disattiva, l app mostra gli IP sospetti ma non prova a bloccarli automaticamente.';
}

async function refreshSecurityStatus() {
  securityStatus = await api.getSecurityStatus();
  vpnConnected = Boolean(securityStatus?.vpn?.connected);
  renderSecurityStatus();
  renderVpnStatus(await api.getVpnStatus());
}

function renderSecurityStatus() {
  if (!securityStatus) return;

  const allGood = securityStatus.issues.length === 0;
  document.getElementById('security-score').textContent = securityStatus.score;
  document.getElementById('overall-chip').textContent = allGood ? 'Dispositivo protetto' : 'Azioni richieste';
  document.getElementById('overall-chip').className = `status-chip ${allGood ? 'good' : 'warn'}`;
  document.getElementById('hero-summary').textContent = allGood
    ? 'I controlli principali risultano attivi e il sistema appare ben protetto.'
    : `Ci sono ${securityStatus.issues.length} punti da sistemare per migliorare la protezione reale del PC.`;

  setMetric('defender', securityStatus.defender.enabled && securityStatus.defender.realtime ? 'Attivo' : 'Critico', securityStatus.defender.enabled ? `Realtime ${securityStatus.defender.realtime ? 'attiva' : 'spenta'}${securityStatus.defender.signaturesAge !== null ? `, firme di ${securityStatus.defender.signaturesAge} giorni.` : '.'}` : 'Microsoft Defender non attivo.');
  setMetric('firewall', securityStatus.firewall.allEnabled ? 'Attivo' : 'Critico', securityStatus.firewall.allEnabled ? 'Tutti i profili firewall risultano attivi.' : 'Almeno un profilo firewall e disattivato.');
  setMetric('vpn', securityStatus.vpn.connected ? 'Connessa' : securityStatus.vpn.installed ? (securityStatus.vpn.configCount > 0 ? 'Non connessa' : 'Config mancante') : 'Da installare', securityStatus.vpn.connected ? `Tunnel ${securityStatus.vpn.tunnel} in esecuzione.` : securityStatus.vpn.installed ? (securityStatus.vpn.configCount > 0 ? 'WireGuard presente ma nessun tunnel attivo.' : 'WireGuard presente ma nessun file .conf trovato.') : 'WireGuard non installato.');
  setMetric('smartscreen', securityStatus.smartscreen.enabled ? 'Attivo' : 'Critico', securityStatus.smartscreen.enabled ? `Stato corrente: ${securityStatus.smartscreen.state}.` : 'Filtro SmartScreen disattivato.');

  const issueList = document.getElementById('issue-list');
  issueList.innerHTML = securityStatus.issues.length
    ? securityStatus.issues.map((issue) => `<div class="issue-row">${escapeHtml(issue)}</div>`).join('')
    : '<div class="issue-row success">Nessun problema critico rilevato nei controlli principali.</div>';
}

function setMetric(name, status, copy) {
  const statusEl = document.getElementById(`metric-${name}`);
  const copyEl = document.getElementById(`metric-${name}-copy`);
  statusEl.textContent = status;
  statusEl.className = `metric-status ${normalizeStatus(status)}`;
  copyEl.textContent = copy;
}

function normalizeStatus(status) {
  const value = String(status).toLowerCase();
  if (value.includes('critico') || value.includes('installare') || value.includes('mancante')) return 'bad';
  if (value.includes('non connessa')) return 'warn';
  return 'good';
}

function renderSystemGlance(info) {
  const items = [
    ['Host', info.hostname],
    ['Utente', info.username],
    ['CPU', `${info.cpus} core`],
    ['RAM', `${info.freeMem}/${info.totalMem} GB liberi`],
    ['Uptime', `${info.uptime} ore`],
    ['OS', `Windows ${info.arch}`]
  ];
  document.getElementById('system-glance').innerHTML = items.map(([label, value]) => `<div class="glance-item"><span>${label}</span><strong>${value}</strong></div>`).join('');
}

async function handleNetworkUpdate(rawConnections) {
  connections = rawConnections;
  const uniqueIps = [...new Set(rawConnections.map((connection) => connection.remoteIp).filter(Boolean))];

  for (const ip of uniqueIps.slice(0, 16)) {
    if (!geoCache[ip]) {
      geoCache[ip] = await api.geolocateIp(ip);
    }
  }

  classifiedConnections = await api.classifyConnections(
    rawConnections.map((connection) => ({
      ...connection,
      geo: geoCache[connection.remoteIp] || {}
    }))
  );

  renderMonitorTable(classifiedConnections);

  const protectionResults = await api.inspectAndProtectConnections(classifiedConnections);
  if (protectionResults.length) {
    activeProtection = await api.getActiveProtectionStatus();
    renderActiveProtection();
    for (const result of protectionResults) {
      const message = result.success
        ? result.alreadyBlocked
          ? `IP sospetto gia bloccato: ${result.ip}`
          : `IP sospetto bloccato: ${result.ip} (${result.processName}:${result.pid})`
        : result.skipped
          ? `IP rilevato ma non bloccabile automaticamente: ${result.ip}`
          : `Tentativo di blocco fallito per ${result.ip}: ${result.reason}`;
      protectionAlerts.unshift({ ...result, message });
      protectionAlerts = protectionAlerts.slice(0, 20);
      addLog(message, result.success ? 'err' : 'warn');
    }
    renderProtectionAlerts();
  }

  const riskyCount = classifiedConnections.filter((connection) => connection.computedRisk === 'high').length;
  if (riskyCount > 0) {
    addLog(`Rilevate ${riskyCount} connessioni da verificare.`, 'warn');
  }
}

function renderProtectionAlerts() {
  const container = document.getElementById('protection-alerts');
  if (!protectionAlerts.length) {
    container.innerHTML = '<div class="empty-state">Nessun IP sospetto bloccato finora.</div>';
    return;
  }

  container.innerHTML = protectionAlerts.map((alert) => `
    <div class="issue-row ${alert.success ? 'success' : ''}">
      <strong>${alert.ip}</strong> porta ${alert.port || '-'} ${alert.processName ? `• ${escapeHtml(alert.processName)}` : ''}
      <br />
      ${escapeHtml(alert.message)}
    </div>
  `).join('');
}

function renderMonitorTable(records) {
  const tbody = document.getElementById('conn-tbody');
  const query = document.getElementById('ip-filter').value.trim().toLowerCase();
  const onlyRisky = document.getElementById('show-suspicious-only').checked;

  let visible = records;
  if (query) {
    visible = visible.filter((record) =>
      [record.remoteIp, record.remotePort, record.geo?.country, record.geo?.city, record.geo?.isp]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query))
    );
  }
  if (onlyRisky) {
    visible = visible.filter((record) => record.computedRisk === 'high');
  }

  if (!visible.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-cell">Nessuna connessione compatibile con i filtri.</td></tr>';
    return;
  }

  tbody.innerHTML = visible.slice(0, 80).map((record) => `
    <tr>
      <td>${record.remoteIp || '-'}</td>
      <td>${record.geo?.countryCode || '-'} ${record.geo?.country || '-'}</td>
      <td>${record.geo?.city || '-'}</td>
      <td>${record.geo?.isp || '-'}</td>
      <td>${record.remotePort || '-'}</td>
      <td>${record.proto || '-'}</td>
      <td>${record.state || '-'}</td>
      <td><span class="pill ${record.computedRisk === 'high' ? 'danger' : 'safe'}">${record.computedRisk === 'high' ? 'ALTO' : 'BASSO'}</span></td>
    </tr>
  `).join('');
}

function setupProcessScanner() {
  document.getElementById('scan-proc-btn').addEventListener('click', async () => {
    const button = document.getElementById('scan-proc-btn');
    button.disabled = true;
    button.textContent = 'Scansione in corso...';

    lastProcesses = await api.scanProcesses();
    const suspicious = lastProcesses.filter((process) => process.status === 'danger');
    const normal = lastProcesses.filter((process) => process.status === 'normal');
    const safe = lastProcesses.filter((process) => process.status === 'safe');

    document.getElementById('ps-safe').textContent = safe.length + normal.length;
    document.getElementById('ps-warn').textContent = normal.length;
    document.getElementById('ps-danger').textContent = suspicious.length;

    document.getElementById('proc-tbody').innerHTML = lastProcesses.map((process) => `
      <tr>
        <td>${process.name}</td>
        <td>${process.pid}</td>
        <td>${process.mem}</td>
        <td><span class="pill ${process.status === 'danger' ? 'danger' : process.status === 'safe' ? 'safe' : 'warn'}">${process.status === 'danger' ? 'Sospetto' : process.status === 'safe' ? 'Sistema' : 'Normale'}</span></td>
      </tr>
    `).join('');

    const alert = document.getElementById('proc-alert');
    if (suspicious.length) {
      document.getElementById('proc-alert-text').textContent = `Attenzione: rilevati ${suspicious.length} processi sospetti (${suspicious.map((item) => item.name).join(', ')}).`;
      alert.hidden = false;
      addLog('Scansione processi: presenti esecuzioni sospette da verificare.', 'err');
    } else {
      alert.hidden = true;
      addLog('Scansione processi completata senza indicatori noti di rischio.', 'ok');
    }

    button.disabled = false;
    button.textContent = 'Avvia scansione';
  });

  document.getElementById('proc-alert-close').addEventListener('click', () => {
    document.getElementById('proc-alert').hidden = true;
  });
}

async function loadVpnServers() {
  const servers = await api.getVpnServers();
  document.getElementById('server-grid').innerHTML = servers.map((server) => `
    <button class="server-card" data-id="${server.id}">
      <div class="server-country">${server.country}</div>
      <strong>${server.name}</strong>
      <span>${server.city}</span>
      <small>Carico ${server.load}%${server.free ? ' • Free' : ''}</small>
    </button>
  `).join('');

  document.querySelectorAll('.server-card').forEach((card) => {
    card.addEventListener('click', () => {
      selectedServerId = card.dataset.id;
      document.querySelectorAll('.server-card').forEach((entry) => entry.classList.remove('selected'));
      card.classList.add('selected');
      document.getElementById('vpn-connect-btn').disabled = false;
    });
  });
}

function setupVPNActions() {
  document.getElementById('vpn-connect-btn').addEventListener('click', async () => {
    if (!selectedServerId) return;
    const button = document.getElementById('vpn-connect-btn');
    button.disabled = true;
    button.textContent = 'Connessione...';

    const result = await api.vpnConnect(selectedServerId);
    if (!result.success) {
      const message = result.error === 'wireguard_not_found'
        ? 'WireGuard non installato.'
        : result.error === 'config_not_found'
          ? `Configurazione non trovata: ${result.configPath}`
          : (result.error || 'Errore VPN');
      addLog(`VPN: ${message}`, 'err');
      alert(message);
      button.disabled = false;
      button.textContent = 'Connetti VPN';
      return;
    }

    addLog(`VPN connessa sul tunnel ${selectedServerId}.`, 'ok');
    await refreshSecurityStatus();
    const myIp = await api.getMyIp();
    document.getElementById('my-ip').textContent = myIp;
    document.getElementById('vpn-current-ip').textContent = myIp;
  });

  document.getElementById('vpn-disconnect-btn').addEventListener('click', async () => {
    const result = await api.vpnDisconnect();
    if (!result.success) {
      addLog(`Errore disconnessione VPN: ${result.error}`, 'err');
      alert(result.error || 'Errore durante la disconnessione.');
      return;
    }

    addLog('VPN disconnessa.', 'warn');
    await refreshSecurityStatus();
    const myIp = await api.getMyIp();
    document.getElementById('my-ip').textContent = myIp;
    document.getElementById('vpn-current-ip').textContent = myIp;
  });
}

function renderVpnStatus(status) {
  const label = document.getElementById('vpn-state-label');
  const sub = document.getElementById('vpn-state-sub');
  const connectBtn = document.getElementById('vpn-connect-btn');
  const disconnectBtn = document.getElementById('vpn-disconnect-btn');
  const footer = document.getElementById('my-ip-vpn');

  if (status.connected) {
    label.textContent = 'VPN connessa';
    sub.textContent = `Tunnel attivo: ${status.tunnel}`;
    footer.textContent = `VPN attiva: ${status.tunnel}`;
    connectBtn.hidden = true;
    disconnectBtn.hidden = false;
  } else {
    label.textContent = !status.installed ? 'WireGuard non installato' : status.configCount > 0 ? 'VPN non connessa' : 'Config VPN mancante';
    sub.textContent = !status.installed
      ? 'Ion Security puo installare WireGuard automaticamente.'
      : status.configCount > 0
        ? 'Nessun tunnel in esecuzione.'
        : 'Aggiungi almeno un file .conf del provider nella cartella VPN.';
    footer.textContent = status.connected ? `VPN attiva: ${status.tunnel}` : 'VPN non attiva';
    connectBtn.hidden = false;
    connectBtn.disabled = !selectedServerId;
    connectBtn.textContent = 'Connetti VPN';
    disconnectBtn.hidden = true;
  }
}

function setupAssistant() {
  document.getElementById('send-btn').addEventListener('click', sendAssistantMessage);
  document.getElementById('chat-input').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      sendAssistantMessage();
    }
  });
}

async function sendAssistantMessage() {
  const input = document.getElementById('chat-input');
  const text = input.value.trim();
  if (!text) return;

  input.value = '';
  appendChatMessage(text, 'user');
  const thinking = appendChatMessage('Sto analizzando i dati reali raccolti dall\'app...', 'assistant');

  const result = await api.localAiQuery({
    question: text,
    context: buildAssistantContext()
  });

  thinking.remove();
  appendChatMessage(result.text, 'assistant');
  addLog('Assistente locale: risposta generata.', 'ok');
}

function buildAssistantContext() {
  return {
    securityScore: securityStatus?.score ?? null,
    issues: securityStatus?.issues ?? [],
    vpnConnected,
    riskyConnections: classifiedConnections.filter((connection) => connection.computedRisk === 'high').map((connection) => connection.remoteIp),
    suspiciousProcesses: lastProcesses.filter((process) => process.status === 'danger').map((process) => process.name)
  };
}

function appendChatMessage(text, role) {
  const wrapper = document.createElement('div');
  wrapper.className = `chat-msg ${role}`;
  wrapper.innerHTML = `<div class="msg-bubble">${escapeHtml(text).replace(/\n/g, '<br>')}</div>`;
  const messages = document.getElementById('chat-messages');
  messages.appendChild(wrapper);
  messages.scrollTop = messages.scrollHeight;
  return wrapper;
}

function setupSettings() {
  document.getElementById('scan-interval').addEventListener('change', async (event) => {
    const normalized = await api.setScanInterval(Number(event.target.value));
    addLog(`Intervallo scansione rete impostato a ${normalized / 1000} secondi.`, 'ok');
  });
}

function addLog(message, type = 'ok') {
  logLines.unshift({ ts: new Date().toLocaleTimeString('it-IT'), message, type });
  logLines = logLines.slice(0, 40);
  document.getElementById('dash-log').innerHTML = logLines.map((line) => `
    <div class="log-line ${line.type}">
      <span>${line.ts}</span>
      <p>${escapeHtml(line.message)}</p>
    </div>
  `).join('');
}

function quickQuery(question) {
  document.getElementById('chat-input').value = question;
  sendAssistantMessage();
}

window.quickQuery = quickQuery;

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
