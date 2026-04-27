const { app, BrowserWindow, ipcMain, shell, Tray, Menu, nativeImage } = require('electron');
const path = require('path');
const { exec } = require('child_process');
const fs = require('fs');
const os = require('os');
const http = require('http');

let mainWindow;
let tray;
let monitorInterval = null;
let activeVpnTunnel = null;

const CONFIG_DIR = path.join(os.homedir(), '.ion-security');
const CONFIG_PATH = path.join(CONFIG_DIR, 'config.json');
const VPN_CONFIG_DIR = path.join(os.homedir(), 'ion-security-vpn');
const KNOWN_DANGEROUS_PORTS = new Set(['4444', '1337', '9999', '5555', '6667']);
const DEFAULT_CONFIG = {
  scanIntervalMs: 4000,
  lastVpnTunnel: '',
  bootstrapCompletedAt: null
};

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 1024,
    minHeight: 700,
    frame: false,
    backgroundColor: '#eef3f7',
    icon: path.join(__dirname, 'assets', 'icon.ico'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    titleBarStyle: 'hidden'
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
  mainWindow.on('minimize', (event) => {
    event.preventDefault();
    mainWindow.hide();
  });
}

function createTray() {
  const iconPath = path.join(__dirname, 'assets', 'icon.ico');
  const icon = fs.existsSync(iconPath)
    ? nativeImage.createFromPath(iconPath)
    : nativeImage.createEmpty();

  tray = new Tray(icon);
  tray.setToolTip('Ion Security');
  tray.setContextMenu(
    Menu.buildFromTemplate([
      {
        label: 'Apri Ion Security',
        click: () => {
          mainWindow.show();
          mainWindow.focus();
        }
      },
      { type: 'separator' },
      {
        label: 'Esci',
        click: () => app.quit()
      }
    ])
  );
  tray.on('double-click', () => {
    mainWindow.show();
    mainWindow.focus();
  });
}

function ensureDirectories() {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }
  if (!fs.existsSync(VPN_CONFIG_DIR)) {
    fs.mkdirSync(VPN_CONFIG_DIR, { recursive: true });
  }
}

function loadConfig() {
  ensureDirectories();
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      return { ...DEFAULT_CONFIG, ...JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')) };
    }
  } catch {}
  return { ...DEFAULT_CONFIG };
}

function saveConfig(patch) {
  ensureDirectories();
  const next = { ...loadConfig(), ...patch };
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(next, null, 2), 'utf8');
  return next;
}

function execCommand(command, timeout = 20000) {
  return new Promise((resolve) => {
    exec(command, { timeout, windowsHide: true, maxBuffer: 1024 * 1024 * 16 }, (error, stdout, stderr) => {
      resolve({
        ok: !error,
        stdout: stdout || '',
        stderr: stderr || '',
        error: error ? error.message : ''
      });
    });
  });
}

async function checkWireGuardInstalled() {
  const result = await execCommand('where wireguard', 5000);
  return result.ok;
}

async function installWireGuard() {
  const command = 'winget install --id WireGuard.WireGuard -e --source winget --accept-source-agreements --accept-package-agreements --silent';
  const result = await execCommand(command, 180000);
  return {
    ok: result.ok,
    details: result.ok ? 'WireGuard installato o gia presente.' : (result.stderr || result.error || 'Installazione WireGuard non riuscita.')
  };
}

async function enableFirewallProfiles() {
  const result = await execCommand('powershell -NoProfile -Command "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"', 30000);
  return {
    ok: result.ok,
    details: result.ok ? 'Firewall Windows attivato su tutti i profili.' : (result.stderr || result.error || 'Attivazione firewall non riuscita.')
  };
}

async function updateDefenderSignatures() {
  const result = await execCommand('powershell -NoProfile -Command "Update-MpSignature"', 120000);
  return {
    ok: result.ok,
    details: result.ok ? 'Definizioni Defender aggiornate.' : (result.stderr || result.error || 'Aggiornamento firme Defender non riuscito.')
  };
}

async function setSmartScreenToWarn() {
  const result = await execCommand('powershell -NoProfile -Command "Set-ItemProperty -Path \\"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" -Name SmartScreenEnabled -Value Warn"', 30000);
  return {
    ok: result.ok,
    details: result.ok ? 'SmartScreen impostato su Warn.' : (result.stderr || result.error || 'Impostazione SmartScreen non riuscita.')
  };
}

function getVpnConfigCount() {
  ensureDirectories();
  return fs.readdirSync(VPN_CONFIG_DIR).filter((file) => file.toLowerCase().endsWith('.conf')).length;
}

async function resolveVpnStatus() {
  const config = loadConfig();
  const tunnel = activeVpnTunnel || config.lastVpnTunnel || '';
  const wireguardInstalled = await checkWireGuardInstalled();

  if (!wireguardInstalled) {
    return {
      installed: false,
      connected: false,
      tunnel: '',
      configDir: VPN_CONFIG_DIR,
      configCount: getVpnConfigCount()
    };
  }

  if (!tunnel) {
    return {
      installed: true,
      connected: false,
      tunnel: '',
      configDir: VPN_CONFIG_DIR,
      configCount: getVpnConfigCount()
    };
  }

  const serviceStatus = await execCommand(`sc query "${tunnel}"`, 6000);
  const connected = serviceStatus.ok && /STATE\s+:\s+\d+\s+RUNNING/i.test(serviceStatus.stdout);
  if (connected) {
    activeVpnTunnel = tunnel;
  }

  return {
    installed: true,
    connected,
    tunnel,
    configDir: VPN_CONFIG_DIR,
    configCount: getVpnConfigCount()
  };
}

async function getBootstrapStatus() {
  ensureDirectories();
  const config = loadConfig();
  const wireguardInstalled = await checkWireGuardInstalled();
  return {
    directoriesReady: fs.existsSync(CONFIG_DIR) && fs.existsSync(VPN_CONFIG_DIR),
    wireguardInstalled,
    vpnConfigDir: VPN_CONFIG_DIR,
    vpnConfigCount: getVpnConfigCount(),
    bootstrapCompletedAt: config.bootstrapCompletedAt
  };
}

async function runBootstrap() {
  ensureDirectories();
  const steps = [];

  const wireguardInstalled = await checkWireGuardInstalled();
  if (!wireguardInstalled) {
    steps.push({ name: 'WireGuard', ...(await installWireGuard()) });
  } else {
    steps.push({ name: 'WireGuard', ok: true, details: 'WireGuard gia installato.' });
  }

  steps.push({ name: 'Firewall', ...(await enableFirewallProfiles()) });
  steps.push({ name: 'Defender', ...(await updateDefenderSignatures()) });
  steps.push({ name: 'SmartScreen', ...(await setSmartScreenToWarn()) });

  const allOk = steps.every((step) => step.ok);
  saveConfig({ bootstrapCompletedAt: new Date().toISOString() });

  return {
    success: allOk,
    steps,
    status: await getBootstrapStatus(),
    note: getVpnConfigCount() > 0
      ? 'Bootstrap completato. Le configurazioni VPN sono presenti.'
      : 'Bootstrap completato, ma per connettere una VPN serve ancora almeno un file .conf del provider.'
  };
}

async function getSecurityStatus() {
  const [defenderResult, firewallResult, smartscreenResult, vpnStatus] = await Promise.all([
    execCommand('powershell -NoProfile -Command "Get-MpComputerStatus | ConvertTo-Json -Compress"'),
    execCommand('powershell -NoProfile -Command "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress"'),
    execCommand('powershell -NoProfile -Command "Get-ItemProperty -Path \\"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" -Name SmartScreenEnabled | Select-Object SmartScreenEnabled | ConvertTo-Json -Compress"'),
    resolveVpnStatus()
  ]);

  let defender = null;
  let firewallProfiles = [];
  let smartscreen = 'Unknown';

  try { defender = JSON.parse(defenderResult.stdout); } catch {}
  try {
    const parsed = JSON.parse(firewallResult.stdout);
    firewallProfiles = Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
  } catch {}
  try { smartscreen = JSON.parse(smartscreenResult.stdout)?.SmartScreenEnabled || 'Unknown'; } catch {}

  const defenderHealthy = Boolean(defender?.AntivirusEnabled && defender?.RealTimeProtectionEnabled);
  const definitionsFresh = defender?.AntivirusSignatureAge === 0 || defender?.AntivirusSignatureAge === 1;
  const firewallHealthy = firewallProfiles.length > 0 && firewallProfiles.every((profile) => profile.Enabled === true);
  const smartscreenHealthy = String(smartscreen).toLowerCase() !== 'off';

  const issues = [];
  if (!defender?.AntivirusEnabled) issues.push('Antivirus Microsoft Defender non attivo');
  if (!defender?.RealTimeProtectionEnabled) issues.push('Protezione in tempo reale disattivata');
  if (!definitionsFresh) issues.push('Definizioni antivirus non aggiornate');
  if (!firewallHealthy) issues.push('Uno o piu profili firewall risultano disattivati');
  if (!smartscreenHealthy) issues.push('SmartScreen risulta disattivato');
  if (!vpnStatus.installed) issues.push('WireGuard non installato');
  else if (vpnStatus.configCount === 0) issues.push('Configurazione VPN mancante');
  else if (!vpnStatus.connected) issues.push('VPN non connessa');

  const score =
    (defenderHealthy ? 30 : 0) +
    (definitionsFresh ? 20 : 0) +
    (firewallHealthy ? 20 : 0) +
    (smartscreenHealthy ? 10 : 0) +
    (vpnStatus.connected ? 20 : vpnStatus.installed ? 10 : 0);

  return {
    score,
    issues,
    defender: {
      enabled: Boolean(defender?.AntivirusEnabled),
      realtime: Boolean(defender?.RealTimeProtectionEnabled),
      signaturesAge: Number.isFinite(defender?.AntivirusSignatureAge) ? defender.AntivirusSignatureAge : null
    },
    firewall: {
      profiles: firewallProfiles,
      allEnabled: firewallHealthy
    },
    smartscreen: {
      state: smartscreen,
      enabled: smartscreenHealthy
    },
    vpn: vpnStatus,
    bootstrap: await getBootstrapStatus()
  };
}

function classifyConnectionRisk(connection, geo = {}) {
  if (KNOWN_DANGEROUS_PORTS.has(String(connection.remotePort))) return 'high';
  if (geo.isProxy || geo.isHosting || geo.risk === 'high') return 'high';
  return 'low';
}

function getNetworkConnections() {
  exec('netstat -ano', { timeout: 8000, windowsHide: true, maxBuffer: 1024 * 1024 * 8 }, (err, stdout) => {
    if (err || !stdout) return;

    const lines = stdout.split('\n').filter((line) =>
      (line.includes('ESTABLISHED') || line.includes('LISTENING') || line.includes('TIME_WAIT')) &&
      line.trim().length > 0
    );

    const connections = [];
    lines.slice(0, 80).forEach((line) => {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 5) return;

      const proto = parts[0];
      const local = parts[1];
      const remote = parts[2];
      const state = parts[3];
      const pid = parts[4];

      if (!remote || remote === '0.0.0.0:0' || remote === '[::]:0' || remote.startsWith('0.0.0.0')) return;

      const remoteIp = remote.includes(':')
        ? remote.split(':').slice(0, -1).join(':') || remote.split(':')[0]
        : remote.split(':')[0];
      const remotePort = remote.split(':').pop();

      connections.push({ proto, local, remote, remoteIp, remotePort, state, pid });
    });

    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('network-update', connections);
    }
  });
}

function startNetworkMonitor() {
  const intervalMs = Number(loadConfig().scanIntervalMs) || 4000;
  if (monitorInterval) clearInterval(monitorInterval);
  monitorInterval = setInterval(getNetworkConnections, intervalMs);
  getNetworkConnections();
}

function buildLocalAssistantReply(question, context) {
  const q = String(question || '').toLowerCase();
  const score = context?.securityScore ?? null;
  const issues = context?.issues || [];
  const riskyConnections = context?.riskyConnections || [];
  const suspiciousProcesses = context?.suspiciousProcesses || [];
  const vpnConnected = Boolean(context?.vpnConnected);

  if (q.includes('vpn')) {
    return vpnConnected
      ? `La VPN risulta attiva. Verifica comunque che l'IP pubblico sia cambiato e che il tunnel selezionato sia quello corretto.`
      : `La VPN non risulta attiva. Ion Security puo installare WireGuard, ma per una connessione reale serve almeno un file .conf del provider nella cartella VPN.`;
  }

  if (q.includes('rete') || q.includes('connession')) {
    return riskyConnections.length
      ? `Ho rilevato ${riskyConnections.length} connessioni da verificare: ${riskyConnections.slice(0, 6).join(', ')}. Controlla soprattutto porte insolite, proxy, hosting e processi associati.`
      : `Al momento non vedo connessioni ad alto rischio tra quelle classificate. Il monitor di rete usa dati reali da netstat e geolocalizzazione IP.`;
  }

  if (q.includes('process')) {
    return suspiciousProcesses.length
      ? `Ci sono processi sospetti o da approfondire: ${suspiciousProcesses.slice(0, 6).join(', ')}. Ti consiglio di verificare percorso file, firma digitale e avvio automatico.`
      : `Non risultano processi esplicitamente sospetti nell'ultima scansione, ma resta utile controllare memoria, percorso e firma digitale dei processi normali se noti anomalie.`;
  }

  if (issues.length === 0) {
    return `Lo stato generale e buono${score !== null ? ` con punteggio ${score}/100` : ''}. Antivirus, firewall e controlli principali risultano allineati; resta da mantenere aggiornata la configurazione VPN se la usi.`;
  }

  return `Situazione attuale${score !== null ? `: punteggio ${score}/100.` : '.'} Le priorita sono: ${issues.slice(0, 4).join('; ')}. Posso aiutarti a leggere rete, VPN o processi usando i dati reali raccolti dall'app.`;
}

app.whenReady().then(() => {
  ensureDirectories();
  createWindow();
  createTray();
  startNetworkMonitor();
});

app.on('window-all-closed', () => {});
app.on('before-quit', () => {
  if (monitorInterval) clearInterval(monitorInterval);
});

ipcMain.on('window-minimize', () => mainWindow.minimize());
ipcMain.on('window-maximize', () => mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize());
ipcMain.on('window-close', () => mainWindow.hide());
ipcMain.on('window-quit', () => app.quit());

ipcMain.handle('scan-processes', async () => {
  const taskListResult = await execCommand('tasklist /FO CSV /NH');
  if (!taskListResult.ok) return [];

  const suspiciousNames = ['mimikatz', 'netcat', 'nc.exe', 'nmap', 'wireshark', 'metasploit', 'meterpreter', 'cobaltstrike', 'empire', 'psexec', 'pwdump', 'procdump', 'wce.exe', 'fgdump', 'gsecdump', 'quarks', 'lazagne'];
  const systemProcesses = new Set(['system', 'svchost.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'explorer.exe', 'taskhostw.exe', 'msmpeng.exe']);

  return taskListResult.stdout.split('\n').filter((line) => line.trim()).slice(0, 140).map((line) => {
    const parts = line.replace(/"/g, '').split(',');
    const name = (parts[0] || '').trim();
    const lowerName = name.toLowerCase();
    const suspicious = suspiciousNames.some((entry) => lowerName.includes(entry));
    return {
      name,
      pid: (parts[1] || '').trim(),
      mem: parts[4] ? parts[4].trim() : 'N/A',
      status: suspicious ? 'danger' : systemProcesses.has(lowerName) ? 'safe' : 'normal',
      suspicious
    };
  });
});

ipcMain.handle('geolocate-ip', async (event, ip) => {
  return new Promise((resolve) => {
    if (
      ip.startsWith('192.168') ||
      ip.startsWith('10.') ||
      ip.startsWith('127.') ||
      ip.startsWith('172.') ||
      ip === '::1' ||
      ip.startsWith('fe80')
    ) {
      resolve({ ip, country: 'LAN', city: 'Locale', isp: 'Rete privata', risk: 'low', isProxy: false, isHosting: false, flag: 'LAN' });
      return;
    }

    http.get(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,isp,org,query,proxy,hosting`, { timeout: 3000 }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve({
            ip: json.query || ip,
            country: json.country || '?',
            countryCode: json.countryCode || '?',
            city: json.city || '?',
            isp: json.isp || json.org || '?',
            risk: json.proxy || json.hosting ? 'high' : 'low',
            isProxy: Boolean(json.proxy),
            isHosting: Boolean(json.hosting),
            flag: json.countryCode || 'NET'
          });
        } catch {
          resolve({ ip, country: '?', city: '?', isp: '?', risk: 'unknown', isProxy: false, isHosting: false, flag: 'NET' });
        }
      });
    }).on('error', () => resolve({ ip, country: '?', city: '?', isp: '?', risk: 'unknown', isProxy: false, isHosting: false, flag: 'NET' }));
  });
});

ipcMain.handle('get-my-ip', async () => {
  return new Promise((resolve) => {
    http.get('http://api.ipify.org?format=json', { timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data).ip); } catch { resolve('N/A'); }
      });
    }).on('error', () => resolve('N/A'));
  });
});

ipcMain.handle('vpn-get-servers', async () => [
  { id: 'nl-free-01', name: 'Netherlands #1', country: 'NL', city: 'Amsterdam', load: 45, free: true },
  { id: 'us-free-01', name: 'United States #1', country: 'US', city: 'New York', load: 62, free: true },
  { id: 'jp-free-01', name: 'Japan #1', country: 'JP', city: 'Tokyo', load: 38, free: true },
  { id: 'ch-01', name: 'Switzerland #1', country: 'CH', city: 'Zurich', load: 28, free: false },
  { id: 'de-01', name: 'Germany #1', country: 'DE', city: 'Frankfurt', load: 51, free: false },
  { id: 'se-01', name: 'Sweden #1', country: 'SE', city: 'Stockholm', load: 33, free: false }
]);

ipcMain.handle('vpn-status', async () => resolveVpnStatus());
ipcMain.handle('bootstrap-status', async () => getBootstrapStatus());
ipcMain.handle('bootstrap-run', async () => runBootstrap());

ipcMain.handle('vpn-connect', async (event, serverId) => {
  if (!(await checkWireGuardInstalled())) return { success: false, error: 'wireguard_not_found' };
  const configPath = path.join(VPN_CONFIG_DIR, `${serverId}.conf`);
  if (!fs.existsSync(configPath)) return { success: false, error: 'config_not_found', configPath };

  const result = await execCommand(`wireguard /installtunnelservice "${configPath}"`, 15000);
  if (!result.ok) return { success: false, error: result.error || result.stderr || 'vpn_connect_failed' };

  activeVpnTunnel = serverId;
  saveConfig({ lastVpnTunnel: serverId });
  return { success: true, status: await resolveVpnStatus() };
});

ipcMain.handle('vpn-disconnect', async () => {
  const status = await resolveVpnStatus();
  if (!status.connected || !status.tunnel) return { success: true, status };
  const result = await execCommand(`wireguard /uninstalltunnelservice "${status.tunnel}"`, 15000);
  if (!result.ok) return { success: false, error: result.error || result.stderr || 'vpn_disconnect_failed' };
  activeVpnTunnel = null;
  saveConfig({ lastVpnTunnel: '' });
  return { success: true, status: await resolveVpnStatus() };
});

ipcMain.handle('security-status', async () => getSecurityStatus());

ipcMain.handle('set-scan-interval', async (event, intervalMs) => {
  const normalized = Math.max(2000, Number(intervalMs) || 4000);
  saveConfig({ scanIntervalMs: normalized });
  startNetworkMonitor();
  return normalized;
});

ipcMain.handle('load-settings', async () => {
  const config = loadConfig();
  return {
    scanIntervalMs: Number(config.scanIntervalMs) || 4000,
    vpnConfigDir: VPN_CONFIG_DIR,
    lastVpnTunnel: config.lastVpnTunnel || '',
    bootstrapCompletedAt: config.bootstrapCompletedAt
  };
});

ipcMain.handle('local-ai-query', async (event, { question, context }) => {
  return {
    success: true,
    text: buildLocalAssistantReply(question, context || {})
  };
});

ipcMain.handle('get-system-info', async () => ({
  platform: os.platform(),
  hostname: os.hostname(),
  username: os.userInfo().username,
  arch: os.arch(),
  totalMem: Math.round(os.totalmem() / 1024 / 1024 / 1024),
  freeMem: Math.round(os.freemem() / 1024 / 1024 / 1024),
  uptime: Math.round(os.uptime() / 3600),
  cpus: os.cpus().length,
  cpuModel: os.cpus()[0]?.model || 'N/A'
}));

ipcMain.handle('classify-connections', async (event, records) => records.map((record) => ({
  ...record,
  computedRisk: classifyConnectionRisk(record, record.geo || {})
})));

ipcMain.on('open-external', (event, url) => shell.openExternal(url));
ipcMain.on('open-path', (event, targetPath) => shell.openPath(targetPath));
