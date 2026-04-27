const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  minimize: () => ipcRenderer.send('window-minimize'),
  maximize: () => ipcRenderer.send('window-maximize'),
  close: () => ipcRenderer.send('window-close'),
  quit: () => ipcRenderer.send('window-quit'),

  onNetworkUpdate: (cb) => ipcRenderer.on('network-update', (event, data) => cb(data)),
  geolocateIp: (ip) => ipcRenderer.invoke('geolocate-ip', ip),
  getMyIp: () => ipcRenderer.invoke('get-my-ip'),
  classifyConnections: (records) => ipcRenderer.invoke('classify-connections', records),

  scanProcesses: () => ipcRenderer.invoke('scan-processes'),

  getVpnServers: () => ipcRenderer.invoke('vpn-get-servers'),
  getVpnStatus: () => ipcRenderer.invoke('vpn-status'),
  vpnConnect: (serverId) => ipcRenderer.invoke('vpn-connect', serverId),
  vpnDisconnect: () => ipcRenderer.invoke('vpn-disconnect'),

  getSecurityStatus: () => ipcRenderer.invoke('security-status'),
  setScanInterval: (intervalMs) => ipcRenderer.invoke('set-scan-interval', intervalMs),
  loadSettings: () => ipcRenderer.invoke('load-settings'),
  getBootstrapStatus: () => ipcRenderer.invoke('bootstrap-status'),
  runBootstrap: () => ipcRenderer.invoke('bootstrap-run'),

  localAiQuery: (params) => ipcRenderer.invoke('local-ai-query', params),

  getSystemInfo: () => ipcRenderer.invoke('get-system-info'),

  openExternal: (url) => ipcRenderer.send('open-external', url),
  openPath: (targetPath) => ipcRenderer.send('open-path', targetPath)
});
