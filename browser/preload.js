const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('samman', {
  upload: (domain, content) => ipcRenderer.invoke('upload', domain, content),
  register: (txJson) => ipcRenderer.invoke('register', txJson),
  resolve: (domain) => ipcRenderer.invoke('resolve', domain),
  fetchCid: (cid) => ipcRenderer.invoke('fetchCid', cid)
});
