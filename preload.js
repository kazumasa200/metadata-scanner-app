'use strict';
const { contextBridge, ipcRenderer, webUtils } = require('electron');
const fs = require('fs');
const path = require('path');

/* Blobワーカー用ソース (engine.js + worker-boot.js)。file://ではfetchできないためここで読む */
let workerSource = null;
try {
  workerSource =
    fs.readFileSync(path.join(__dirname, 'lzma.js'), 'utf-8') + '\n' +
    fs.readFileSync(path.join(__dirname, 'engine.js'), 'utf-8') + '\n' +
    fs.readFileSync(path.join(__dirname, 'worker-boot.js'), 'utf-8');
} catch (e) { /* フォールバック: レンダラーがメインスレッドで解析する */ }

contextBridge.exposeInMainWorld('metascanNative', {
  onOpenFiles: (cb) => ipcRenderer.on('open-files', (_e, files) => cb(files)),
  workerSource,
  getPathForFile: (file) => {
    try { return webUtils.getPathForFile(file); } catch (e) { return null; }
  },
  readZone: (p) => ipcRenderer.invoke('read-zone', p),
  ctxStatus: () => ipcRenderer.invoke('ctx-status'),
  ctxRegister: () => ipcRenderer.invoke('ctx-register'),
  ctxUnregister: () => ipcRenderer.invoke('ctx-unregister'),
});
