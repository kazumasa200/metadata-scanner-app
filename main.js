'use strict';
const { app, BrowserWindow, Menu, ipcMain } = require('electron');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

const PARTIAL_READ = 16 * 1024 * 1024;
const FULL_READ_LIMIT = 256 * 1024 * 1024;

let win = null;

function readZoneText(filePath) {
  try { return fs.readFileSync(filePath + ':Zone.Identifier', 'utf-8'); }
  catch (e) { return null; }
}

function readFileLimited(filePath, size) {
  if (size > FULL_READ_LIMIT) {
    const fd = fs.openSync(filePath, 'r');
    const data = Buffer.alloc(PARTIAL_READ);
    fs.readSync(fd, data, 0, PARTIAL_READ, 0);
    fs.closeSync(fd);
    return { data, truncated: true };
  }
  return { data: fs.readFileSync(filePath), truncated: false };
}

function collectArgFiles(argv) {
  const files = [];
  for (const a of argv.slice(1)) {
    if (!a || a.startsWith('-')) continue;
    try {
      const st = fs.statSync(a);
      if (st.isFile()) files.push({ path: a, size: st.size, mtimeMs: st.mtimeMs });
    } catch (e) { /* 読めない引数は無視 */ }
  }
  return files;
}

/* ---------- CLIモード: MetaScan.exe --scan file... [--out report.json] ---------- */
async function runCliScan(argv) {
  const Engine = require('./engine.js');
  const outIdx = argv.indexOf('--out');
  const outFile = outIdx !== -1 ? argv[outIdx + 1] : null;
  const fileArgs = argv.filter((a, i) => i > 0 && !a.startsWith('-') && i !== outIdx + 1);
  const results = [];
  for (const p of fileArgs) {
    try {
      const st = fs.statSync(p);
      if (!st.isFile()) continue;
      const { data, truncated } = readFileLimited(p, st.size);
      const r = await Engine.analyzeBuffer(new Uint8Array(data), {
        name: path.basename(p), size: st.size, lastModified: st.mtimeMs,
      });
      const zone = readZoneText(p);
      results.push({
        file: p, truncated,
        maxRisk: r.findings.reduce((m, f) => Math.max(m, f.risk), 0),
        findings: r.findings, metadata: r.metadata,
        zoneIdentifier: zone || undefined,
      });
    } catch (e) {
      results.push({ file: p, error: String(e && e.message || e) });
    }
  }
  const json = JSON.stringify(results, null, 2);
  if (outFile) fs.writeFileSync(outFile, json);
  else process.stdout.write(json + '\n');
}

/* GUI: 引数やドロップ起動で渡されたファイルをレンダラーへ送る */
function sendArgFiles(argv) {
  if (!win) return;
  const files = [];
  for (const f of collectArgFiles(argv)) {
    try {
      const { data, truncated } = readFileLimited(f.path, f.size);
      files.push({
        name: path.basename(f.path),
        size: f.size,
        lastModified: f.mtimeMs,
        truncated,
        data,
        zoneText: readZoneText(f.path),
      });
    } catch (e) { /* skip */ }
  }
  if (files.length) win.webContents.send('open-files', files);
}

function createWindow() {
  win = new BrowserWindow({
    width: 1150,
    height: 840,
    minWidth: 640,
    minHeight: 480,
    backgroundColor: '#111210',
    icon: path.join(__dirname, 'icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  Menu.setApplicationMenu(null);
  win.loadFile('index.html');
  win.webContents.on('did-finish-load', () => sendArgFiles(process.argv));
  win.on('closed', () => { win = null; });
}

ipcMain.handle('read-zone', (_e, p) => {
  if (typeof p !== 'string') return null;
  return readZoneText(p);
});

/* ---------- エクスプローラー右クリック統合 (HKCU = 管理者権限不要) ---------- */
const CTX_KEY = 'HKCU\\Software\\Classes\\*\\shell\\MetaScan';

function regExec(args) {
  return new Promise((resolve, reject) => {
    execFile('reg', args, { windowsHide: true }, (err, stdout) => {
      if (err) reject(err); else resolve(stdout);
    });
  });
}
/* ポータブルexeは一時フォルダに展開されて実行されるため、元のexeパスを使う */
function ownExePath() {
  return process.env.PORTABLE_EXECUTABLE_FILE || process.execPath;
}

ipcMain.handle('ctx-status', async () => {
  try { await regExec(['query', CTX_KEY]); return true; } catch (e) { return false; }
});
ipcMain.handle('ctx-register', async () => {
  const exe = ownExePath();
  await regExec(['add', CTX_KEY, '/ve', '/d', 'MetaScanでスキャン', '/f']);
  await regExec(['add', CTX_KEY, '/v', 'Icon', '/d', exe, '/f']);
  await regExec(['add', CTX_KEY + '\\command', '/ve', '/d', `"${exe}" "%1"`, '/f']);
  return exe;
});
ipcMain.handle('ctx-unregister', async () => {
  try { await regExec(['delete', CTX_KEY, '/f']); } catch (e) { /* 未登録なら無視 */ }
  return true;
});

if (process.argv.includes('--scan')) {
  /* ウィンドウを開かずJSONを出力して終了 */
  app.whenReady().then(async () => {
    try { await runCliScan(process.argv); } catch (e) { process.stderr.write(String(e) + '\n'); }
    app.exit(0);
  });
} else {
  const gotLock = app.requestSingleInstanceLock();
  if (!gotLock) {
    app.quit();
  } else {
    app.on('second-instance', (_e, argv) => {
      if (win) {
        if (win.isMinimized()) win.restore();
        win.focus();
        sendArgFiles(argv);
      }
    });
    app.whenReady().then(createWindow);
    app.on('window-all-closed', () => app.quit());
  }
}
