/* MetaScan エンジンの自動テスト: 各形式の合成ファイルを作って検出結果を検証する */
'use strict';
const zlib = require('zlib');
const fs = require('fs');
const Engine = require('./engine.js');
const Cleaner = require('./cleaner.js');

let pass = 0, fail = 0;
function check(label, cond, detail) {
  if (cond) { pass++; console.log('  OK  ' + label); }
  else { fail++; console.log('  NG  ' + label + (detail ? '  -- ' + detail : '')); }
}
function hasFinding(result, keyPart, minRisk) {
  return result.findings.some(f => f.key.indexOf(keyPart) !== -1 && (minRisk == null || f.risk >= minRisk));
}
function dump(result) {
  return JSON.stringify(result.findings.map(f => f.key + '=' + f.val), null, 0);
}

/* ---------- テストデータ生成ヘルパー ---------- */
function bytes(...parts) {
  const arrs = parts.map(p => {
    if (typeof p === 'string') return Buffer.from(p, 'latin1');
    if (Buffer.isBuffer(p)) return p;
    return Buffer.from(p);
  });
  return new Uint8Array(Buffer.concat(arrs));
}
function u16be(n) { return [n >> 8 & 255, n & 255]; }
function u32be(n) { return [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255]; }
function u16le(n) { return [n & 255, n >> 8 & 255]; }
function u32le(n) { return [n & 255, n >> 8 & 255, n >>> 16 & 255, n >>> 24 & 255]; }

/* 最小ZIPを構築 (deflate圧縮) */
function makeZip(files) {
  const locals = [], centrals = [];
  let offset = 0;
  for (const f of files) {
    const nameB = Buffer.from(f.name, 'utf-8');
    const raw = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data, 'utf-8');
    const comp = zlib.deflateRawSync(raw);
    const local = Buffer.concat([
      Buffer.from([0x50,0x4B,0x03,0x04, 20,0, 0,0, 8,0, 0,0, 0,0]),
      Buffer.from(u32le(0)),            // crc (検証しないので0)
      Buffer.from(u32le(comp.length)),
      Buffer.from(u32le(raw.length)),
      Buffer.from(u16le(nameB.length)),
      Buffer.from(u16le(0)),
      nameB, comp,
    ]);
    const central = Buffer.concat([
      Buffer.from([0x50,0x4B,0x01,0x02, 20,0, 20,0, 0,0, 8,0, 0,0, 0,0]),
      Buffer.from(u32le(0)),
      Buffer.from(u32le(comp.length)),
      Buffer.from(u32le(raw.length)),
      Buffer.from(u16le(nameB.length)),
      Buffer.from(u16le(0)), Buffer.from(u16le(0)),
      Buffer.from(u16le(0)), Buffer.from(u16le(0)),
      Buffer.from(u32le(0)),
      Buffer.from(u32le(offset)),
      nameB,
    ]);
    locals.push(local);
    centrals.push(central);
    offset += local.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.concat([
    Buffer.from([0x50,0x4B,0x05,0x06, 0,0, 0,0]),
    Buffer.from(u16le(files.length)), Buffer.from(u16le(files.length)),
    Buffer.from(u32le(cd.length)),
    Buffer.from(u32le(offset)),
    Buffer.from(u16le(0)),
  ]);
  return new Uint8Array(Buffer.concat([...locals, cd, eocd]));
}

/* RAR可変長整数 */
function rvint(n) {
  const o = [];
  while (true) { let b = n & 0x7F; n = Math.floor(n / 128); if (n) o.push(b | 0x80); else { o.push(b); break; } }
  return Buffer.from(o);
}
/* 最小RAR5 (storeファイル1個) */
function makeRar5(name, data) {
  const nameB = Buffer.from(name, 'utf-8');
  const dataB = Buffer.from(data, 'latin1');
  const hc = Buffer.concat([
    rvint(2), rvint(2), rvint(dataB.length), rvint(0), rvint(dataB.length),
    rvint(0x20), rvint(0), rvint(0), rvint(nameB.length), nameB,
  ]);
  const block = Buffer.concat([Buffer.from([0xEF, 0xBE, 0xAD, 0xDE]), rvint(hc.length), hc]);
  const sig = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]);
  return new Uint8Array(Buffer.concat([sig, block, dataB]));
}
/* 最小RAR4 (storeファイル1個) */
function makeRar4(name, data) {
  const nameB = Buffer.from(name, 'latin1');
  const dataB = Buffer.from(data, 'latin1');
  const hsize = 32 + nameB.length;
  const hdr = Buffer.concat([
    Buffer.from([0xAA, 0xBB, 0x74, 0x00, 0x80, hsize & 0xFF, (hsize >> 8) & 0xFF]),
    Buffer.from(u32le(dataB.length)), Buffer.from(u32le(dataB.length)),
    Buffer.from([0]), Buffer.from(u32le(0)), Buffer.from(u32le(0)),
    Buffer.from([20, 0x30]), Buffer.from(u16le(nameB.length)), Buffer.from(u32le(0x20)),
    nameB,
  ]);
  const sig = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]);
  return new Uint8Array(Buffer.concat([sig, hdr, dataB]));
}

/* EXIF付き最小JPEG (Artist + GPS) */
function makeJpegWithExif() {
  // TIFFボディ (リトルエンディアン)
  // IFD0: Artist(0x013B, ASCII), GPS IFD pointer(0x8825)
  const artist = 'Taro Yamada\0';
  // レイアウト: ヘッダー8 + IFD0(2+2*12+4=30) -> 38 .. artist(12) -> 50 GPS IFD
  const artistOff = 38;
  const gpsOff = artistOff + artist.length; // 50
  // GPS IFD: 4エントリ (LatRef, Lat, LonRef, Lon) = 2+48+4 = 54 -> 値域は gpsOff+54 = 104
  const latValsOff = gpsOff + 54;
  const lonValsOff = latValsOff + 24;
  const tiff = Buffer.alloc(lonValsOff + 24);
  tiff.write('II', 0, 'latin1');
  tiff.writeUInt16LE(42, 2);
  tiff.writeUInt32LE(8, 4);
  // IFD0
  tiff.writeUInt16LE(2, 8);
  let e = 10;
  // Artist
  tiff.writeUInt16LE(0x013B, e); tiff.writeUInt16LE(2, e+2); tiff.writeUInt32LE(artist.length, e+4); tiff.writeUInt32LE(artistOff, e+8); e += 12;
  // GPS pointer
  tiff.writeUInt16LE(0x8825, e); tiff.writeUInt16LE(4, e+2); tiff.writeUInt32LE(1, e+4); tiff.writeUInt32LE(gpsOff, e+8); e += 12;
  tiff.writeUInt32LE(0, e); // next IFD
  tiff.write(artist, artistOff, 'latin1');
  // GPS IFD
  tiff.writeUInt16LE(4, gpsOff);
  let g = gpsOff + 2;
  // LatRef 'N'
  tiff.writeUInt16LE(1, g); tiff.writeUInt16LE(2, g+2); tiff.writeUInt32LE(2, g+4); tiff.write('N\0', g+8, 'latin1'); g += 12;
  // Lat 3 rationals
  tiff.writeUInt16LE(2, g); tiff.writeUInt16LE(5, g+2); tiff.writeUInt32LE(3, g+4); tiff.writeUInt32LE(latValsOff, g+8); g += 12;
  // LonRef 'E'
  tiff.writeUInt16LE(3, g); tiff.writeUInt16LE(2, g+2); tiff.writeUInt32LE(2, g+4); tiff.write('E\0', g+8, 'latin1'); g += 12;
  // Lon 3 rationals
  tiff.writeUInt16LE(4, g); tiff.writeUInt16LE(5, g+2); tiff.writeUInt32LE(3, g+4); tiff.writeUInt32LE(lonValsOff, g+8); g += 12;
  tiff.writeUInt32LE(0, g);
  // 35° 39' 29.16" N / 139° 42' 1.8" E (渋谷付近)
  const rats = [[35,1],[39,1],[2916,100]];
  rats.forEach((r, i) => { tiff.writeUInt32LE(r[0], latValsOff+i*8); tiff.writeUInt32LE(r[1], latValsOff+i*8+4); });
  const lonRats = [[139,1],[42,1],[18,10]];
  lonRats.forEach((r, i) => { tiff.writeUInt32LE(r[0], lonValsOff+i*8); tiff.writeUInt32LE(r[1], lonValsOff+i*8+4); });

  const exifBody = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff]);
  const app1 = Buffer.concat([Buffer.from([0xFF, 0xE1]), Buffer.from(u16be(exifBody.length + 2)), exifBody]);
  return bytes([0xFF, 0xD8], app1, [0xFF, 0xD9]);
}

/* ---------- テスト本体 ---------- */
async function run() {
  console.log('--- JPEG EXIF (Artist + GPS座標の復号) ---');
  {
    const jpg = makeJpegWithExif();
    const r = await Engine.analyzeBuffer(jpg, { name: 'photo.jpg', size: jpg.length });
    check('Artistを検出', hasFinding(r, '作成者(Artist)', Engine.RISK.HIGH), dump(r));
    check('GPS座標を復号', hasFinding(r, 'GPS位置情報(座標を復号)', Engine.RISK.CRITICAL), dump(r));
    const gps = r.metadata['[EXIF] GPS座標'] || '';
    check('座標値が正しい(35.658...)', gps.indexOf('35.658') === 0 && gps.indexOf('139.700') !== -1, gps);
    check('拡張子一致なので偽装検出なし', !hasFinding(r, '不一致'), dump(r));
  }

  console.log('--- 偽装ファイル (PEをjpgと偽装) ---');
  {
    const fake = bytes('MZ', Buffer.alloc(200));
    const r = await Engine.analyzeBuffer(fake, { name: 'cute_cat.jpg', size: fake.length });
    check('拡張子不一致をCRITICALで検出', hasFinding(r, '不一致', Engine.RISK.CRITICAL), dump(r));
  }

  console.log('--- docx (deflate圧縮されたcore.xmlから作成者を抽出) ---');
  {
    const core = '<?xml version="1.0"?><cp:coreProperties><dc:creator>Hanako Suzuki</dc:creator><cp:lastModifiedBy>Boss</cp:lastModifiedBy><dcterms:created>2024-05-01T10:00:00Z</dcterms:created></cp:coreProperties>';
    const appx = '<Properties><Application>Microsoft Office Word</Application><Company>Example Corp</Company><Template>C:\\Users\\hanako\\Templates\\Normal.dotm</Template></Properties>';
    const zip = makeZip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'docProps/core.xml', data: core },
      { name: 'docProps/app.xml', data: appx },
      { name: 'word/document.xml', data: '<w:document/>' },
    ]);
    const r = await Engine.analyzeBuffer(zip, { name: 'report.docx', size: zip.length });
    check('作成者を検出', hasFinding(r, '作成者') && r.metadata['[Office] 作成者'] === 'Hanako Suzuki', dump(r));
    check('最終更新者を検出', r.metadata['[Office] 最終更新者'] === 'Boss', dump(r));
    check('会社名を検出', hasFinding(r, '会社名', Engine.RISK.HIGH), dump(r));
    check('テンプレートのユーザー名パスを検出', hasFinding(r, 'テンプレートパス', Engine.RISK.HIGH), dump(r));
    check('docx内のdocument.xmlを実行ファイル扱いしない', !hasFinding(r, 'ZIP内に実行可能ファイル'), dump(r));
  }

  console.log('--- docx (VBAマクロ + コメント残存) ---');
  {
    const zip = makeZip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'word/vbaProject.bin', data: 'binarydata' },
      { name: 'word/comments.xml', data: '<comments/>' },
    ]);
    const r = await Engine.analyzeBuffer(zip, { name: 'macro.docm', size: zip.length });
    check('VBAマクロを検出', hasFinding(r, 'VBAマクロ', Engine.RISK.CRITICAL), dump(r));
    check('コメント残存を検出', hasFinding(r, 'コメント(レビュー履歴)'), dump(r));
  }

  console.log('--- PDF (メタデータが末尾にある場合) ---');
  {
    const head = '%PDF-1.7\n';
    const filler = 'x'.repeat(200 * 1024); // 先頭64KBを超えさせる
    const tail = '1 0 obj << /Author (Ichiro Tanaka) /Creator (Microsoft Word) /CreationDate (D:20240501120000+09\'00\') >> endobj\ntrailer\n%%EOF';
    const pdf = bytes(head, filler, tail);
    const r = await Engine.analyzeBuffer(pdf, { name: 'doc.pdf', size: pdf.length });
    check('末尾のAuthorを検出', hasFinding(r, 'PDF: 作成者') && r.metadata['[PDF] 作成者'] === 'Ichiro Tanaka', dump(r));
    check('日付を整形', (r.metadata['[PDF] 作成日時'] || '').indexOf('2024-05-01') === 0, r.metadata['[PDF] 作成日時']);
  }

  console.log('--- PDF (JavaScript埋め込み) ---');
  {
    const pdf = bytes('%PDF-1.4\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n%%EOF');
    const r = await Engine.analyzeBuffer(pdf, { name: 'evil.pdf', size: pdf.length });
    check('JavaScriptをCRITICALで検出', hasFinding(r, 'JavaScript', Engine.RISK.CRITICAL), dump(r));
  }

  console.log('--- MP3 ID3v2.4 (syncsafeフレームサイズ) ---');
  {
    // TXXX: enc(1) + "desc\0value"
    const frameBody = Buffer.from('\x03MyTag\x00Encoded by hanako-PC', 'latin1');
    const frame = Buffer.concat([
      Buffer.from('TXXX', 'latin1'),
      // syncsafeサイズ
      Buffer.from([(frameBody.length >> 21) & 0x7F, (frameBody.length >> 14) & 0x7F, (frameBody.length >> 7) & 0x7F, frameBody.length & 0x7F]),
      Buffer.from([0, 0]),
      frameBody,
    ]);
    const tagSize = frame.length;
    const hdr = Buffer.from([0x49,0x44,0x33, 4, 0, 0, (tagSize>>21)&0x7F, (tagSize>>14)&0x7F, (tagSize>>7)&0x7F, tagSize&0x7F]);
    const mp3 = bytes(hdr, frame, [0xFF, 0xFB], Buffer.alloc(100));
    const r = await Engine.analyzeBuffer(mp3, { name: 'song.mp3', size: mp3.length });
    check('v2.4のTXXXを正しく読む', hasFinding(r, 'TXXX') && (r.metadata['[ID3] ユーザー定義テキスト']||'').indexOf('hanako-PC') !== -1, dump(r) + ' meta=' + JSON.stringify(r.metadata['[ID3] ユーザー定義テキスト']));
  }

  console.log('--- GZIP (元ファイル名) ---');
  {
    const gz = zlib.gzipSync(Buffer.from('hello'), {});
    // Node のgzipSyncはFNAMEを付けないので手で作る
    const body = zlib.deflateRawSync(Buffer.from('hello'));
    const manual = bytes([0x1F,0x8B,8, 8], u32le(1715000000), [0,0], 'backup_C_Users_taro.tar\0', body, u32le(0), u32le(5));
    const r = await Engine.analyzeBuffer(manual, { name: 'backup.gz', size: manual.length });
    check('元ファイル名を検出', hasFinding(r, 'GZIP: 元ファイル名'), dump(r));
    check('gzipSync出力もクラッシュしない', !!(await Engine.analyzeBuffer(new Uint8Array(gz), { name: 'a.gz', size: gz.length })));
  }

  console.log('--- FLAC (Vorbisコメント / LOCATION) ---');
  {
    const vendor = 'reference libFLAC';
    const comments = ['ARTIST=Yamada Band', 'LOCATION=35.6595,139.7005'];
    let vc = Buffer.concat([
      Buffer.from(u32le(vendor.length)), Buffer.from(vendor, 'latin1'),
      Buffer.from(u32le(comments.length)),
      ...comments.map(c => Buffer.concat([Buffer.from(u32le(c.length)), Buffer.from(c, 'latin1')])),
    ]);
    const block = Buffer.concat([Buffer.from([0x84, (vc.length>>16)&255, (vc.length>>8)&255, vc.length&255]), vc]);
    const flac = bytes('fLaC', block);
    const r = await Engine.analyzeBuffer(flac, { name: 'music.flac', size: flac.length });
    check('LOCATIONをCRITICALで検出', hasFinding(r, 'LOCATION', Engine.RISK.CRITICAL), dump(r));
  }

  console.log('--- PE (タイムスタンプ + ビルドパス) ---');
  {
    const pe = Buffer.alloc(512);
    pe.write('MZ', 0, 'latin1');
    pe.writeUInt32LE(128, 0x3C);
    pe.write('PE\0\0', 128, 'latin1');
    pe.writeUInt16LE(0x8664, 132);          // machine
    pe.writeUInt32LE(1715000000, 136);      // timestamp (2024年)
    pe.writeUInt16LE(0x20B, 152);           // optional magic
    pe.write('C:\\Users\\taro\\source\\app\\app.pdb', 300, 'latin1');
    const r = await Engine.analyzeBuffer(new Uint8Array(pe), { name: 'tool.exe', size: pe.length });
    check('アーキテクチャ判定', r.metadata['[PE] アーキテクチャ'] === 'x64(64bit)', r.metadata['[PE] アーキテクチャ']);
    check('ビルドパス(ユーザー名)を検出', hasFinding(r, 'ビルドパス', Engine.RISK.HIGH), dump(r));
    check('ホームディレクトリパスも汎用検出', hasFinding(r, 'ホームディレクトリ'), dump(r));
  }

  console.log('--- 認証情報スキャン ---');
  {
    const txt = bytes('config:\n  aws_key: AKIAIOSFODNN7EXAMPLE\n  password = hunter22\n  mail: taro.yamada@example-company.jp\n');
    const r = await Engine.analyzeBuffer(txt, { name: 'config.txt', size: txt.length });
    check('AWSキーを検出', hasFinding(r, 'AWS', Engine.RISK.CRITICAL), dump(r));
    check('パスワードを検出', hasFinding(r, 'パスワード', Engine.RISK.CRITICAL), dump(r));
    check('メールアドレスを検出', hasFinding(r, 'メールアドレス', Engine.RISK.HIGH), dump(r));
  }

  console.log('--- 誤検出の抑制 ---');
  {
    // 高エントロピーだが正常な圧縮形式 (ランダムデータをPNGに見せる)
    const rnd = Buffer.alloc(70000);
    for (let i = 0; i < rnd.length; i++) rnd[i] = Math.floor(Math.random() * 256);
    const png = bytes([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A], u32be(13), 'IHDR', Buffer.alloc(17), rnd);
    const r = await Engine.analyzeBuffer(png, { name: 'image.png', size: png.length });
    check('PNGの高エントロピーを警告しない', !hasFinding(r, '高エントロピー'), dump(r));
    // ID3なしMP3を偽装と誤判定しない
    const mp3raw = bytes([0xFF, 0xFB, 0x90, 0x00], Buffer.alloc(100));
    const r2 = await Engine.analyzeBuffer(mp3raw, { name: 'raw.mp3', size: mp3raw.length });
    check('ID3なしMP3を偽装と誤判定しない', !hasFinding(r2, '不一致'), dump(r2));
    // バージョン番号をIPと誤検出しない
    const v = bytes('app version 1.2.3.4 released');
    const r3 = await Engine.analyzeBuffer(v, { name: 'notes.txt', size: v.length });
    check('1.2.3.4をIPとして検出しない', !hasFinding(r3, 'IPアドレス'), dump(r3));
  }

  console.log('--- ファイル名偽装 ---');
  {
    const pe = bytes('MZ', Buffer.alloc(100));
    const r = await Engine.analyzeBuffer(pe, { name: 'invoice.pdf.exe', size: pe.length });
    check('二重拡張子をCRITICALで検出', hasFinding(r, '二重拡張子', Engine.RISK.CRITICAL), dump(r));
  }

  console.log('--- ZIP (実行ファイル入り + 暗号化なし通常ZIP) ---');
  {
    const zip = makeZip([
      { name: 'readme.txt', data: 'hello' },
      { name: 'install.exe', data: 'MZfake' },
    ]);
    const r = await Engine.analyzeBuffer(zip, { name: 'archive.zip', size: zip.length });
    check('ZIP内の実行ファイルを検出', hasFinding(r, 'ZIP内に実行可能ファイル', Engine.RISK.HIGH), dump(r));
  }

  console.log('--- PNG tEXt ---');
  {
    const txt = 'Author\0Jiro Sato';
    const chunk = bytes(u32be(txt.length), 'tEXt', txt, u32be(0));
    const png = bytes([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A], u32be(13), 'IHDR', Buffer.alloc(17), chunk, u32be(0), 'IEND', u32be(0));
    const r = await Engine.analyzeBuffer(png, { name: 'img.png', size: png.length });
    check('PNG Authorを検出', hasFinding(r, 'PNGテキスト: Author'), dump(r));
  }

  console.log('--- RTF ---');
  {
    const rtf = bytes('{\\rtf1\\ansi{\\info{\\author Saburo Kato}{\\company ACME Inc}{\\creatim\\yr2024\\mo5\\dy1}}body}');
    const r = await Engine.analyzeBuffer(rtf, { name: 'memo.rtf', size: rtf.length });
    check('RTF作成者を検出', hasFinding(r, 'RTF: 作成者', Engine.RISK.HIGH), dump(r));
    check('RTF作成日を検出', hasFinding(r, 'RTF: 作成日'), dump(r));
  }

  console.log('--- SVG (スクリプト埋め込み) ---');
  {
    const svg = bytes('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
    const r = await Engine.analyzeBuffer(svg, { name: 'icon.svg', size: svg.length });
    check('SVG内スクリプトをCRITICALで検出', hasFinding(r, 'スクリプト埋め込み', Engine.RISK.CRITICAL), dump(r));
  }

  console.log('--- LNK ---');
  {
    const lnk = Buffer.alloc(400);
    Buffer.from([0x4C,0,0,0, 0x01,0x14,0x02,0x00]).copy(lnk, 0);
    Buffer.from('C:\\Users\\taro\\Documents\\secret.docx', 'utf16le').copy(lnk, 100);
    const r = await Engine.analyzeBuffer(new Uint8Array(lnk), { name: 'doc.lnk', size: lnk.length });
    check('LNKを警告', hasFinding(r, 'ショートカットファイル', Engine.RISK.HIGH), dump(r));
    check('LNK参照パスを検出', hasFinding(r, 'LNK: 参照パス'), dump(r));
  }

  /* ============ v2.1 追加機能 ============ */

  console.log('--- EXIFサムネイル残存 (IFD1) ---');
  {
    // IFD0(Artist 1件) → IFD1(0x0201/0x0202) → 偽サムネイルJPEG
    const thumbJpeg = Buffer.concat([Buffer.from([0xFF,0xD8]), Buffer.alloc(40, 0x41), Buffer.from([0xFF,0xD9])]);
    const ifd1Off = 8 + 2 + 12 + 4;          // ヘッダー8 + IFD0(1エントリ)
    const thumbOff = ifd1Off + 2 + 24 + 4;    // IFD1(2エントリ)の後ろ
    const tiff = Buffer.alloc(thumbOff + thumbJpeg.length);
    tiff.write('II', 0, 'latin1'); tiff.writeUInt16LE(42, 2); tiff.writeUInt32LE(8, 4);
    tiff.writeUInt16LE(1, 8);                                   // IFD0: 1エントリ
    tiff.writeUInt16LE(0x0131, 10); tiff.writeUInt16LE(2, 12);  // Software (ダミー)
    tiff.writeUInt32LE(4, 14); tiff.write('App\0', 18, 'latin1');
    tiff.writeUInt32LE(ifd1Off, 22);                            // next IFD → IFD1
    tiff.writeUInt16LE(2, ifd1Off);
    tiff.writeUInt16LE(0x0201, ifd1Off+2); tiff.writeUInt16LE(4, ifd1Off+4);
    tiff.writeUInt32LE(1, ifd1Off+6); tiff.writeUInt32LE(thumbOff, ifd1Off+10);
    tiff.writeUInt16LE(0x0202, ifd1Off+14); tiff.writeUInt16LE(4, ifd1Off+16);
    tiff.writeUInt32LE(1, ifd1Off+18); tiff.writeUInt32LE(thumbJpeg.length, ifd1Off+22);
    tiff.writeUInt32LE(0, ifd1Off+26);
    thumbJpeg.copy(tiff, thumbOff);
    const exifBody = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff]);
    const app1 = Buffer.concat([Buffer.from([0xFF,0xE1]), Buffer.from(u16be(exifBody.length+2)), exifBody]);
    const jpg = bytes([0xFF,0xD8], app1, [0xFF,0xD9]);
    const r = await Engine.analyzeBuffer(jpg, { name:'edited.jpg', size:jpg.length });
    check('サムネイル残存を検出', hasFinding(r, 'EXIFサムネイル残存', Engine.RISK.HIGH), dump(r));
    check('サムネイルのバイト列を返す', r.thumbnail && r.thumbnail.length === thumbJpeg.length, String(r.thumbnail && r.thumbnail.length));
  }

  console.log('--- JPEG終端以降の余剰データ ---');
  {
    const jpg = bytes([0xFF,0xD8, 0xFF,0xDA, 0x00,0x04, 0x01,0x02], [0x10,0x20,0x30], [0xFF,0xD9], 'PK\x03\x04hidden-archive-data');
    const r = await Engine.analyzeBuffer(jpg, { name:'photo.jpg', size:jpg.length });
    check('余剰データを検出', hasFinding(r, '余剰データ', Engine.RISK.HIGH), dump(r));
  }

  console.log('--- PDF増分更新(旧版残存) ---');
  {
    const pdf = bytes('%PDF-1.4\n1 0 obj << /Author (Old Name) >>\n%%EOF\n2 0 obj << /Type /Page >>\n%%EOF');
    const r = await Engine.analyzeBuffer(pdf, { name:'redacted.pdf', size:pdf.length });
    check('増分更新を検出', hasFinding(r, '旧バージョンの内容が残存', Engine.RISK.HIGH), dump(r));
    const lin = bytes('%PDF-1.4\n1 0 obj << /Linearized 1 >>\n%%EOF\ncontent\n%%EOF');
    const r2 = await Engine.analyzeBuffer(lin, { name:'fast.pdf', size:lin.length });
    check('リニアライズPDF(EOF2個)は誤検出しない', !hasFinding(r2, '旧バージョン'), dump(r2));
  }

  console.log('--- Excel非表示シート / PowerPointノート / Word変更履歴 ---');
  {
    const wb = '<workbook><sheets><sheet name="売上" sheetId="1" r:id="rId1"/><sheet name="原価データ" sheetId="2" state="veryHidden" r:id="rId2"/></sheets></workbook>';
    const xlsx = makeZip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'xl/workbook.xml', data: wb },
    ]);
    const r = await Engine.analyzeBuffer(xlsx, { name:'budget.xlsx', size:xlsx.length });
    check('veryHiddenシートを検出', hasFinding(r, '完全非表示シート', Engine.RISK.HIGH) && (r.metadata['[Office] 非表示シート(veryHidden)']||'').indexOf('原価データ') !== -1, dump(r));

    const notes = '<p:notes><a:t>このスライドは社外秘の数字を含む</a:t></p:notes>';
    const pptx = makeZip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'ppt/notesSlides/notesSlide1.xml', data: notes },
    ]);
    const r2 = await Engine.analyzeBuffer(pptx, { name:'deck.pptx', size:pptx.length });
    check('発表者ノートを検出', hasFinding(r2, '発表者ノート'), dump(r2));

    const doc = '<w:document><w:ins w:author="Taro Yamada" w:date="2024-01-01"><w:r><w:t>追記</w:t></w:r></w:ins></w:document>';
    const docx = makeZip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'word/document.xml', data: doc },
    ]);
    const r3 = await Engine.analyzeBuffer(docx, { name:'draft.docx', size:docx.length });
    check('未承認の変更履歴を検出', hasFinding(r3, '変更履歴が残存', Engine.RISK.HIGH), dump(r3));
  }

  console.log('--- ZIP再帰スキャン (ZIP内のJPEGのGPS) ---');
  {
    const jpg = makeJpegWithExif();
    const zip = makeZip([
      { name: 'photos/photo.jpg', data: Buffer.from(jpg) },
      { name: 'readme.txt', data: 'hello' },
    ]);
    const r = await Engine.analyzeBuffer(zip, { name:'album.zip', size:zip.length });
    check('内包JPEGのGPSを検出', r.findings.some(f => f.category === '内包ファイル' && f.key.indexOf('GPS位置情報') !== -1), dump(r));
  }

  console.log('--- SHA-256 ---');
  {
    const data = bytes('hello world');
    const r = await Engine.analyzeBuffer(data, { name:'a.txt', size:data.length });
    check('SHA-256を計算', r.metadata['SHA-256'] === 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9', r.metadata['SHA-256']);
  }

  console.log('--- クリーナー: JPEG ---');
  {
    const jpg = makeJpegWithExif();
    const out = await Cleaner.clean(jpg, 'photo.jpg');
    check('EXIFを除去リストに記録', out.removed.some(s => s.indexOf('EXIF') !== -1), JSON.stringify(out.removed));
    const re = await Engine.analyzeBuffer(out.bytes, { name:'photo_clean.jpg', size:out.bytes.length });
    check('除去後はGPS・Artistなし', !hasFinding(re, 'GPS') && !hasFinding(re, 'Artist'), dump(re));
    check('JPEGとして妥当なまま', re.metadata['ファイル形式（マジック）'] === 'JPEG画像', re.metadata['ファイル形式（マジック）']);
  }

  console.log('--- クリーナー: PNG / MP3 ---');
  {
    const txt = 'Author\0Jiro Sato';
    const chunk = bytes(u32be(txt.length), 'tEXt', txt, u32be(0));
    const png = bytes([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A], u32be(13), 'IHDR', Buffer.alloc(17), chunk, u32be(0), 'IEND', u32be(0));
    const outP = await Cleaner.clean(png, 'img.png');
    const reP = await Engine.analyzeBuffer(outP.bytes, { name:'img_clean.png', size:outP.bytes.length });
    check('PNG: tEXt除去後にAuthorなし', !hasFinding(reP, 'PNGテキスト'), dump(reP));

    const id3 = Buffer.concat([
      Buffer.from([0x49,0x44,0x33, 3, 0, 0, 0, 0, 0, 20]),
      Buffer.alloc(20),
    ]);
    const mp3 = bytes(id3, [0xFF,0xFB,0x90,0x00], Buffer.alloc(50), 'TAG', Buffer.alloc(125));
    const outM = await Cleaner.clean(mp3, 'song.mp3');
    check('MP3: ID3v2とID3v1を除去', outM.removed.length === 2 && outM.bytes[0] === 0xFF && outM.bytes[1] === 0xFB, JSON.stringify(outM.removed) + ' head=' + outM.bytes[0]);
  }

  console.log('--- クリーナー: docx (ZIP再構築) ---');
  {
    const core = '<?xml version="1.0"?><cp:coreProperties><dc:creator>Hanako Suzuki</dc:creator><cp:lastModifiedBy>Boss</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">2024-05-01T10:00:00Z</dcterms:created></cp:coreProperties>';
    const appx = '<Properties><Application>Word</Application><Company>Example Corp</Company><Template>C:\\Users\\hanako\\Normal.dotm</Template></Properties>';
    const zip = makeZip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'docProps/core.xml', data: core },
      { name: 'docProps/app.xml', data: appx },
      { name: 'word/document.xml', data: '<w:document><w:body>本文テキスト</w:body></w:document>' },
    ]);
    const out = await Cleaner.clean(zip, 'report.docx');
    const re = await Engine.analyzeBuffer(out.bytes, { name:'report_clean.docx', size:out.bytes.length });
    check('除去後に作成者なし', !hasFinding(re, 'Office: 作成者') && !hasFinding(re, '最終更新者'), dump(re));
    check('除去後に会社名・テンプレートパスなし', !hasFinding(re, '会社名') && !hasFinding(re, 'テンプレートパス'), dump(re));
    check('ZIPとして読み戻せる(本文維持)', (re.metadata['[ZIP] エントリ数'] === '4'), re.metadata['[ZIP] エントリ数']);
    // 本文が壊れていないことを実際に展開して確認
    const reEntries = [];
    {
      const zi = require('./engine.js').zip.listEntries(out.bytes);
      for (const e of zi.entries) {
        const d = await require('./engine.js').zip.readEntry(out.bytes, e);
        reEntries.push({ name: e.name, ok: d != null, text: d ? Buffer.from(d).toString('utf-8') : '' });
      }
    }
    const docEntry = reEntries.find(e => e.name === 'word/document.xml');
    check('再構築後も本文が一致', docEntry && docEntry.text.indexOf('本文テキスト') !== -1, JSON.stringify(reEntries.map(e => e.name + ':' + e.ok)));
    check('CRC32がzlibと一致', Cleaner.crc32(new Uint8Array(Buffer.from('hello'))) === zlib.crc32(Buffer.from('hello')), String(Cleaner.crc32(new Uint8Array(Buffer.from('hello')))));
  }

  console.log('--- 秘密鍵検出 (テキスト形式) ---');
  {
    const pem = bytes('-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk...\n-----END OPENSSH PRIVATE KEY-----');
    const r1 = await Engine.analyzeBuffer(pem, { name:'backup.txt', size:pem.length });
    check('OpenSSH秘密鍵(PEM)を検出', hasFinding(r1, '秘密鍵(PEM)', Engine.RISK.CRITICAL), dump(r1));

    const pgp = bytes('-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQVYBF...\n-----END PGP PRIVATE KEY BLOCK-----');
    const r2 = await Engine.analyzeBuffer(pgp, { name:'key.asc', size:pgp.length });
    check('PGP秘密鍵を検出', hasFinding(r2, 'PGP秘密鍵', Engine.RISK.CRITICAL), dump(r2));

    const ppk = bytes('PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPrivate-Lines: 1\n');
    const r3 = await Engine.analyzeBuffer(ppk, { name:'server.ppk', size:ppk.length });
    check('PuTTY秘密鍵を検出', hasFinding(r3, 'PuTTY秘密鍵', Engine.RISK.CRITICAL), dump(r3));

    const aws = bytes('[default]\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n');
    const r4 = await Engine.analyzeBuffer(aws, { name:'credentials', size:aws.length });
    check('AWSシークレットキーを検出', hasFinding(r4, 'AWSシークレット', Engine.RISK.CRITICAL), dump(r4));
    check('credentialsファイル名も警告', hasFinding(r4, '認証情報ファイル', Engine.RISK.HIGH), dump(r4));

    const gcp = bytes('{"type": "service_account", "project_id": "my-proj", "private_key": "-----BEGIN PRIVATE KEY-----\\n..."}');
    const r5 = await Engine.analyzeBuffer(gcp, { name:'service.json', size:gcp.length });
    check('GCPサービスアカウントJSONを検出', hasFinding(r5, 'GCPサービスアカウント', Engine.RISK.CRITICAL), dump(r5));
  }

  console.log('--- 秘密鍵検出 (バイナリ・ファイル名) ---');
  {
    const jks = bytes([0xFE,0xED,0xFE,0xED], Buffer.alloc(64));
    const r1 = await Engine.analyzeBuffer(jks, { name:'release.jks', size:jks.length });
    check('Javaキーストアを検出', hasFinding(r1, 'Javaキーストア', Engine.RISK.CRITICAL), dump(r1));

    const pfx = bytes([0x30,0x82,0x0A,0x00], Buffer.alloc(64));
    const r2 = await Engine.analyzeBuffer(pfx, { name:'cert.pfx', size:pfx.length });
    check('PKCS#12キーストアを検出', hasFinding(r2, 'PKCS#12', Engine.RISK.CRITICAL), dump(r2));

    const sshKey = bytes('dummy-binary-content');
    const r3 = await Engine.analyzeBuffer(sshKey, { name:'id_rsa', size:sshKey.length });
    check('id_rsaファイル名を警告', hasFinding(r3, 'SSH秘密鍵ファイル', Engine.RISK.CRITICAL), dump(r3));

    const pub = bytes('ssh-rsa AAAAB3Nza... user@host');
    const r4 = await Engine.analyzeBuffer(pub, { name:'id_rsa.pub', size:pub.length });
    check('公開鍵(id_rsa.pub)は警告しない', !hasFinding(r4, 'SSH秘密鍵ファイル'), dump(r4));
  }

  console.log('--- ZIP内の.env / id_rsa を再帰検出 ---');
  {
    const zip = makeZip([
      { name: 'project/src/app.js', data: 'console.log(1)' },
      { name: 'project/.env', data: 'AWS_KEY=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=hunter22' },
      { name: 'project/.ssh/id_rsa', data: '-----BEGIN OPENSSH PRIVATE KEY-----\nxxx\n-----END OPENSSH PRIVATE KEY-----' },
    ]);
    const r = await Engine.analyzeBuffer(zip, { name:'project-backup.zip', size:zip.length });
    check('ZIP内の.envのAWSキーを検出', r.findings.some(f => f.category === '内包ファイル' && f.key.indexOf('AWS') !== -1), dump(r));
    check('ZIP内のid_rsaの秘密鍵を検出', r.findings.some(f => f.category === '内包ファイル' && f.key.indexOf('秘密鍵') !== -1), dump(r));
  }

  console.log('--- RAR5 (ファイル一覧 + store内包スキャン) ---');
  {
    const rar5 = makeRar5('.env', 'AWS_KEY=AKIAIOSFODNN7EXAMPLE\nPASSWORD=hunter2222');
    const r = await Engine.analyzeBuffer(rar5, { name:'backup.rar', size:rar5.length });
    check('RAR5と判定', r.metadata['[RAR] バージョン'] === 'RAR 5.x', r.metadata['[RAR] バージョン']);
    check('エントリ名を取得', (r.metadata['[RAR] 含有ファイル']||'').indexOf('.env') !== -1, r.metadata['[RAR] 含有ファイル']);
    check('store内包の秘密情報を検出', r.findings.some(f => f.category === '内包ファイル' && f.key.indexOf('AWS') !== -1), dump(r));
  }

  console.log('--- RAR4 (実行ファイル混入) ---');
  {
    const rar4 = makeRar4('installer.exe', 'MZ' + 'x'.repeat(40));
    const r = await Engine.analyzeBuffer(rar4, { name:'tool.rar', size:rar4.length });
    check('RAR4と判定', r.metadata['[RAR] バージョン'] === 'RAR 4.x', r.metadata['[RAR] バージョン']);
    check('RAR内の実行ファイルを検出', hasFinding(r, 'RAR内に実行可能ファイル', Engine.RISK.HIGH), dump(r));
  }

  console.log('--- 7z (7z.exeがあれば実ファイルで検証) ---');
  {
    const sevenZip = [
      (process.env.ProgramFiles || '') + '\\7-Zip\\7z.exe',
      (process.env['ProgramFiles(x86)'] || '') + '\\7-Zip\\7z.exe',
    ].find(p => { try { return fs.existsSync(p); } catch (e) { return false; } });
    if (!sevenZip) {
      console.log('  SKIP (7z.exe が見つかりません)');
    } else {
      const os = require('os'); const cp = require('child_process');
      const tmp = fs.mkdtempSync(require('path').join(os.tmpdir(), 'ms7z-'));
      const arc = require('path').join(os.tmpdir(), 'ms-test-' + Date.now() + '.7z');
      try {
        fs.writeFileSync(require('path').join(tmp, 'readme.txt'), 'hello');
        fs.writeFileSync(require('path').join(tmp, 'secret.env'), 'AWS_KEY=AKIAIOSFODNN7EXAMPLE');
        fs.writeFileSync(require('path').join(tmp, 'run.exe'), 'MZ');
        // LZMA圧縮ヘッダー(既定)
        cp.execFileSync(sevenZip, ['a', arc, tmp + '\\*'], { stdio: 'ignore' });
        const b1 = new Uint8Array(fs.readFileSync(arc));
        const r1 = await Engine.analyzeBuffer(b1, { name: 'a.7z', size: b1.length });
        check('7z: LZMAヘッダーを展開してファイル名取得', (r1.metadata['[7z] 含有ファイル']||'').indexOf('secret.env') !== -1, r1.metadata['[7z] 含有ファイル']);
        check('7z: 実行ファイルを検出', hasFinding(r1, '7z内に実行可能ファイル', Engine.RISK.HIGH), dump(r1));
        fs.unlinkSync(arc);
        // 無圧縮(Copy) → 内包の秘密情報まで検出
        cp.execFileSync(sevenZip, ['a', '-mx0', '-mhc=off', arc, tmp + '\\*'], { stdio: 'ignore' });
        const b2 = new Uint8Array(fs.readFileSync(arc));
        const r2 = await Engine.analyzeBuffer(b2, { name: 'b.7z', size: b2.length });
        check('7z: 無圧縮の内包.envからAWSキー検出', r2.findings.some(f => f.category === '内包ファイル' && f.key.indexOf('AWS') !== -1), dump(r2));
        fs.unlinkSync(arc);
        // LZMA2(既定圧縮) → 中身を展開してファイル単位で検出 (ssh.7z相当のケース)
        fs.writeFileSync(require('path').join(tmp, 'id_ed25519'), '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----\n');
        cp.execFileSync(sevenZip, ['a', '-m0=lzma2', arc, tmp + '\\*'], { stdio: 'ignore' });
        const b3 = new Uint8Array(fs.readFileSync(arc));
        const r3 = await Engine.analyzeBuffer(b3, { name: 'c.7z', size: b3.length });
        check('7z: LZMA2の中身から秘密鍵を検出', r3.findings.some(f => f.category === '内包ファイル' && f.key.indexOf('秘密鍵') !== -1), dump(r3));
        check('7z: 名前ベースでもid_ed25519を警告', r3.findings.some(f => f.key.indexOf('SSH秘密鍵ファイル') !== -1 && f.risk === Engine.RISK.CRITICAL), dump(r3));
        check('7z: LZMA2の中身からAWSキーを検出(ファイル名付き)', r3.findings.some(f => f.category === '内包ファイル' && f.key.indexOf('secret.env') !== -1 && f.key.indexOf('AWS') !== -1), dump(r3));
        fs.unlinkSync(arc);
        // LZMA2マルチチャンク (2MB超のデータ末尾にシークレット → チャンクまたぎの展開を検証)
        const big = 'A'.repeat(3 * 1024 * 1024) + '\naws_key=AKIAIOSFODNN7EXAMPLE\n';
        fs.writeFileSync(require('path').join(tmp, 'big.log'), big);
        cp.execFileSync(sevenZip, ['a', '-m0=lzma2', arc, require('path').join(tmp, 'big.log')], { stdio: 'ignore' });
        const b4 = new Uint8Array(fs.readFileSync(arc));
        const r4 = await Engine.analyzeBuffer(b4, { name: 'd.7z', size: b4.length });
        check('7z: マルチチャンクLZMA2末尾のAWSキーを検出', r4.findings.some(f => f.category === '内包ファイル' && f.key.indexOf('AWS') !== -1), dump(r4));
        fs.unlinkSync(arc);
      } finally {
        try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e) {}
        try { if (fs.existsSync(arc)) fs.unlinkSync(arc); } catch (e) {}
      }
    }
  }

  console.log('--- クリーナー: 非対応形式の理由提示 ---');
  {
    const pdf = bytes('%PDF-1.4\ncontent\n%%EOF');
    const s = Cleaner.supports('doc.pdf', pdf);
    check('PDFは非対応+理由つき', !s.ok && s.reason.indexOf('PDF') !== -1, JSON.stringify(s));
  }

  console.log('\n結果: ' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
}

run().catch(e => { console.error(e); process.exit(1); });
