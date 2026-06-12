/* =========================================================
 * MetaScan 解析エンジン
 * ブラウザ(Electronレンダラー)と Node.js の両方で動作する。
 * 公開API: analyzeBuffer(bytes, info) -> Promise<{metadata, findings, truncated}>
 * ========================================================= */
(function(global){
'use strict';

var RISK = { NONE:0, LOW:1, MEDIUM:2, HIGH:3, CRITICAL:4 };

/* LZMAデコーダー (7z展開用)。Nodeはrequire、ブラウザはグローバル */
var LZMA = (typeof require!=='undefined' && typeof module!=='undefined' && module.exports)
  ? (function(){ try{ return require('./lzma.js'); }catch(e){ return null; } })()
  : (global.MetaScanLZMA || null);

/* ---------- バイト読み取りヘルパー ---------- */
function u16le(b,o){ return b[o] | (b[o+1]<<8); }
function u32le(b,o){ return (b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)) >>> 0; }
function u16be(b,o){ return (b[o]<<8) | b[o+1]; }
function u32be(b,o){ return ((b[o]<<24) | (b[o+1]<<16) | (b[o+2]<<8) | b[o+3]) >>> 0; }
function ascii(b,o,n){
  var s=''; for(var i=0;i<n && o+i<b.length;i++) s+=String.fromCharCode(b[o+i]);
  return s;
}
function decode(b,enc){
  try{ return new TextDecoder(enc||'utf-8',{fatal:false}).decode(b); }catch(e){ return ''; }
}
function fmtBytes(n){
  if(n<1024) return n+' B';
  if(n<1048576) return (n/1024).toFixed(1)+' KB';
  if(n<1073741824) return (n/1048576).toFixed(2)+' MB';
  return (n/1073741824).toFixed(2)+' GB';
}
function xmlDecode(s){
  return String(s)
    .replace(/&#x([0-9a-fA-F]+);/g,function(_,h){return String.fromCodePoint(parseInt(h,16));})
    .replace(/&#(\d+);/g,function(_,d){return String.fromCodePoint(parseInt(d,10));})
    .replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"')
    .replace(/&apos;/g,"'").replace(/&amp;/g,'&');
}
function clean(s){ return String(s).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g,'').trim(); }

/* deflate-raw の展開。Node(Electronメイン/CLI/テスト)ではzlib、それ以外はDecompressionStream */
function inflateRaw(data){
  if(typeof require!=='undefined' && typeof process!=='undefined' && process.versions && process.versions.node){
    try{ return Promise.resolve(new Uint8Array(require('zlib').inflateRawSync(data))); }catch(e){ return Promise.resolve(null); }
  }
  if(typeof DecompressionStream==='undefined') return Promise.resolve(null);
  try{
    var ds = new DecompressionStream('deflate-raw');
    var resp = new Response(new Blob([data]).stream().pipeThrough(ds));
    return resp.arrayBuffer().then(function(buf){ return new Uint8Array(buf); })
      .catch(function(){ return null; });
  }catch(e){ return Promise.resolve(null); }
}

function F(key,val,why,risk,category){
  return { key:key, val:clean(String(val)).substring(0,300), why:why, risk:risk, category:category };
}

/* ---------- マジックバイト判定 ---------- */
function detectMagic(b){
  function eq(o,arr){ for(var i=0;i<arr.length;i++){ if(b[o+i]!==arr[i]) return false; } return true; }
  if(b.length<4) return null;
  if(eq(0,[0xFF,0xD8,0xFF])) return {id:'jpeg', label:'JPEG画像'};
  if(eq(0,[0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A])) return {id:'png', label:'PNG画像'};
  if(eq(0,[0x47,0x49,0x46,0x38])) return {id:'gif', label:'GIF画像'};
  if(eq(0,[0x42,0x4D]) && b.length>26 && u32le(b,2)>0) return {id:'bmp', label:'BMP画像'};
  if(eq(0,[0x00,0x00,0x01,0x00])) return {id:'ico', label:'ICOアイコン'};
  if(eq(0,[0x49,0x49,0x2A,0x00]) || eq(0,[0x4D,0x4D,0x00,0x2A])) return {id:'tiff', label:'TIFF画像'};
  if(eq(0,[0x25,0x50,0x44,0x46])) return {id:'pdf', label:'PDF文書'};
  if(eq(0,[0x50,0x4B,0x03,0x04]) || eq(0,[0x50,0x4B,0x05,0x06])) return {id:'zip', label:'ZIPアーカイブ(Office等含む)'};
  if(eq(0,[0x4D,0x5A])) return {id:'pe', label:'PE実行ファイル(EXE/DLL)'};
  if(eq(0,[0x7F,0x45,0x4C,0x46])) return {id:'elf', label:'ELFバイナリ(Linux)'};
  if(eq(0,[0xCA,0xFE,0xBA,0xBE]) || eq(0,[0xCF,0xFA,0xED,0xFE])) return {id:'macho', label:'Mach-Oバイナリ(macOS)'};
  if(eq(0,[0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1])) return {id:'ole', label:'OLE複合ファイル(旧Office/MSI)'};
  if(eq(0,[0x4C,0x00,0x00,0x00,0x01,0x14,0x02,0x00])) return {id:'lnk', label:'Windowsショートカット(LNK)'};
  if(eq(0,[0x49,0x44,0x33])) return {id:'mp3', label:'MP3音声(ID3タグ付き)'};
  if(b[0]===0xFF && (b[1]&0xE0)===0xE0 && (b[1]&0x18)!==0x08) return {id:'mp3', label:'MP3/MPEG音声'};
  if(eq(0,[0x66,0x4C,0x61,0x43])) return {id:'flac', label:'FLAC音声'};
  if(eq(0,[0x4F,0x67,0x67,0x53])) return {id:'ogg', label:'OGGコンテナ(Vorbis/Opus)'};
  if(eq(0,[0x52,0x49,0x46,0x46])){
    var sub = ascii(b,8,4);
    if(sub==='WEBP') return {id:'webp', label:'WebP画像'};
    if(sub==='WAVE') return {id:'wav', label:'WAV音声'};
    if(sub==='AVI ') return {id:'avi', label:'AVI動画'};
    return {id:'riff', label:'RIFFコンテナ'};
  }
  if(b.length>11 && ascii(b,4,4)==='ftyp'){
    var brand = ascii(b,8,4);
    if(/^(heic|heix|hevc|mif1|msf1|heim|heis)/.test(brand)) return {id:'heic', label:'HEIC/HEIF画像'};
    if(/^avif|^avis/.test(brand)) return {id:'avif', label:'AVIF画像'};
    if(/^qt\s\s/.test(brand)) return {id:'mp4', label:'QuickTime動画(MOV)'};
    return {id:'mp4', label:'MP4/ISOメディア('+clean(brand)+')'};
  }
  if(eq(0,[0x1A,0x45,0xDF,0xA3])) return {id:'mkv', label:'WebM/MKV動画'};
  if(eq(0,[0x37,0x7A,0xBC,0xAF,0x27,0x1C])) return {id:'7z', label:'7-Zipアーカイブ'};
  if(eq(0,[0x52,0x61,0x72,0x21,0x1A,0x07])) return {id:'rar', label:'RARアーカイブ'};
  if(eq(0,[0x1F,0x8B])) return {id:'gzip', label:'GZIP圧縮'};
  if(eq(0,[0x42,0x5A,0x68])) return {id:'bz2', label:'BZIP2圧縮'};
  if(eq(0,[0xFD,0x37,0x7A,0x58,0x5A,0x00])) return {id:'xz', label:'XZ圧縮'};
  if(eq(0,[0x28,0xB5,0x2F,0xFD])) return {id:'zstd', label:'Zstandard圧縮'};
  if(ascii(b,0,5)==='{\\rtf') return {id:'rtf', label:'RTF文書'};
  if(ascii(b,0,15)==='SQLite format 3') return {id:'sqlite', label:'SQLiteデータベース'};
  if(eq(0,[0x00,0x61,0x73,0x6D])) return {id:'wasm', label:'WebAssemblyバイナリ'};
  if(eq(0,[0xCA,0xFE,0xD0,0x0D])) return {id:'class', label:'Javaクラスファイル'};
  if(b.length>262 && ascii(b,257,5)==='ustar') return {id:'tar', label:'TARアーカイブ'};
  if(eq(0,[0xFF,0xFE]) || eq(0,[0xFE,0xFF])) return {id:'utf16', label:'テキストファイル(UTF-16)'};
  /* テキスト判定 (UTF-8 BOM・日本語マルチバイト許容) */
  var start = eq(0,[0xEF,0xBB,0xBF]) ? 3 : 0;
  var bin=0, n=Math.min(1024,b.length);
  for(var i=start;i<n;i++){
    var v=b[i];
    if(v===0){ bin=999; break; }
    if(v<0x20 && v!==0x09 && v!==0x0A && v!==0x0D) bin++;
  }
  if(bin<4 && n>start){
    var head = decode(b.slice(start, Math.min(b.length, start+2048))).trimStart().toLowerCase();
    if(head.indexOf('<!doctype html')===0 || head.indexOf('<html')===0) return {id:'html', label:'HTML文書'};
    if(head.indexOf('<svg')===0 || (head.indexOf('<?xml')===0 && head.indexOf('<svg')!==-1)) return {id:'svg', label:'SVG画像'};
    if(head.indexOf('<?xml')===0) return {id:'xml', label:'XML文書'};
    if(head.indexOf('%pdf')===0) return {id:'pdf', label:'PDF文書'};
    return {id:'text', label:'テキストファイル'};
  }
  return null;
}

/* 拡張子 → 許容されるマジックID(複数可)。不一致のみ偽装を疑う */
var EXT_EXPECT = {
  jpg:['jpeg'], jpeg:['jpeg'], jfif:['jpeg'],
  png:['png'], gif:['gif'], bmp:['bmp'], ico:['ico'],
  tif:['tiff'], tiff:['tiff'], webp:['webp'],
  heic:['heic'], heif:['heic'], avif:['avif','heic'],
  pdf:['pdf'],
  zip:['zip'], docx:['zip'], xlsx:['zip'], pptx:['zip'], odt:['zip'], ods:['zip'], odp:['zip'],
  jar:['zip'], apk:['zip'], epub:['zip'], xpi:['zip'],
  exe:['pe'], dll:['pe'], sys:['pe'], scr:['pe'], msi:['ole'],
  doc:['ole','zip','rtf'], xls:['ole','zip'], ppt:['ole','zip'], rtf:['rtf','text'],
  mp3:['mp3'], wav:['wav'], avi:['avi'],
  mp4:['mp4'], m4a:['mp4'], m4v:['mp4'], mov:['mp4'], '3gp':['mp4'],
  mkv:['mkv'], webm:['mkv'], flac:['flac'], ogg:['ogg'], opus:['ogg'],
  '7z':['7z'], rar:['rar'], gz:['gzip'], tgz:['gzip'], bz2:['bz2'], xz:['xz'], tar:['tar'],
  lnk:['lnk'], sqlite:['sqlite'], db:['sqlite'],
  txt:['text','utf16','html','xml','svg'], md:['text','utf16'], csv:['text','utf16'],
  log:['text','utf16'], json:['text','utf16'], xml:['xml','text','utf16','svg'],
  html:['html','text','utf16','xml'], htm:['html','text','utf16','xml'], svg:['svg','xml','text']
};
var DANGEROUS_MAGIC = { pe:1, elf:1, macho:1, lnk:1, html:1 };

function checkMismatch(ext, magic, findings){
  var expect = EXT_EXPECT[ext];
  if(!expect || !magic) return;
  if(expect.indexOf(magic.id)!==-1) return;
  if(magic.id==='text' && expect.indexOf('utf16')!==-1) return;
  var risk = DANGEROUS_MAGIC[magic.id] ? RISK.CRITICAL : RISK.HIGH;
  findings.push(F('拡張子とファイル形式の不一致',
    '拡張子: .'+ext+' / 実際: '+magic.label,
    '偽装ファイルの可能性があります。実行ファイル等が別形式に偽装されるケースがあります。',
    risk, '偽装検出'));
}

/* =========================================================
 * TIFF / EXIF (JPEG APP1・TIFF・PNG eXIf・WebP EXIFチャンクで共用)
 * ========================================================= */
function parseTIFF(bytes, base){
  var meta={}, findings=[];
  if(base+8>bytes.length) return {meta:meta, findings:findings};
  var le = bytes[base]===0x49 && bytes[base+1]===0x49;
  var be = bytes[base]===0x4D && bytes[base+1]===0x4D;
  if(!le && !be) return {meta:meta, findings:findings};
  function r16(o){ o+=base; return o+1<bytes.length ? (le?u16le(bytes,o):u16be(bytes,o)) : 0; }
  function r32(o){ o+=base; return o+3<bytes.length ? (le?u32le(bytes,o):u32be(bytes,o)) : 0; }
  if(r16(2)!==42) return {meta:meta, findings:findings};

  var TYPE_SIZE={1:1,2:1,3:2,4:4,5:8,7:1,9:4,10:8};
  function readEntry(eOff){
    var tag=r16(eOff), type=r16(eOff+2), count=r32(eOff+4);
    var size=(TYPE_SIZE[type]||1)*count;
    var vOff = size>4 ? r32(eOff+8) : eOff+8;
    return {tag:tag, type:type, count:count, vOff:vOff};
  }
  function tagStr(t){
    var s='';
    for(var i=0;i<t.count && i<300;i++){
      var p=base+t.vOff+i;
      if(p>=bytes.length || bytes[p]===0) break;
      s+=String.fromCharCode(bytes[p]);
    }
    return clean(s);
  }
  function tagRat(t,idx){
    var o=t.vOff+idx*8;
    var d=r32(o+4);
    return d ? r32(o)/d : 0;
  }
  function walkIFD(ifdOff, cb){
    if(ifdOff<=0 || base+ifdOff+2>bytes.length) return;
    var n=r16(ifdOff);
    if(n<1 || n>512) return;
    for(var i=0;i<n;i++){
      var eOff=ifdOff+2+i*12;
      if(base+eOff+12>bytes.length) break;
      cb(readEntry(eOff));
    }
  }

  var IFD0_TAGS={
    0x010E:{l:'画像説明', r:RISK.MEDIUM, w:'画像説明欄にテキストが含まれています。'},
    0x010F:{l:'カメラメーカー', r:RISK.LOW, w:'撮影機器が特定でき、所有者特定につながる場合があります。'},
    0x0110:{l:'カメラモデル', r:RISK.LOW, w:'撮影機器が特定でき、所有者特定につながる場合があります。'},
    0x0131:{l:'ソフトウェア', r:RISK.MEDIUM, w:'使用ソフトウェアとバージョンが特定できます(環境情報漏えい)。'},
    0x0132:{l:'更新日時', r:RISK.MEDIUM, w:'画像の更新日時が特定できます。'},
    0x013B:{l:'作成者(Artist)', r:RISK.HIGH, w:'撮影者・作成者名が埋め込まれています。'},
    0x8298:{l:'著作権', r:RISK.MEDIUM, w:'著作権表記に個人名が含まれる場合があります。'}
  };
  var EXIF_TAGS={
    0x9003:{l:'撮影日時(Original)', r:RISK.MEDIUM, w:'撮影日時が特定できます。'},
    0x9004:{l:'デジタル化日時', r:RISK.LOW, w:'デジタル化日時が含まれています。'},
    0xA420:{l:'画像UID', r:RISK.HIGH, w:'画像固有IDで撮影元の紐付けが可能になる場合があります。'},
    0xA430:{l:'カメラ所有者名', r:RISK.HIGH, w:'カメラ所有者の名前が埋め込まれています。'},
    0xA431:{l:'ボディシリアル番号', r:RISK.HIGH, w:'カメラのシリアル番号は個体識別に使えます。'},
    0xA433:{l:'レンズメーカー', r:RISK.LOW, w:'使用レンズが特定できます。'},
    0xA434:{l:'レンズモデル', r:RISK.LOW, w:'使用レンズが特定できます。'},
    0xA435:{l:'レンズシリアル番号', r:RISK.HIGH, w:'レンズのシリアル番号は個体識別に使えます。'}
  };

  var exifIfdOff=0, gpsIfdOff=0;
  walkIFD(r32(4), function(t){
    if(t.tag===0x8769){ exifIfdOff = t.type===4||t.type===3 ? (t.type===4?r32(t.vOff):r16(t.vOff)) : 0; return; }
    if(t.tag===0x8825){ gpsIfdOff = t.type===4||t.type===3 ? (t.type===4?r32(t.vOff):r16(t.vOff)) : 0; return; }
    var def=IFD0_TAGS[t.tag];
    if(!def || t.type!==2) return;
    var v=tagStr(t);
    if(!v) return;
    meta['[EXIF] '+def.l]=v;
    findings.push(F('EXIF: '+def.l, v, def.w, def.r, 'EXIF'));
  });

  walkIFD(exifIfdOff, function(t){
    var def=EXIF_TAGS[t.tag];
    if(t.tag===0x9286){ /* UserComment: 8バイトの文字コードヘッダー付き */
      var hdr=ascii(bytes,base+t.vOff,8);
      var body=bytes.slice(base+t.vOff+8, base+t.vOff+Math.min(t.count,300));
      var v=clean(/^UNICODE/.test(hdr) ? decode(body,'utf-16be') : decode(body));
      if(v){
        meta['[EXIF] ユーザーコメント']=v;
        findings.push(F('EXIF: ユーザーコメント', v, 'コメント欄に個人情報が含まれる可能性があります。', RISK.HIGH, 'EXIF'));
      }
      return;
    }
    if(!def || t.type!==2) return;
    var v2=tagStr(t);
    if(!v2) return;
    meta['[EXIF] '+def.l]=v2;
    findings.push(F('EXIF: '+def.l, v2, def.w, def.r, 'EXIF'));
  });

  if(gpsIfdOff){
    var gps={};
    walkIFD(gpsIfdOff, function(t){ gps[t.tag]=t; });
    var latT=gps[2], lonT=gps[4];
    if(latT && lonT && latT.type===5 && lonT.type===5 && latT.count>=1 && lonT.count>=1){
      function dms(t){
        var d=tagRat(t,0), m=t.count>1?tagRat(t,1):0, s=t.count>2?tagRat(t,2):0;
        return d+m/60+s/3600;
      }
      var lat=dms(latT), lon=dms(lonT);
      var latRef=gps[1]?tagStr(gps[1]):'N', lonRef=gps[3]?tagStr(gps[3]):'E';
      if(/S/i.test(latRef)) lat=-lat;
      if(/W/i.test(lonRef)) lon=-lon;
      if(isFinite(lat) && isFinite(lon) && (lat!==0 || lon!==0)){
        var coord=lat.toFixed(6)+', '+lon.toFixed(6);
        meta['[EXIF] GPS座標']=coord;
        findings.push(F('GPS位置情報(座標を復号)', coord,
          '撮影場所の緯度・経度がそのまま含まれています。自宅・職場等が特定される重大なプライバシーリスクです。',
          RISK.CRITICAL, 'EXIF/位置情報'));
        if(gps[6] && gps[6].type===5){
          meta['[EXIF] GPS高度']=tagRat(gps[6],0).toFixed(1)+' m';
        }
      }
    } else {
      meta['[EXIF] GPS情報']='存在します';
      findings.push(F('GPS位置情報', 'GPS IFDが検出されました',
        '撮影場所の緯度・経度が含まれている可能性があります。', RISK.CRITICAL, 'EXIF/位置情報'));
    }
  }

  /* IFD1 = サムネイル。編集前の元画像が残っている事故が多い */
  var thumb=null;
  var ifd0Off=r32(4);
  var n0=r16(ifd0Off);
  if(n0>0 && n0<=512){
    var ifd1Off=r32(ifd0Off+2+n0*12);
    var tOff=0, tLen=0;
    walkIFD(ifd1Off, function(t){
      if(t.tag===0x0201) tOff = t.type===3 ? r16(t.vOff) : r32(t.vOff);
      if(t.tag===0x0202) tLen = t.type===3 ? r16(t.vOff) : r32(t.vOff);
    });
    if(tOff>0 && tLen>16 && tLen<512*1024 && base+tOff+tLen<=bytes.length &&
       bytes[base+tOff]===0xFF && bytes[base+tOff+1]===0xD8){
      thumb=bytes.slice(base+tOff, base+tOff+tLen);
      meta['[EXIF] サムネイル']=tLen+' bytes (IFD1)';
      findings.push(F('EXIFサムネイル残存', tLen+' bytesの埋め込みJPEG',
        'トリミング・モザイク等の編集「前」の画像がサムネイルとして残っている可能性があります。プレビューで内容を確認してください。',
        RISK.HIGH, 'EXIF'));
    }
  }
  return {meta:meta, findings:findings, thumb:thumb};
}

/* ---------- XMP ---------- */
function parseXMP(text){
  var meta={}, findings=[];
  if(!text || text.indexOf('adobe:ns:meta')===-1 && text.indexOf('x:xmpmeta')===-1 && text.indexOf('rdf:RDF')===-1)
    return {meta:meta, findings:findings};
  var rules=[
    {re:/xmp:CreatorTool(?:>|=")([^<"]{1,200})/, l:'作成ツール(XMP)', r:RISK.MEDIUM, w:'使用ソフトウェアが特定できます。'},
    {re:/dc:creator[\s\S]{0,200}?<rdf:li[^>]*>([^<]{1,200})</, l:'作成者(XMP)', r:RISK.HIGH, w:'作成者名が埋め込まれています。'},
    {re:/photoshop:City(?:>|=")([^<"]{1,100})/, l:'撮影都市(XMP)', r:RISK.HIGH, w:'撮影場所の都市名が含まれています。'},
    {re:/photoshop:Country(?:>|=")([^<"]{1,100})/, l:'撮影国(XMP)', r:RISK.MEDIUM, w:'撮影場所の国名が含まれています。'},
    {re:/xmpMM:DocumentID(?:>|=")([^<"]{1,120})/, l:'ドキュメントID(XMP)', r:RISK.LOW, w:'文書固有IDで編集履歴の紐付けが可能です。'},
    {re:/exif:GPSLatitude(?:>|=")([^<"]{1,60})/, l:'GPS緯度(XMP)', r:RISK.CRITICAL, w:'位置情報がXMPに含まれています。'},
    {re:/exif:GPSLongitude(?:>|=")([^<"]{1,60})/, l:'GPS経度(XMP)', r:RISK.CRITICAL, w:'位置情報がXMPに含まれています。'}
  ];
  for(var i=0;i<rules.length;i++){
    var m=text.match(rules[i].re);
    if(m && clean(m[1])){
      var v=xmlDecode(clean(m[1]));
      meta['[XMP] '+rules[i].l]=v;
      findings.push(F('XMP: '+rules[i].l, v, rules[i].w, rules[i].r, 'XMPメタデータ'));
    }
  }
  return {meta:meta, findings:findings};
}

/* ---------- IPTC (JPEG APP13) ---------- */
function parseIPTC(seg){
  var meta={}, findings=[];
  var DS={80:{l:'撮影者(Byline)',r:RISK.HIGH},85:{l:'撮影者の肩書',r:RISK.MEDIUM},90:{l:'市区町村',r:RISK.HIGH},
          92:{l:'詳細地名',r:RISK.HIGH},95:{l:'都道府県/州',r:RISK.HIGH},101:{l:'国名',r:RISK.MEDIUM},
          105:{l:'見出し',r:RISK.LOW},110:{l:'クレジット',r:RISK.MEDIUM},116:{l:'著作権',r:RISK.MEDIUM},
          120:{l:'キャプション',r:RISK.MEDIUM},122:{l:'キャプション執筆者',r:RISK.HIGH}};
  for(var i=0;i<seg.length-5;i++){
    if(seg[i]!==0x1C || seg[i+1]!==0x02) continue;
    var ds=seg[i+2], len=u16be(seg,i+3);
    if(len<=0 || len>1000 || i+5+len>seg.length) continue;
    var def=DS[ds];
    if(def){
      var v=clean(decode(seg.slice(i+5,i+5+len)));
      if(v){
        meta['[IPTC] '+def.l]=v;
        findings.push(F('IPTC: '+def.l, v,
          def.r>=RISK.HIGH?'撮影者・撮影場所の特定につながる情報です。':'IPTCメタデータに情報が含まれています。',
          def.r, 'IPTCメタデータ'));
      }
    }
    i+=4+len;
  }
  return {meta:meta, findings:findings};
}

/* ---------- JPEG ---------- */
function parseJPEG(bytes){
  var meta={}, findings=[], thumb=null;
  function merge(r){
    Object.assign(meta,r.meta);
    findings.push.apply(findings,r.findings);
    if(r.thumb && !thumb) thumb=r.thumb;
  }
  var i=2;
  while(i+4<=bytes.length){
    if(bytes[i]!==0xFF){ i++; continue; }
    var marker=bytes[i+1];
    if(marker===0xFF){ i++; continue; }
    if(marker===0x01 || (marker>=0xD0 && marker<=0xD8)){ i+=2; continue; }
    if(marker===0xD9) break;
    if(marker===0xDA){
      /* SOS以降の圧縮データ内でFFはFF00/リスタートマーカーに限られるため、最初のFFD9が真のEOI */
      var eoi=-1;
      for(var j=i+2;j<bytes.length-1;j++){
        if(bytes[j]===0xFF && bytes[j+1]===0xD9){ eoi=j; break; }
      }
      if(eoi!==-1){
        var trailing=bytes.length-(eoi+2);
        if(trailing>4){
          meta['[JPEG] 終端以降の余剰データ']=fmtBytes(trailing);
          findings.push(F('画像終端(EOI)以降の余剰データ', fmtBytes(trailing),
            '正規の画像データの後ろに別のデータが付加されています。ステガノグラフィーや別ファイルの隠蔽(ポリグロット)の可能性があります。',
            RISK.HIGH, 'バイナリ解析'));
        }
      }
      break; /* メタ用セグメントはSOSより前 */
    }
    var segLen=u16be(bytes,i+2);
    if(segLen<2) break;
    var segStart=i+4, segEnd=Math.min(i+2+segLen, bytes.length);
    if(marker===0xE1){
      if(ascii(bytes,segStart,4)==='Exif' && bytes[segStart+4]===0 && bytes[segStart+5]===0){
        merge(parseTIFF(bytes, segStart+6));
      } else if(ascii(bytes,segStart,28).indexOf('http://ns.adobe.com/xap/')===0){
        merge(parseXMP(decode(bytes.slice(segStart+29,segEnd))));
      }
    } else if(marker===0xED){
      if(ascii(bytes,segStart,13).indexOf('Photoshop')===0){
        merge(parseIPTC(bytes.slice(segStart,segEnd)));
      }
    } else if(marker===0xFE){
      var com=clean(decode(bytes.slice(segStart,segEnd)));
      if(com){
        meta['[JPEG] コメント']=com;
        findings.push(F('JPEGコメント', com, 'コメントセグメントにテキストが埋め込まれています。', RISK.MEDIUM, 'JPEGメタデータ'));
      }
    }
    i = i+2+segLen;
  }
  return {meta:meta, findings:findings, thumb:thumb};
}

/* ---------- PNG ---------- */
function parsePNG(bytes){
  var meta={}, findings=[], thumb=null;
  function merge(r){
    Object.assign(meta,r.meta);
    findings.push.apply(findings,r.findings);
    if(r.thumb && !thumb) thumb=r.thumb;
  }
  var pending=[];
  var SENSITIVE_KEYS=['author','comment','copyright','software','source','creation time','create-date','modify-date','xml:com.adobe'];
  function handleText(key, val){
    if(!val || val.length>100000) return;
    if(key.toLowerCase()==='xml:com.adobe.xmp'){ merge(parseXMP(val)); return; }
    meta['[PNG] '+key]=val.substring(0,200);
    for(var si=0;si<SENSITIVE_KEYS.length;si++){
      if(key.toLowerCase().indexOf(SENSITIVE_KEYS[si])!==-1){
        findings.push(F('PNGテキスト: '+key, val.substring(0,150),
          '作成者・ソフトウェア・日時等の情報が埋め込まれています。', RISK.MEDIUM, 'PNGメタデータ'));
        break;
      }
    }
  }
  var i=8;
  var guard=0;
  while(i+12<=bytes.length && guard++<10000){
    var len=u32be(bytes,i);
    var type=ascii(bytes,i+4,4);
    if(len>0x7FFFFFFF || i+12+len>bytes.length+4) break;
    var dataStart=i+8, dataEnd=Math.min(i+8+len, bytes.length);
    if(type==='tEXt' && len>0){
      var d=bytes.slice(dataStart,dataEnd);
      var ni=0; while(ni<d.length && d[ni]!==0) ni++;
      handleText(ascii(d,0,ni), clean(decode(d.slice(ni+1),'latin1')));
    } else if(type==='iTXt' && len>0){
      var d2=bytes.slice(dataStart,dataEnd);
      var p=0; while(p<d2.length && d2[p]!==0) p++;
      var key2=ascii(d2,0,p);
      var compFlag=d2[p+1];
      var q=p+3; while(q<d2.length && d2[q]!==0) q++; /* 言語タグを飛ばす */
      q++; while(q<d2.length && d2[q]!==0) q++;       /* 翻訳キーワードを飛ばす */
      q++;
      var body=d2.slice(q);
      if(compFlag===1){
        pending.push(inflateZlib(body).then((function(k){ return function(out){ if(out) handleText(k, clean(decode(out))); }; })(key2)));
      } else {
        handleText(key2, clean(decode(body)));
      }
    } else if(type==='zTXt' && len>0){
      var d3=bytes.slice(dataStart,dataEnd);
      var p3=0; while(p3<d3.length && d3[p3]!==0) p3++;
      var key3=ascii(d3,0,p3);
      pending.push(inflateZlib(d3.slice(p3+2)).then((function(k){ return function(out){ if(out) handleText(k, clean(decode(out))); }; })(key3)));
    } else if(type==='eXIf' && len>8){
      merge(parseTIFF(bytes.slice(dataStart,dataEnd), 0));
    } else if(type==='tIME' && len>=7){
      var y=u16be(bytes,dataStart);
      meta['[PNG] 最終更新(tIME)']=y+'-'+pad2(bytes[dataStart+2])+'-'+pad2(bytes[dataStart+3])+' '+
        pad2(bytes[dataStart+4])+':'+pad2(bytes[dataStart+5])+':'+pad2(bytes[dataStart+6]);
    } else if(type==='IEND'){ break; }
    i += 12+len;
  }
  function pad2(n){ return (n<10?'0':'')+n; }
  return Promise.all(pending).then(function(){
    return {meta:meta, findings:findings, thumb:thumb};
  });
}
/* zlibヘッダー付きdeflateの展開 (PNG zTXt/iTXt用) */
function inflateZlib(data){
  if(typeof require!=='undefined' && typeof process!=='undefined' && process.versions && process.versions.node){
    try{ return Promise.resolve(new Uint8Array(require('zlib').inflateSync(data))); }catch(e){ return Promise.resolve(null); }
  }
  if(typeof DecompressionStream==='undefined') return Promise.resolve(null);
  try{
    var ds=new DecompressionStream('deflate');
    var resp=new Response(new Blob([data]).stream().pipeThrough(ds));
    return resp.arrayBuffer().then(function(b){return new Uint8Array(b);}).catch(function(){return null;});
  }catch(e){ return Promise.resolve(null); }
}

/* ---------- GIF ---------- */
function parseGIF(bytes){
  var meta={}, findings=[];
  /* コメント拡張ブロック (0x21 0xFE) を構造的に妥当な範囲で探索 */
  var found=0;
  for(var i=13;i<Math.min(bytes.length-3, 1024*1024) && found<5;i++){
    if(bytes[i]!==0x21 || bytes[i+1]!==0xFE) continue;
    var txt='', p=i+2, ok=true;
    var guard=0;
    while(p<bytes.length && guard++<200){
      var blen=bytes[p];
      if(blen===0) break;
      if(p+1+blen>bytes.length){ ok=false; break; }
      txt+=decode(bytes.slice(p+1,p+1+blen));
      p+=1+blen;
    }
    txt=clean(txt);
    if(ok && txt.length>2 && /^[\x20-\x7E -￿\s]+$/.test(txt)){
      found++;
      meta['[GIF] コメント'+(found>1?found:'')]=txt.substring(0,200);
      findings.push(F('GIFコメント', txt.substring(0,150),
        'コメント拡張ブロックにテキストが埋め込まれています。', RISK.MEDIUM, 'GIFメタデータ'));
      i=p;
    }
  }
  var text=decode(bytes.slice(0,Math.min(bytes.length,1024*1024)),'latin1');
  if(text.indexOf('XMP DataXMP')!==-1){
    var r=parseXMP(text);
    Object.assign(meta,r.meta); findings.push.apply(findings,r.findings);
  }
  return {meta:meta, findings:findings};
}

/* ---------- RIFF (WAV / AVI / WebP) ---------- */
function parseRIFF(bytes){
  var meta={}, findings=[], thumb=null;
  function merge(r){
    Object.assign(meta,r.meta);
    findings.push.apply(findings,r.findings);
    if(r.thumb && !thumb) thumb=r.thumb;
  }
  var form=ascii(bytes,8,4);
  var INFO_TAGS={IART:{l:'アーティスト',r:RISK.HIGH},ICMT:{l:'コメント',r:RISK.MEDIUM},ISFT:{l:'作成ソフトウェア',r:RISK.MEDIUM},
                 ICOP:{l:'著作権',r:RISK.MEDIUM},ICRD:{l:'作成日',r:RISK.MEDIUM},IENG:{l:'エンジニア',r:RISK.HIGH},
                 INAM:{l:'タイトル',r:RISK.LOW},IPRD:{l:'製品/アルバム',r:RISK.LOW},ITCH:{l:'技術者',r:RISK.HIGH}};
  function walk(start,end,depth){
    var i=start, guard=0;
    while(i+8<=end && guard++<5000){
      var id=ascii(bytes,i,4);
      var size=u32le(bytes,i+4);
      if(size>end-i-8+1) break;
      if(id==='LIST' && depth<4){
        var listType=ascii(bytes,i+8,4);
        if(listType==='INFO'){
          var j=i+12;
          while(j+8<i+8+size){
            var sid=ascii(bytes,j,4), ssz=u32le(bytes,j+4);
            if(ssz>size) break;
            var def=INFO_TAGS[sid];
            if(def){
              var v=clean(decode(bytes.slice(j+8,j+8+ssz)));
              if(v){
                meta['[RIFF] '+def.l]=v;
                findings.push(F('RIFF INFO: '+def.l, v,
                  def.r>=RISK.HIGH?'制作者個人の特定につながる情報です。':'メディア制作環境の情報が含まれています。',
                  def.r, 'RIFFメタデータ'));
              }
            }
            j+=8+ssz+(ssz&1);
          }
        } else {
          walk(i+12, i+8+size, depth+1);
        }
      } else if(id==='EXIF'){
        var off=i+8;
        if(ascii(bytes,off,4)==='Exif') off+=6;
        merge(parseTIFF(bytes, off));
      } else if(id==='XMP '){
        merge(parseXMP(decode(bytes.slice(i+8,i+8+size))));
      }
      i+=8+size+(size&1);
    }
  }
  walk(12, Math.min(bytes.length, 64*1024*1024), 0);
  if(form==='WEBP') meta['[WebP] 形式']='WebP画像';
  return {meta:meta, findings:findings, thumb:thumb};
}

/* ---------- HEIC / AVIF ---------- */
function parseHEIC(bytes){
  var meta={}, findings=[], thumb=null;
  /* metaボックスを正確に辿る代わりに "Exif\0\0" シグネチャを探す(実用上十分) */
  var limit=Math.min(bytes.length-10, 4*1024*1024);
  for(var i=0;i<limit;i++){
    if(bytes[i]===0x45 && bytes[i+1]===0x78 && bytes[i+2]===0x69 && bytes[i+3]===0x66 &&
       bytes[i+4]===0x00 && bytes[i+5]===0x00){
      var r=parseTIFF(bytes, i+6);
      if(Object.keys(r.meta).length || r.findings.length){
        Object.assign(meta,r.meta); findings.push.apply(findings,r.findings);
        if(r.thumb) thumb=r.thumb;
        break;
      }
    }
  }
  return {meta:meta, findings:findings, thumb:thumb};
}

/* ---------- MP4 / MOV ---------- */
function parseMP4(bytes){
  var meta={}, findings=[];
  var ILST_TAGS={'©too':{l:'エンコーダー',r:RISK.MEDIUM,w:'使用ソフトウェアが特定できます。'},
                 '©nam':{l:'タイトル',r:RISK.LOW,w:'タイトルが含まれています。'},
                 '©ART':{l:'アーティスト',r:RISK.HIGH,w:'制作者名が含まれています。'},
                 '©day':{l:'作成日',r:RISK.MEDIUM,w:'作成日が含まれています。'},
                 '©cmt':{l:'コメント',r:RISK.MEDIUM,w:'コメントが含まれています。'},
                 '©wrt':{l:'作者',r:RISK.HIGH,w:'作者名が含まれています。'},
                 'desc':{l:'説明',r:RISK.LOW,w:'説明文が含まれています。'}};
  function walk(start,end,depth){
    var i=start, guard=0;
    while(i+8<=end && guard++<3000){
      var size=u32be(bytes,i);
      var type=ascii(bytes,i+4,4);
      var hdr=8;
      if(size===1){
        if(i+16>end) break;
        size=u32be(bytes,i+8)*4294967296+u32be(bytes,i+12);
        hdr=16;
      } else if(size===0){ size=end-i; }
      if(size<hdr || i+size>end) break;
      var bs=i+hdr, be=i+size;
      if(type==='ftyp'){
        meta['[MP4] ブランド']=clean(ascii(bytes,bs,4));
      } else if(type==='mvhd' && bs+20<=be){
        var ver=bytes[bs];
        var ct = ver===1 ? u32be(bytes,bs+4)*4294967296+u32be(bytes,bs+8) : u32be(bytes,bs+4);
        if(ct>2082844800){
          var d=new Date((ct-2082844800)*1000);
          if(d.getFullYear()>1971 && d.getFullYear()<2100){
            var ds=d.toLocaleString('ja-JP');
            meta['[MP4] 作成日時']=ds;
            findings.push(F('MP4: 作成日時', ds, '動画の作成日時が特定できます。', RISK.MEDIUM, 'MP4メタデータ'));
          }
        }
      } else if(type==='©xyz' && bs+4<be){
        var slen=u16be(bytes,bs);
        var gv=clean(decode(bytes.slice(bs+4,Math.min(bs+4+slen,be))));
        if(gv){
          meta['[MP4] GPS位置(©xyz)']=gv;
          findings.push(F('MP4: GPS位置情報', gv,
            '撮影場所の緯度・経度が埋め込まれています(スマートフォン撮影動画に多い)。重大なプライバシーリスクです。',
            RISK.CRITICAL, 'MP4/位置情報'));
        }
      } else if(ILST_TAGS[type] && bs+16<be){
        var dSize=u32be(bytes,bs);
        if(ascii(bytes,bs+4,4)==='data' && dSize<=be-bs){
          var v=clean(decode(bytes.slice(bs+16,bs+dSize)));
          if(v){
            var def=ILST_TAGS[type];
            meta['[MP4] '+def.l]=v;
            findings.push(F('MP4: '+def.l, v, def.w, def.r, 'MP4メタデータ'));
          }
        }
      } else if(type==='meta' && depth<7){
        walk(bs+4, be, depth+1);
      } else if(['moov','udta','trak','mdia','minf','ilst','stbl'].indexOf(type)!==-1 && depth<7){
        walk(bs, be, depth+1);
      }
      i+=size;
    }
  }
  walk(0, bytes.length, 0);
  return {meta:meta, findings:findings};
}

/* ---------- PDF ---------- */
function parsePDF(bytes){
  var meta={}, findings=[];
  /* メタデータ(Infoディクショナリ)は末尾付近にあることが多いので先頭と末尾の両方を見る */
  var head=decode(bytes.slice(0,Math.min(bytes.length,128*1024)),'latin1');
  var tail=bytes.length>128*1024 ? decode(bytes.slice(Math.max(0,bytes.length-256*1024)),'latin1') : '';
  var text=head+'\n'+tail;
  function pdfStr(raw){
    var s=raw.replace(/\\([nrtbf()\\])/g,function(_,c){ return {n:'\n',r:'\r',t:'\t',b:'\b',f:'\f'}[c]||c; })
             .replace(/\\(\d{1,3})/g,function(_,o){ return String.fromCharCode(parseInt(o,8)); });
    if(s.charCodeAt(0)===0xFE && s.charCodeAt(1)===0xFF){
      var out=''; for(var i=2;i+1<s.length;i+=2) out+=String.fromCharCode((s.charCodeAt(i)<<8)|s.charCodeAt(i+1));
      return out;
    }
    return s;
  }
  function fmtPdfDate(v){
    var m=v.match(/^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?/);
    if(!m) return v;
    return m[1]+(m[2]?'-'+m[2]:'')+(m[3]?'-'+m[3]:'')+(m[4]?' '+m[4]:'')+(m[5]?':'+m[5]:'')+(m[6]?':'+m[6]:'');
  }
  var props=[
    {k:'Author',l:'作成者',r:RISK.HIGH,w:'PDFの作成者名が埋め込まれています。',date:false},
    {k:'Creator',l:'作成ソフト',r:RISK.MEDIUM,w:'使用ソフトウェア・バージョンが特定できます。',date:false},
    {k:'Producer',l:'Producerソフト',r:RISK.LOW,w:'PDF変換ソフトウェア情報が含まれています。',date:false},
    {k:'Title',l:'タイトル',r:RISK.LOW,w:'文書タイトルが埋め込まれています。',date:false},
    {k:'Subject',l:'サブジェクト',r:RISK.LOW,w:'文書サブジェクトが含まれています。',date:false},
    {k:'Keywords',l:'キーワード',r:RISK.LOW,w:'キーワードメタデータが含まれています。',date:false},
    {k:'CreationDate',l:'作成日時',r:RISK.MEDIUM,w:'文書の作成日時が特定できます。',date:true},
    {k:'ModDate',l:'更新日時',r:RISK.MEDIUM,w:'文書の更新日時が特定できます。',date:true}
  ];
  for(var i=0;i<props.length;i++){
    var p=props[i];
    var re=new RegExp('/'+p.k+'\\s*\\(((?:\\\\.|[^\\\\)]){1,300})\\)');
    var m=text.match(re);
    var val=null;
    if(m){ val=clean(pdfStr(m[1])); }
    else {
      var reHex=new RegExp('/'+p.k+'\\s*<([0-9A-Fa-f\\s]{4,600})>');
      var mh=text.match(reHex);
      if(mh){
        var hex=mh[1].replace(/\s/g,'');
        var raw=''; for(var h=0;h+1<hex.length;h+=2) raw+=String.fromCharCode(parseInt(hex.substr(h,2),16));
        val=clean(pdfStr(raw));
      }
    }
    if(val){
      if(p.date) val=fmtPdfDate(val);
      meta['[PDF] '+p.l]=val;
      findings.push(F('PDF: '+p.l, val, p.w, p.r, 'PDFメタデータ'));
    }
  }
  var xmp=parseXMP(text);
  Object.assign(meta,xmp.meta); findings.push.apply(findings,xmp.findings);

  if(/\/JavaScript/.test(text) || /\/JS\s*[(</]/.test(text)){
    meta['[PDF] JavaScript']='検出';
    findings.push(F('PDF: JavaScript埋め込み','/JavaScriptディクショナリ検出',
      '悪意あるPDFはJavaScriptで脆弱性を悪用することがあります。', RISK.CRITICAL, 'PDFセキュリティ'));
  }
  if(/\/Launch/.test(text)){
    findings.push(F('PDF: Launchアクション','/Launchディクショナリ検出',
      '外部プログラムを起動するアクションが埋め込まれている可能性があります。', RISK.CRITICAL, 'PDFセキュリティ'));
  }
  if(/\/OpenAction/.test(text)){
    findings.push(F('PDF: OpenAction','文書を開いた時に自動実行されるアクションがあります',
      '自動実行アクションはマルウェアに悪用されることがあります。', RISK.MEDIUM, 'PDFセキュリティ'));
  }
  if(/\/EmbeddedFiles?/.test(text)){
    findings.push(F('PDF: 埋め込みファイル','/EmbeddedFile検出',
      'PDF内に別ファイルが埋め込まれています。内容を確認してください。', RISK.HIGH, 'PDFセキュリティ'));
  }
  if(/\/Encrypt\b/.test(text)) meta['[PDF] 暗号化']='あり';
  var um=text.match(/\/URI\s*\(((?:\\.|[^\\)]){1,300})\)/);
  if(um){
    var uri=clean(pdfStr(um[1]));
    meta['[PDF] 埋め込みURL']=uri;
    findings.push(F('PDF: 埋め込みURL', uri, '外部URLへのリンクが設定されています。', RISK.MEDIUM, 'PDFセキュリティ'));
  }

  /* 増分更新の検出: %%EOFが複数 = 修正・墨消し「前」の内容がファイル内に残存している */
  var eofCount=0;
  var scanEnd=Math.min(bytes.length-4, 64*1024*1024);
  for(var b=0;b<scanEnd;b++){
    if(bytes[b]===0x25 && bytes[b+1]===0x25 && bytes[b+2]===0x45 && bytes[b+3]===0x4F && bytes[b+4]===0x46){
      eofCount++; b+=4;
    }
  }
  if(eofCount>0) meta['[PDF] %%EOF数']=String(eofCount);
  var expected=/\/Linearized/.test(head) ? 2 : 1; /* リニアライズPDFは正常でも2個持つ */
  if(eofCount>expected){
    findings.push(F('PDF: 旧バージョンの内容が残存(増分更新)', '%%EOFが'+eofCount+'箇所',
      '増分更新により編集・墨消し「前」の内容がファイル内に丸ごと残っています。修正したはずの情報が復元可能な場合があります。「名前を付けて保存」や印刷→PDF化で作り直すことを推奨します。',
      RISK.HIGH, 'PDFセキュリティ'));
  }
  return {meta:meta, findings:findings};
}

/* ---------- ZIP (汎用 + Office/ODF) ---------- */
function listZipEntries(bytes){
  /* EOCDを末尾から探して central directory を辿る */
  var minOff=Math.max(0, bytes.length-22-65536);
  var eocd=-1;
  for(var i=bytes.length-22;i>=minOff;i--){
    if(bytes[i]===0x50 && bytes[i+1]===0x4B && bytes[i+2]===0x05 && bytes[i+3]===0x06){ eocd=i; break; }
  }
  var entries=[], comment=null;
  if(eocd!==-1){
    var count=u16le(bytes,eocd+10);
    var cdOff=u32le(bytes,eocd+16);
    var cLen=u16le(bytes,eocd+20);
    if(cLen>0) comment=clean(decode(bytes.slice(eocd+22,eocd+22+cLen)));
    if(cdOff!==0xFFFFFFFF && cdOff<bytes.length){
      var p=cdOff;
      for(var n=0;n<count && p+46<=bytes.length;n++){
        if(!(bytes[p]===0x50 && bytes[p+1]===0x4B && bytes[p+2]===0x01 && bytes[p+3]===0x02)) break;
        var flags=u16le(bytes,p+8);
        var method=u16le(bytes,p+10);
        var compSize=u32le(bytes,p+20);
        var uncompSize=u32le(bytes,p+24);
        var nLen=u16le(bytes,p+28), eLen=u16le(bytes,p+30), cmLen=u16le(bytes,p+32);
        var localOff=u32le(bytes,p+42);
        entries.push({
          name:decode(bytes.slice(p+46,p+46+nLen)),
          method:method, compSize:compSize, uncompSize:uncompSize,
          localOff:localOff, encrypted:(flags&1)===1
        });
        p+=46+nLen+eLen+cmLen;
      }
    }
  }
  if(!entries.length){
    /* フォールバック: ローカルヘッダーを直接走査(切り詰められたファイル用) */
    var idx=0;
    while(idx<bytes.length-30 && entries.length<500){
      if(bytes[idx]===0x50 && bytes[idx+1]===0x4B && bytes[idx+2]===0x03 && bytes[idx+3]===0x04){
        var fl=u16le(bytes,idx+6);
        var me=u16le(bytes,idx+8);
        var cs=u32le(bytes,idx+18);
        var fn=u16le(bytes,idx+26), ex=u16le(bytes,idx+28);
        entries.push({
          name:decode(bytes.slice(idx+30,idx+30+fn)),
          method:me, compSize:cs, uncompSize:u32le(bytes,idx+22),
          localOff:idx, encrypted:(fl&1)===1
        });
        idx+=30+fn+ex+(cs<bytes.length?cs:0);
      } else idx++;
    }
  }
  return {entries:entries, comment:comment};
}
function zipReadEntry(bytes, entry){
  var off=entry.localOff;
  if(off+30>bytes.length) return Promise.resolve(null);
  if(!(bytes[off]===0x50 && bytes[off+1]===0x4B && bytes[off+2]===0x03 && bytes[off+3]===0x04)) return Promise.resolve(null);
  var nLen=u16le(bytes,off+26), eLen=u16le(bytes,off+28);
  var dataOff=off+30+nLen+eLen;
  var data=bytes.slice(dataOff, dataOff+entry.compSize);
  if(entry.encrypted) return Promise.resolve(null);
  if(entry.method===0) return Promise.resolve(data);
  if(entry.method===8) return inflateRaw(data);
  return Promise.resolve(null);
}

function parseZIPFamily(bytes, ext, depth){
  depth=depth||0;
  var meta={}, findings=[];
  var zi=listZipEntries(bytes);
  var entries=zi.entries;
  var names=entries.map(function(e){return e.name;});

  if(zi.comment){
    meta['[ZIP] コメント']=zi.comment;
    findings.push(F('ZIPコメント', zi.comment, 'ZIPコメントフィールドに情報が埋め込まれています。', RISK.LOW, 'ZIPメタデータ'));
  }
  if(names.length){
    meta['[ZIP] エントリ数']=String(names.length);
    meta['[ZIP] 含有ファイル']=names.slice(0,20).join(', ')+(names.length>20?' …':'');
  }
  var encCount=entries.filter(function(e){return e.encrypted;}).length;
  if(encCount){
    findings.push(F('暗号化されたZIPエントリ', encCount+'件のエントリがパスワード保護されています',
      'パスワード付きZIPはウイルススキャン回避のためマルウェア配布にもよく使われます。', RISK.MEDIUM, 'ZIPセキュリティ'));
  }
  var execNames=names.filter(function(f){return /\.(exe|dll|bat|ps1|vbs|js|jse|wsf|sh|cmd|scr|pif|com|jar|py|hta|msi|lnk)$/i.test(f);});
  if(execNames.length && !/^(docx|xlsx|pptx|odt|ods|odp|jar|apk|epub|xpi)$/.test(ext)){
    findings.push(F('ZIP内に実行可能ファイル', execNames.slice(0,5).join(', '),
      'ZIPに実行可能ファイル・ショートカットが含まれています。マルウェア配布によく使われる手法です。', RISK.HIGH, 'ZIPセキュリティ'));
  }
  if(names.some(function(f){return f.indexOf('../')!==-1 || /^([A-Za-z]:|\\\\|\/)/.test(f);})){
    findings.push(F('ZIPパストラバーサルの疑い', '「../」や絶対パスを含むエントリ名',
      '展開時に意図しない場所へファイルを書き込む攻撃(Zip Slip)の可能性があります。', RISK.HIGH, 'ZIPセキュリティ'));
  }
  if(names.some(function(f){return /vbaProject\.bin$/i.test(f);})){
    meta['[Office] VBAマクロ']='検出';
    findings.push(F('VBAマクロ検出', 'vbaProject.bin が含まれています',
      'VBAマクロが埋め込まれています。マルウェア配布に悪用されることがあります。', RISK.CRITICAL, 'Officeセキュリティ'));
  }
  if(names.some(function(f){return /oleObject\d*\.bin$/i.test(f);})){
    findings.push(F('OLEオブジェクト埋め込み', '埋め込みオブジェクト(.bin)が含まれています',
      '埋め込みOLEオブジェクトは別ファイルやスクリプトを隠していることがあります。', RISK.MEDIUM, 'Officeセキュリティ'));
  }
  var hasComments=names.some(function(f){return /(word\/comments\.xml|xl\/comments\d*\.xml|ppt\/comments\/)/i.test(f);});
  if(hasComments){
    findings.push(F('コメント(レビュー履歴)が残存', 'comments.xml が含まれています',
      '校閲コメントには氏名や社内情報が含まれることがあります。共有前に削除を推奨します。', RISK.HIGH, 'Officeメタデータ'));
  }

  var isOffice=/^(docx|xlsx|pptx)$/.test(ext) || names.indexOf('[Content_Types].xml')!==-1;
  var isODF=/^(odt|ods|odp)$/.test(ext) || names.indexOf('meta.xml')!==-1;
  var tasks=[];

  function findEntry(n){ for(var i=0;i<entries.length;i++){ if(entries[i].name===n) return entries[i]; } return null; }

  if(isOffice){
    var core=findEntry('docProps/core.xml'), app=findEntry('docProps/app.xml');
    var OFFICE_PROPS=[
      {k:'dc:creator',l:'作成者',r:RISK.HIGH,w:'ドキュメントの作成者名が含まれています。'},
      {k:'cp:lastModifiedBy',l:'最終更新者',r:RISK.HIGH,w:'最後に編集したユーザー名が含まれています。'},
      {k:'dcterms:created',l:'作成日時',r:RISK.MEDIUM,w:'文書の作成日時が特定できます。'},
      {k:'dcterms:modified',l:'更新日時',r:RISK.MEDIUM,w:'最終更新日時が含まれています。'},
      {k:'cp:revision',l:'改訂回数',r:RISK.LOW,w:'編集回数が分かります。'},
      {k:'dc:title',l:'タイトル',r:RISK.LOW,w:'文書タイトルが含まれています。'},
      {k:'dc:description',l:'説明/コメント',r:RISK.MEDIUM,w:'説明欄にテキストが含まれています。'},
      {k:'cp:keywords',l:'キーワード',r:RISK.LOW,w:'キーワードが含まれています。'}
    ];
    var APP_PROPS=[
      {k:'Application',l:'アプリケーション',r:RISK.MEDIUM,w:'使用したOfficeアプリが特定できます。'},
      {k:'AppVersion',l:'アプリバージョン',r:RISK.MEDIUM,w:'バージョン情報から環境が特定できます。'},
      {k:'Company',l:'会社名',r:RISK.HIGH,w:'組織名が埋め込まれており、所属が特定できます。'},
      {k:'Manager',l:'管理者',r:RISK.HIGH,w:'管理者名が含まれています。'},
      {k:'TotalTime',l:'総編集時間(分)',r:RISK.LOW,w:'編集にかけた時間が分かります。'},
      {k:'Template',l:'テンプレート',r:RISK.NONE,w:''}
    ];
    function parseProps(xml, props){
      for(var i=0;i<props.length;i++){
        var p=props[i];
        var re=new RegExp('<'+p.k+'(?:\\s[^>]*)?>([^<]{1,300})</'+p.k+'>');
        var m=xml.match(re);
        if(m && clean(m[1])){
          var v=xmlDecode(clean(m[1]));
          meta['[Office] '+p.l]=v;
          if(p.k==='Template' && /[A-Za-z]:\\|\/Users\/|\/home\/|\\\\/.test(v)){
            findings.push(F('Office: テンプレートパス', v,
              'ローカルファイルパス(ユーザー名等)が含まれています。', RISK.HIGH, 'Officeメタデータ'));
          } else if(p.r>RISK.NONE){
            findings.push(F('Office: '+p.l, v, p.w, p.r, 'Officeメタデータ'));
          }
        }
      }
    }
    if(core) tasks.push(zipReadEntry(bytes,core).then(function(d){ if(d) parseProps(decode(d), OFFICE_PROPS); }));
    if(app) tasks.push(zipReadEntry(bytes,app).then(function(d){ if(d) parseProps(decode(d), APP_PROPS); }));

    /* Excel: 非表示シート */
    var wb=findEntry('xl/workbook.xml');
    if(wb) tasks.push(zipReadEntry(bytes,wb).then(function(d){
      if(!d) return;
      var xml=decode(d);
      var hidden=[], veryHidden=[], m;
      var sheetRe=/<sheet\s[^>]*?\/?>/g;
      while((m=sheetRe.exec(xml))){
        var tag=m[0];
        var nm=(tag.match(/name="([^"]{1,100})"/)||[])[1]||'(名称不明)';
        if(/state="veryHidden"/.test(tag)) veryHidden.push(nm);
        else if(/state="hidden"/.test(tag)) hidden.push(nm);
      }
      if(veryHidden.length){
        meta['[Office] 非表示シート(veryHidden)']=veryHidden.join(', ');
        findings.push(F('Excel: 完全非表示シート(veryHidden)', veryHidden.join(', '),
          'UIからは再表示できない完全非表示シートです。見せるつもりのないデータが入っている典型的な場所です。',
          RISK.HIGH, 'Office隠しデータ'));
      }
      if(hidden.length){
        meta['[Office] 非表示シート']=hidden.join(', ');
        findings.push(F('Excel: 非表示シート', hidden.join(', '),
          '非表示シートに削除したつもりのデータが残っていることがあります。', RISK.MEDIUM, 'Office隠しデータ'));
      }
    }));

    /* PowerPoint: 発表者ノート */
    var noteEntries=entries.filter(function(e){ return /^ppt\/notesSlides\/notesSlide\d+\.xml$/.test(e.name); });
    if(noteEntries.length){
      tasks.push(Promise.all(noteEntries.slice(0,5).map(function(e){ return zipReadEntry(bytes,e); })).then(function(ds){
        var texts=[];
        ds.forEach(function(d){
          if(!d) return;
          var xml=decode(d);
          var t=[], re=/<a:t>([^<]{1,300})<\/a:t>/g, m;
          while((m=re.exec(xml)) && t.length<20) t.push(xmlDecode(m[1]));
          var joined=clean(t.join(' '));
          if(joined) texts.push(joined);
        });
        var snippet=texts.join(' / ').substring(0,150);
        if(snippet){
          meta['[Office] 発表者ノート']=noteEntries.length+'スライド分';
          findings.push(F('PowerPoint: 発表者ノート残存', snippet,
            '発表者ノート('+noteEntries.length+'スライド分)が残っています。社内向けのメモが入りがちな場所です。共有前に削除を推奨します。',
            RISK.MEDIUM, 'Office隠しデータ'));
        }
      }));
    }

    /* Word: 未承認の変更履歴 */
    var docXml=findEntry('word/document.xml');
    if(docXml && docXml.uncompSize<30*1024*1024) tasks.push(zipReadEntry(bytes,docXml).then(function(d){
      if(!d) return;
      var xml=decode(d);
      if(/<w:(ins|del)\s/.test(xml)){
        var authors=[], re=/<w:(?:ins|del)\s[^>]*?w:author="([^"]{1,100})"/g, m;
        while((m=re.exec(xml)) && authors.length<10){ var a=xmlDecode(m[1]); if(authors.indexOf(a)===-1) authors.push(a); }
        findings.push(F('Word: 未承認の変更履歴が残存', authors.length?('編集者: '+authors.join(', ')):'挿入/削除の履歴',
          '承認されていない変更履歴には削除前の文面と編集者名がそのまま残っています。', RISK.HIGH, 'Office隠しデータ'));
      }
      if(/<w:vanish\s*\/>/.test(xml)){
        findings.push(F('Word: 隠し文字', 'w:vanish 検出',
          '「隠し文字」書式のテキストが含まれています。画面に見えなくてもデータは残っています。', RISK.MEDIUM, 'Office隠しデータ'));
      }
    }));
    var people=findEntry('word/people.xml');
    if(people) tasks.push(zipReadEntry(bytes,people).then(function(d){
      if(!d) return;
      var xml=decode(d);
      var authors=[], re=/w15:author="([^"]{1,100})"/g, m;
      while((m=re.exec(xml)) && authors.length<10){ var a=xmlDecode(m[1]); if(authors.indexOf(a)===-1) authors.push(a); }
      if(authors.length){
        meta['[Office] 変更履歴の著者']=authors.join(', ');
        findings.push(F('変更履歴の著者名が残存', authors.join(', '),
          '校閲・変更履歴に編集者の氏名が記録されています。', RISK.HIGH, 'Officeメタデータ'));
      }
    }));
  }
  if(isODF){
    var metaXml=findEntry('meta.xml');
    if(metaXml) tasks.push(zipReadEntry(bytes,metaXml).then(function(d){
      if(!d) return;
      var xml=decode(d);
      var rules=[
        {re:/<dc:creator>([^<]{1,200})<\/dc:creator>/,l:'作成者',r:RISK.HIGH,w:'ドキュメントの作成者名が含まれています。'},
        {re:/<meta:initial-creator>([^<]{1,200})<\/meta:initial-creator>/,l:'初版作成者',r:RISK.HIGH,w:'初版作成者名が含まれています。'},
        {re:/<meta:creation-date>([^<]{1,60})<\/meta:creation-date>/,l:'作成日時',r:RISK.MEDIUM,w:'作成日時が特定できます。'},
        {re:/<dc:date>([^<]{1,60})<\/dc:date>/,l:'更新日時',r:RISK.MEDIUM,w:'更新日時が特定できます。'},
        {re:/<meta:generator>([^<]{1,200})<\/meta:generator>/,l:'作成ソフト',r:RISK.MEDIUM,w:'使用ソフトウェアが特定できます。'}
      ];
      for(var i=0;i<rules.length;i++){
        var m=xml.match(rules[i].re);
        if(m && clean(m[1])){
          var v=xmlDecode(clean(m[1]));
          meta['[ODF] '+rules[i].l]=v;
          findings.push(F('ODF: '+rules[i].l, v, rules[i].w, rules[i].r, 'Officeメタデータ'));
        }
      }
    }));
  }
  /* 内包ファイルの再帰スキャン (深さ2まで、Office文書のmedia内画像のEXIF等も拾う) */
  var RECURSE_RE=/\.(jpe?g|png|gif|webp|tiff?|heic|avif|bmp|pdf|zip|docx|xlsx|pptx|exe|dll|scr|lnk|mp3|mp4|mov|7z|gz|svg|html?|pem|key|ppk|pfx|p12|der|jks|env|json|txt|ya?ml|conf|cfg|ini|crt|asc|md|csv|log)$/i;
  var RECURSE_NAMES=/(^|\/)(id_rsa|id_ed25519|id_ecdsa|id_dsa|credentials|\.env|\.npmrc|\.netrc)$/i;
  var thumbFromChild=null;
  if(depth<2){
    var scanList=entries.filter(function(e){
      return !e.encrypted && e.uncompSize>16 && e.uncompSize<20*1024*1024 &&
             (RECURSE_RE.test(e.name) || RECURSE_NAMES.test(e.name));
    }).slice(0,40);
    scanList.forEach(function(e){
      tasks.push(zipReadEntry(bytes,e).then(function(d){
        if(!d) return;
        var childName=e.name.split('/').pop();
        return analyzeBuffer(d, {name:childName, size:d.length}, depth+1).then(function(r){
          r.findings.forEach(function(f){
            if(f.risk>=RISK.MEDIUM){
              findings.push(F(e.name+' › '+f.key, f.val, f.why, f.risk, '内包ファイル'));
            }
          });
          if(r.thumbnail && !thumbFromChild) thumbFromChild=r.thumbnail;
        });
      }).catch(function(){}));
    });
  }
  return Promise.all(tasks).then(function(){ return {meta:meta, findings:findings, thumb:thumbFromChild}; });
}

/* =========================================================
 * 7-Zip (.7z)
 * ヘッダー自体がLZMA圧縮されることが多いため、まずLZMAでヘッダーを展開し
 * FilesInfoからファイル名一覧を得る。可能なら内包ファイルも展開して再帰スキャン。
 * ========================================================= */
function read7zNumber(b, st){
  var first=b[st.p++];
  var mask=0x80, value=0;
  for(var i=0;i<8;i++){
    if((first & mask)===0){
      value += (first & (mask-1)) * Math.pow(2, 8*i);
      break;
    }
    value += b[st.p++] * Math.pow(2, 8*i);
    mask >>= 1;
  }
  return value;
}
function read7zBitVector(b, st, n){
  var bits=[], mask=0, val=0;
  for(var i=0;i<n;i++){
    if(mask===0){ val=b[st.p++]; mask=0x80; }
    bits.push((val & mask)!==0);
    mask >>= 1;
  }
  return bits;
}
function read7zBoolVectorAllowAll(b, st, n){
  var allDefined=b[st.p++];
  if(allDefined!==0){ var a=[]; for(var i=0;i<n;i++) a.push(true); return a; }
  return read7zBitVector(b, st, n);
}

/* StreamsInfo (PackInfo + UnpackInfo + SubStreamsInfo) を末尾(kEnd)まで正確に消費する */
function parse7zStreamsInfo(b, st){
  var info={ packPos:0, packSizes:[], folders:[] };
  var folderCRCdefined=[];
  var id=b[st.p++];
  if(id===0x06){ /* PackInfo */
    info.packPos=read7zNumber(b, st);
    var numPack=read7zNumber(b, st);
    var t=b[st.p++];
    if(t===0x09){ /* kSize */
      for(var i=0;i<numPack;i++) info.packSizes.push(read7zNumber(b, st));
      t=b[st.p++];
    }
    if(t===0x0A){ /* PackリストのCRC(稀) */
      var pdef=read7zBoolVectorAllowAll(b, st, numPack);
      for(var pc=0;pc<pdef.length;pc++) if(pdef[pc]) st.p+=4;
      t=b[st.p++];
    }
    id=b[st.p++]; /* t は kEnd(0x00)。次のセクションIDを読む */
  }
  if(id===0x07){ /* UnpackInfo */
    b[st.p++]; /* kFolder */
    var numFolders=read7zNumber(b, st);
    b[st.p++]; /* external */
    for(var f=0;f<numFolders;f++) info.folders.push(parse7zFolder(b, st));
    b[st.p++]; /* kCodersUnpackSize */
    for(var f2=0;f2<info.folders.length;f2++){
      var fld=info.folders[f2];
      fld.unpackSizes=[];
      for(var s=0;s<fld.totalOut;s++) fld.unpackSizes.push(read7zNumber(b, st));
    }
    var nx=b[st.p++];
    if(nx===0x0A){ /* folderごとのCRC */
      folderCRCdefined=read7zBoolVectorAllowAll(b, st, numFolders);
      for(var c=0;c<folderCRCdefined.length;c++) if(folderCRCdefined[c]) st.p+=4;
      nx=b[st.p++];
    }
    id=b[st.p++]; /* nx は kEnd。次のセクションIDを読む */
  }
  if(id===0x08){ /* SubStreamsInfo */
    var st2=b[st.p++];
    var numUnpack=info.folders.map(function(){ return 1; });
    if(st2===0x0D){ /* kNumUnpackStream */
      for(var ff=0;ff<info.folders.length;ff++) numUnpack[ff]=read7zNumber(b, st);
      st2=b[st.p++];
    }
    info.numUnpack=numUnpack;
    info.subSizes=[];
    if(st2===0x09){ /* kSize: 各folderの最終streamを除くサイズ */
      for(var fs=0;fs<info.folders.length;fs++){
        var partial=[];
        for(var k=0;k<numUnpack[fs]-1;k++) partial.push(read7zNumber(b, st));
        info.subSizes.push(partial);
      }
      st2=b[st.p++];
    }
    if(st2===0x0A){ /* kCRC: folder既存CRC分を除いた数のdigest */
      var numDigests=0;
      for(var fd=0;fd<info.folders.length;fd++){
        var ns=numUnpack[fd];
        if(ns!==1 || !folderCRCdefined[fd]) numDigests+=ns;
      }
      var ddef=read7zBoolVectorAllowAll(b, st, numDigests);
      for(var dc=0;dc<ddef.length;dc++) if(ddef[dc]) st.p+=4;
      st2=b[st.p++];
    }
    while(st2!==0x00 && st.p<b.length){ st2=b[st.p++]; }
    id=b[st.p++];
  }
  return info;
}
function parse7zFolder(b, st){
  var numCoders=read7zNumber(b, st);
  var coders=[], totalIn=0, totalOut=0;
  for(var c=0;c<numCoders;c++){
    var flags=b[st.p++];
    var idSize=flags & 0x0F;
    var id=ascii(b, st.p, idSize); /* バイナリIDだが16進比較用に文字コードで保持 */
    var idHex='';
    for(var k=0;k<idSize;k++){ var v=b[st.p+k]; idHex+=(v<16?'0':'')+v.toString(16); }
    st.p+=idSize;
    var inS=1, outS=1;
    if(flags & 0x10){ inS=read7zNumber(b, st); outS=read7zNumber(b, st); }
    var props=null;
    if(flags & 0x20){ var psz=read7zNumber(b, st); props=b.slice(st.p, st.p+psz); st.p+=psz; }
    coders.push({ idHex:idHex, inS:inS, outS:outS, props:props });
    totalIn+=inS; totalOut+=outS;
  }
  /* BindPairs */
  var numBind=totalOut-1;
  var bindPairs=[];
  for(var bp=0;bp<numBind;bp++){ bindPairs.push([read7zNumber(b, st), read7zNumber(b, st)]); }
  /* PackedStreams */
  var numPacked=totalIn-numBind;
  if(numPacked>1){ for(var ps=0;ps<numPacked;ps++) read7zNumber(b, st); }
  return { coders:coders, totalIn:totalIn, totalOut:totalOut, bindPairs:bindPairs, numPacked:numPacked };
}

/* 単一folder・単一coder(Copy / LZMA / LZMA2)を展開 */
function decode7zFolder(b, folder, dataStart, packSize, outSize){
  if(folder.coders.length!==1) return null;
  var coder=folder.coders[0];
  var input=b.slice(dataStart, dataStart+packSize);
  if(coder.idHex==='00'){ return input.slice(0, outSize); } /* Copy */
  if(coder.idHex==='030101'){ /* LZMA1 */
    if(!LZMA || !coder.props) return null;
    return LZMA.decodeLZMA(coder.props, input, outSize);
  }
  if(coder.idHex==='21'){ /* LZMA2 (7zの既定。lc/lp/pbはチャンク内に持つ) */
    if(!LZMA || !LZMA.decodeLZMA2) return null;
    return LZMA.decodeLZMA2(input, outSize);
  }
  return null; /* BCJ等のフィルターチェーンは非対応 */
}

/* 展開済みヘッダー(kHeaderから)を読んでファイル名等を得る */
function parse7zHeader(b, st, archiveBytes, baseOffset){
  var result={ names:[], encrypted:false, emptyStreams:[], mainStreams:null };
  var id=b[st.p++];
  if(id===0x02){ /* ArchiveProperties — 飛ばす */
    var t=b[st.p++];
    while(t!==0x00){ var sz=read7zNumber(b, st); st.p+=sz; t=b[st.p++]; }
    id=b[st.p++];
  }
  if(id===0x03){ /* AdditionalStreamsInfo */
    parse7zStreamsInfo(b, st); id=b[st.p++];
  }
  if(id===0x04){ /* MainStreamsInfo */
    result.mainStreams=parse7zStreamsInfo(b, st);
    /* coderにAES(暗号化)が含まれるか */
    result.mainStreams.folders.forEach(function(fld){
      fld.coders.forEach(function(cd){ if(cd.idHex.indexOf('06f10701')===0) result.encrypted=true; });
    });
    id=b[st.p++];
  }
  if(id===0x05){ /* FilesInfo */
    var numFiles=read7zNumber(b, st);
    var names=[];
    for(;;){
      var propType=b[st.p++];
      if(propType===0x00) break;
      var size=read7zNumber(b, st);
      var end=st.p+size;
      if(propType===0x11){ /* kName */
        var external=b[st.p++];
        if(external===0){
          /* UTF-16LE, NUL区切り */
          var cur='';
          while(st.p+1<end){
            var ch=b[st.p] | (b[st.p+1]<<8); st.p+=2;
            if(ch===0){ names.push(cur); cur=''; }
            else cur+=String.fromCharCode(ch);
          }
        }
      } else if(propType===0x0E){ /* kEmptyStream: ディレクトリ/空ファイルのビットベクトル */
        result.emptyStreams=read7zBitVector(b, st, numFiles);
      }
      st.p=end;
    }
    result.names=names;
  }
  return result;
}

function parse7z(bytes, depth){
  depth=depth||0;
  var meta={}, findings=[];
  if(bytes.length<32) return Promise.resolve({meta:meta, findings:findings});
  meta['[7z] 形式']='7-Zipアーカイブ';
  var ver=bytes[6]+'.'+bytes[7];
  meta['[7z] フォーマットバージョン']='0.'+bytes[7];

  /* signature header */
  var nextHeaderOffset=u32le(bytes,12) + u32le(bytes,16)*4294967296;
  var nextHeaderSize=u32le(bytes,20) + u32le(bytes,24)*4294967296;
  var base=32;
  var hdrStart=base+nextHeaderOffset;
  if(hdrStart+nextHeaderSize>bytes.length || nextHeaderSize<1 || nextHeaderSize>64*1024*1024){
    findings.push(F('7z: ヘッダーを読めません', 'オフセット異常',
      'ファイルが破損しているか、対応範囲外の7zです。', RISK.LOW, '7zメタデータ'));
    return Promise.resolve({meta:meta, findings:findings});
  }

  var headerBytes=bytes.slice(hdrStart, hdrStart+nextHeaderSize);
  var st={ p:0 };
  var firstId=headerBytes[st.p];

  function finishWithHeader(hdr, fullArchive){
    var names=hdr.names||[];
    var realNames=names.filter(function(n){ return n && n.length; });
    if(realNames.length){
      meta['[7z] エントリ数']=String(realNames.length);
      meta['[7z] 含有ファイル']=realNames.slice(0,20).join(', ')+(realNames.length>20?' …':'');
    }
    if(hdr.encrypted){
      findings.push(F('7z: ファイル名が暗号化', 'ヘッダー暗号化(-mhe=on)',
        'ヘッダーごと暗号化された7zです。中身の確認にはパスワードが必要です。ウイルススキャン回避に使われることもあります。',
        RISK.MEDIUM, '7zセキュリティ'));
    }
    var execNames=realNames.filter(function(n){ return /\.(exe|dll|bat|ps1|vbs|js|jse|wsf|sh|cmd|scr|pif|com|jar|py|hta|msi|lnk)$/i.test(n); });
    if(execNames.length){
      findings.push(F('7z内に実行可能ファイル', execNames.slice(0,5).join(', '),
        '7zに実行可能ファイル・ショートカットが含まれています。マルウェア配布によく使われる手法です。', RISK.HIGH, '7zセキュリティ'));
    }
    if(realNames.some(function(n){ return n.indexOf('../')!==-1 || /^([A-Za-z]:|\\\\|\/)/.test(n); })){
      findings.push(F('7z パストラバーサルの疑い', '「../」や絶対パスを含むエントリ名',
        '展開時に意図しない場所へ書き込む攻撃の可能性があります。', RISK.HIGH, '7zセキュリティ'));
    }
    /* 中身を展開できない場合(暗号化等)でも、ファイル名から秘密鍵・認証情報を警告する */
    realNames.forEach(function(n){
      var base=n.split(/[\\/]/).pop();
      var ext2=(base.lastIndexOf('.')>0)?base.slice(base.lastIndexOf('.')+1).toLowerCase():'';
      detectKeyFiles(new Uint8Array(0), ext2, base).forEach(function(f){
        findings.push(F('7z内: '+f.key, n, f.why, f.risk, '暗号鍵'));
      });
    });
    return tryExtract7z(hdr).then(function(){ return {meta:meta, findings:findings}; });
  }

  /* 内包ファイルの展開→ファイル単位で再帰スキャン。
     folderを展開(Copy/LZMA/LZMA2単一coder)し、SubStreamsInfoの境界でファイルに分割する。 */
  function tryExtract7z(hdr){
    if(!hdr.mainStreams || hdr.encrypted || depth>=2) return Promise.resolve();
    var ms=hdr.mainStreams;
    /* 非空ストリームのファイル名 (folder順に並ぶ) */
    var streamNames=[];
    for(var i=0;i<(hdr.names||[]).length;i++){
      var isEmpty = hdr.emptyStreams && hdr.emptyStreams.length>i && hdr.emptyStreams[i];
      if(!isEmpty) streamNames.push(hdr.names[i]);
    }
    var packOffset=32+ms.packPos;
    var packIdx=0, streamCursor=0, totalScanned=0;
    var tasks=[];
    ms.folders.forEach(function(folder, fIdx){
      var np=folder.numPacked||1;
      var folderPackSize=0;
      for(var i=0;i<np;i++) folderPackSize+=(ms.packSizes[packIdx+i]||0);
      var outSize=folder.unpackSizes ? folder.unpackSizes[folder.unpackSizes.length-1] : 0;
      var numSub=(ms.numUnpack && ms.numUnpack[fIdx]!=null) ? ms.numUnpack[fIdx] : 1;
      var myNames=streamNames.slice(streamCursor, streamCursor+numSub);
      streamCursor+=numSub;
      var thisOffset=packOffset, thisPackSize=folderPackSize;
      packOffset+=folderPackSize;
      packIdx+=np;
      if(!(outSize>0 && outSize<40*1024*1024 && totalScanned<80*1024*1024 && thisOffset+thisPackSize<=bytes.length)) return;
      var decoded=decode7zFolder(bytes, folder, thisOffset, thisPackSize, outSize);
      if(!decoded) return;
      totalScanned+=decoded.length;
      /* substream境界で分割 (最後のサイズは folder合計 - 部分和) */
      var sizes=((ms.subSizes && ms.subSizes[fIdx]) || []).slice(0, Math.max(0,numSub-1));
      var sum=sizes.reduce(function(a,c){return a+c;},0);
      sizes.push(outSize-sum);
      var off=0;
      sizes.forEach(function(sz, si){
        if(sz<=0 || off+sz>decoded.length){ off+=Math.max(0,sz); return; }
        var child=decoded.slice(off, off+sz);
        off+=sz;
        var childName=(myNames[si]||('stream'+si)).split(/[\\/]/).pop();
        tasks.push(analyzeBuffer(child, {name:childName, size:child.length}, depth+1).then(function(r){
          r.findings.forEach(function(f){
            /* 名前ベースの警告は一覧側で出すので、ここでは内容ベースのみ */
            if(f.risk>=RISK.MEDIUM && !/ファイルの可能性$/.test(f.key)){
              findings.push(F((myNames[si]||childName)+' › '+f.key, f.val, f.why, f.risk, '内包ファイル'));
            }
          });
        }).catch(function(){}));
      });
    });
    return Promise.all(tasks);
  }

  if(firstId===0x01){
    /* 非圧縮ヘッダー */
    st.p++;
    var hdr=parse7zHeader(headerBytes, st, bytes, base);
    return finishWithHeader(hdr, bytes);
  } else if(firstId===0x17){
    /* EncodedHeader: StreamsInfoを読んで本ヘッダーをLZMA展開 */
    st.p++;
    var encInfo=parse7zStreamsInfo(headerBytes, st);
    if(!encInfo.folders.length || !encInfo.packSizes.length){
      meta['[7z] 注意']='ヘッダーを展開できませんでした';
      return Promise.resolve({meta:meta, findings:findings});
    }
    var folder=encInfo.folders[0];
    var outSize=folder.unpackSizes ? folder.unpackSizes[folder.unpackSizes.length-1] : 0;
    var dataStart=32+encInfo.packPos;
    var realHeader=decode7zFolder(bytes, folder, dataStart, encInfo.packSizes[0], outSize);
    if(!realHeader){
      var aes=folder.coders.some(function(c){return c.idHex.indexOf('06f10701')===0;});
      meta['[7z] 注意']= aes ? 'ヘッダー暗号化のため一覧を取得できません' : 'このヘッダー圧縮方式には未対応です';
      if(aes){
        findings.push(F('7z: ファイル名が暗号化', 'ヘッダー暗号化(-mhe=on)',
          'ヘッダーごと暗号化された7zです。中身の確認にはパスワードが必要です。', RISK.MEDIUM, '7zセキュリティ'));
      }
      return Promise.resolve({meta:meta, findings:findings});
    }
    var st2={ p:0 };
    var realId=realHeader[st2.p++];
    if(realId!==0x01){ return Promise.resolve({meta:meta, findings:findings}); }
    var hdr2=parse7zHeader(realHeader, st2, bytes, base);
    return finishWithHeader(hdr2, bytes);
  }
  return Promise.resolve({meta:meta, findings:findings});
}

/* =========================================================
 * RAR (RAR4 / RAR5)
 * 圧縮アルゴリズムは独自仕様のため展開はしないが、ファイル一覧・暗号化・
 * 実行ファイル混入を検出する。無圧縮(store)格納のファイルのみ再帰スキャン。
 * ========================================================= */
function parseRAR(bytes){
  var meta={}, findings=[];
  var isV5 = bytes.length>8 && bytes[6]===0x01 && bytes[7]===0x00;
  meta['[RAR] バージョン']= isV5 ? 'RAR 5.x' : 'RAR 4.x';
  var names=[], encryptedNames=false, headerEncrypted=false;
  var storeChildren=[];

  try{
    if(isV5) parseRAR5(bytes, names, storeChildren, function(){ headerEncrypted=true; }, function(){ encryptedNames=true; });
    else parseRAR4(bytes, names, storeChildren, function(){ encryptedNames=true; });
  }catch(e){}

  if(headerEncrypted){
    findings.push(F('RAR: ヘッダー暗号化', 'パスワード保護(-hp)',
      'ヘッダーごと暗号化されたRARです。中身の確認にはパスワードが必要です。', RISK.MEDIUM, 'RARセキュリティ'));
  }
  if(encryptedNames){
    findings.push(F('RAR: 暗号化されたエントリ', 'パスワード保護されたファイルあり',
      'パスワード付きRARはウイルススキャン回避にも使われます。', RISK.MEDIUM, 'RARセキュリティ'));
  }
  var realNames=names.filter(function(n){ return n && n.length; });
  if(realNames.length){
    meta['[RAR] エントリ数']=String(realNames.length);
    meta['[RAR] 含有ファイル']=realNames.slice(0,20).join(', ')+(realNames.length>20?' …':'');
  }
  var execNames=realNames.filter(function(n){ return /\.(exe|dll|bat|ps1|vbs|js|jse|wsf|sh|cmd|scr|pif|com|jar|py|hta|msi|lnk)$/i.test(n); });
  if(execNames.length){
    findings.push(F('RAR内に実行可能ファイル', execNames.slice(0,5).join(', '),
      'RARに実行可能ファイル・ショートカットが含まれています。マルウェア配布によく使われる手法です。', RISK.HIGH, 'RARセキュリティ'));
  }
  if(realNames.some(function(n){ return n.indexOf('../')!==-1 || n.indexOf('..\\')!==-1 || /^([A-Za-z]:|\\\\|\/)/.test(n); })){
    findings.push(F('RAR パストラバーサルの疑い', '「../」や絶対パスを含むエントリ名',
      '展開時に意図しない場所へ書き込む攻撃の可能性があります。', RISK.HIGH, 'RARセキュリティ'));
  }
  /* 中身を展開できなくても、ファイル名から秘密鍵・認証情報を警告する */
  realNames.forEach(function(n){
    var base=n.split(/[\\/]/).pop();
    var ext2=(base.lastIndexOf('.')>0)?base.slice(base.lastIndexOf('.')+1).toLowerCase():'';
    detectKeyFiles(new Uint8Array(0), ext2, base).forEach(function(f){
      findings.push(F('RAR内: '+f.key, n, f.why, f.risk, '暗号鍵'));
    });
  });
  storeChildren.slice(0,20).forEach(function(child){
    var cf=scanPatterns(child.data, false);
    cf.forEach(function(f){
      if(f.risk>=RISK.MEDIUM) findings.push(F('(RAR内 '+child.name+') '+f.key, f.val, f.why, f.risk, '内包ファイル'));
    });
  });
  return {meta:meta, findings:findings};
}

function parseRAR4(bytes, names, storeChildren, onEncrypted){
  var p=7;
  var guard=0;
  while(p+7<=bytes.length && guard++<5000){
    var headType=bytes[p+2];
    var headFlags=u16le(bytes,p+3);
    var headSize=u16le(bytes,p+5);
    if(headSize<7) break;
    var addSize=0;
    if(headFlags & 0x8000) addSize=u32le(bytes,p+7);
    if(headType===0x74){ /* File header */
      var nameLen=u16le(bytes,p+26);
      var flags=headFlags;
      var method=bytes[p+25];
      var attrOff=p+28;
      /* RAR4ファイルヘッダー: 32バイト固定 + 名前 */
      var nameStart=p+32;
      if((flags & 0x100)) nameStart+=8; /* HIGH_PACK/HIGH_UNP_SIZE: 64bitサイズで+8 */
      var nm=clean(decode(bytes.slice(nameStart, nameStart+nameLen), (flags&0x200)?'utf-16le':'latin1'));
      if(nm) names.push(nm);
      if(flags & 0x04) onEncrypted();
      /* store(0x30)かつ無暗号なら展開して再帰 */
      var dataStart=p+headSize;
      if(method===0x30 && !(flags&0x04) && addSize>16 && addSize<20*1024*1024 && dataStart+addSize<=bytes.length){
        if(/\.(jpe?g|png|pdf|docx|xlsx|pptx|txt|env|json|ya?ml|conf|cfg|ini|pem|key|crt|log|csv|md|html?)$/i.test(nm) || /(^|\/)(id_rsa|\.env|credentials)$/i.test(nm)){
          storeChildren.push({ name:nm.split(/[\\/]/).pop(), data:bytes.slice(dataStart, dataStart+addSize) });
        }
      }
    }
    p += headSize + addSize;
    if(headSize+addSize<=0) break;
  }
}

function parseRAR5(bytes, names, storeChildren, onHeaderEnc, onEncrypted){
  function rvint(st){
    var value=0, shift=0;
    for(var i=0;i<10;i++){
      var byte=bytes[st.p++];
      value += (byte & 0x7F) * Math.pow(2, shift);
      if((byte & 0x80)===0) break;
      shift+=7;
    }
    return value;
  }
  var st={ p:8 };
  var guard=0;
  while(st.p+4<bytes.length && guard++<5000){
    var blockStart=st.p;
    st.p+=4; /* CRC32 */
    var headerSize=rvint(st);
    if(headerSize<2 || st.p+headerSize>bytes.length) break;
    var headerStart=st.p;
    var headerType=rvint(st);
    var headerFlags=rvint(st);
    var extraSize=(headerFlags & 0x01) ? rvint(st) : 0;
    var dataSize=(headerFlags & 0x02) ? rvint(st) : 0;
    if(headerType===4){ /* 暗号化ヘッダー */
      onHeaderEnc();
    }
    if(headerType===2 || headerType===3){ /* File or Service header */
      var fileFlags=rvint(st);
      var unpSize=rvint(st);
      var attr=rvint(st);
      if(fileFlags & 0x02) st.p+=4; /* mtime */
      if(fileFlags & 0x04) st.p+=4; /* data CRC */
      var compInfo=rvint(st);
      var method=(compInfo>>7)&0x07;
      var hostOS=rvint(st);
      var nameLen=rvint(st);
      var nm=clean(decode(bytes.slice(st.p, st.p+nameLen), 'utf-8'));
      if(headerType===2 && nm) names.push(nm);
      /* extra area に暗号化レコードがあるか軽くチェック */
      var dataStart=headerStart+headerSize;
      if(method===0 && headerType===2 && dataSize>16 && dataSize<20*1024*1024 && dataStart+dataSize<=bytes.length){
        if(/\.(jpe?g|png|pdf|docx|xlsx|pptx|txt|env|json|ya?ml|conf|cfg|ini|pem|key|crt|log|csv|md|html?)$/i.test(nm) || /(^|\/)(id_rsa|\.env|credentials)$/i.test(nm)){
          storeChildren.push({ name:nm.split(/[\\/]/).pop(), data:bytes.slice(dataStart, dataStart+dataSize) });
        }
      }
    }
    st.p=headerStart+headerSize+dataSize;
    if(headerSize+dataSize<=0) break;
  }
}

/* ---------- MP3 (ID3v1 / v2.2 / v2.3 / v2.4) ---------- */
function parseMP3(bytes){
  var meta={}, findings=[];
  if(bytes[0]===0x49 && bytes[1]===0x44 && bytes[2]===0x33){
    var major=bytes[3];
    meta['[ID3] バージョン']='ID3v2.'+major+'.'+bytes[4];
    var tagSize=((bytes[6]&0x7F)<<21)|((bytes[7]&0x7F)<<14)|((bytes[8]&0x7F)<<7)|(bytes[9]&0x7F);
    var off=10;
    if(bytes[5]&0x40){ /* 拡張ヘッダーを飛ばす */
      var ehSize = major===4
        ? (((bytes[10]&0x7F)<<21)|((bytes[11]&0x7F)<<14)|((bytes[12]&0x7F)<<7)|(bytes[13]&0x7F))
        : u32be(bytes,10)+4;
      off+=ehSize;
    }
    var TAGS={TIT2:'タイトル',TPE1:'アーティスト',TALB:'アルバム',TYER:'年',TDRC:'録音日時',COMM:'コメント',
              TXXX:'ユーザー定義テキスト',TCOM:'作曲者',TENC:'エンコードした人',TSSE:'エンコードソフト',
              TCOP:'著作権',TOFN:'元ファイル名',TPUB:'発行者',WXXX:'ユーザー定義URL',
              TT2:'タイトル',TP1:'アーティスト',TAL:'アルバム',COM:'コメント',TEN:'エンコードした人'};
    var SENSITIVE={TXXX:1,TENC:1,TOFN:1,COMM:1,WXXX:1,TEN:1,COM:1,TSSE:1};
    var idLen = major===2 ? 3 : 4;
    var hdrLen = major===2 ? 6 : 10;
    var end=Math.min(tagSize+10, bytes.length);
    var guard=0;
    while(off+hdrLen<=end && guard++<2000){
      var fid=ascii(bytes,off,idLen);
      if(!/^[A-Z0-9]+$/.test(fid)) break;
      var fsz;
      if(major===2) fsz=(bytes[off+3]<<16)|(bytes[off+4]<<8)|bytes[off+5];
      else if(major===4) fsz=((bytes[off+4]&0x7F)<<21)|((bytes[off+5]&0x7F)<<14)|((bytes[off+6]&0x7F)<<7)|(bytes[off+7]&0x7F);
      else fsz=u32be(bytes,off+4);
      if(fsz<=0 || off+hdrLen+fsz>end) break;
      var fdata=bytes.slice(off+hdrLen, off+hdrLen+fsz);
      var label=TAGS[fid];
      if(label && fdata.length>1){
        var encByte=fdata[0];
        var body=fdata.slice(1);
        if(fid.indexOf('COM')===0 && body.length>4) body=body.slice(3); /* 言語コードを飛ばす */
        var encName = encByte===1 ? 'utf-16' : encByte===2 ? 'utf-16be' : encByte===3 ? 'utf-8' : 'latin1';
        var val=clean(decode(body,encName).replace(/\x00/g,' / '));
        if(val){
          meta['[ID3] '+label]=val.substring(0,200);
          if(SENSITIVE[fid]){
            findings.push(F('ID3: '+label+' ('+fid+')', val.substring(0,150),
              'エンコード環境・元ファイル名・コメント等に個人情報が含まれる可能性があります。', RISK.MEDIUM, 'ID3メタデータ'));
          }
        }
      } else if(fid==='APIC' || fid==='PIC'){
        meta['[ID3] カバー画像']='埋め込みあり';
      } else if(fid==='GEOB'){
        findings.push(F('ID3: 埋め込みオブジェクト(GEOB)', fsz+' bytes',
          '音声ファイル内に任意のファイルが埋め込まれています。', RISK.MEDIUM, 'ID3メタデータ'));
      } else if(fid==='PRIV'){
        var owner=clean(ascii(fdata,0,Math.min(60,fdata.length)));
        if(owner){
          meta['[ID3] PRIVフレーム']=owner;
          if(/microsoft|wmp|uniqueid/i.test(owner)){
            findings.push(F('ID3: PRIV(プレーヤー識別子)', owner,
              'Windows Media Player等の固有IDが埋め込まれている場合があります。', RISK.MEDIUM, 'ID3メタデータ'));
          }
        }
      }
      off+=hdrLen+fsz;
    }
  }
  /* ID3v1 (末尾128バイト) */
  if(bytes.length>=128 && ascii(bytes,bytes.length-128,3)==='TAG'){
    var b1=bytes.length-128;
    var t=clean(decode(bytes.slice(b1+3,b1+33),'latin1'));
    var a=clean(decode(bytes.slice(b1+33,b1+63),'latin1'));
    var c=clean(decode(bytes.slice(b1+97,b1+125),'latin1'));
    if(t) meta['[ID3v1] タイトル']=t;
    if(a) meta['[ID3v1] アーティスト']=a;
    if(c){
      meta['[ID3v1] コメント']=c;
      findings.push(F('ID3v1: コメント', c, 'コメント欄にテキストが含まれています。', RISK.LOW, 'ID3メタデータ'));
    }
  }
  return {meta:meta, findings:findings};
}

/* ---------- Vorbisコメント (FLAC / OGG) ---------- */
function parseVorbisComments(bytes, off, meta, findings, prefix){
  if(off+8>bytes.length) return;
  var vendorLen=u32le(bytes,off);
  if(vendorLen>10000 || off+4+vendorLen+4>bytes.length) return;
  var vendor=clean(decode(bytes.slice(off+4,off+4+vendorLen)));
  if(vendor) meta['['+prefix+'] エンコーダー(vendor)']=vendor;
  var p=off+4+vendorLen;
  var count=u32le(bytes,p); p+=4;
  if(count>500) return;
  var SENSITIVE={COMMENT:RISK.MEDIUM, ENCODER:RISK.MEDIUM, LOCATION:RISK.CRITICAL, CONTACT:RISK.HIGH,
                 PERFORMER:RISK.MEDIUM, ARTIST:RISK.MEDIUM, GEO_LOCATION:RISK.CRITICAL, EMAIL:RISK.HIGH};
  for(var i=0;i<count && p+4<=bytes.length;i++){
    var len=u32le(bytes,p); p+=4;
    if(len>100000 || p+len>bytes.length) break;
    var kv=decode(bytes.slice(p,p+len)); p+=len;
    var eq=kv.indexOf('=');
    if(eq>0){
      var key=kv.slice(0,eq).toUpperCase();
      var val=clean(kv.slice(eq+1));
      if(val){
        meta['['+prefix+'] '+key]=val.substring(0,200);
        if(SENSITIVE[key]!=null){
          findings.push(F(prefix+': '+key, val.substring(0,150),
            key.indexOf('LOCATION')!==-1 ? '位置情報が含まれています。' : '個人・環境の特定につながる情報です。',
            SENSITIVE[key], prefix+'メタデータ'));
        }
      }
    }
  }
}
function parseFLAC(bytes){
  var meta={}, findings=[];
  var i=4, guard=0;
  while(i+4<bytes.length && guard++<200){
    var hdr=bytes[i];
    var type=hdr&0x7F;
    var size=(bytes[i+1]<<16)|(bytes[i+2]<<8)|bytes[i+3];
    if(type===4) parseVorbisComments(bytes, i+4, meta, findings, 'FLAC');
    if(hdr&0x80) break;
    i+=4+size;
  }
  return {meta:meta, findings:findings};
}
function parseOGG(bytes){
  var meta={}, findings=[];
  var limit=Math.min(bytes.length-12, 256*1024);
  for(var i=0;i<limit;i++){
    if(ascii(bytes,i,8)==='OpusTags'){ parseVorbisComments(bytes, i+8, meta, findings, 'Opus'); break; }
    if(bytes[i]===0x03 && ascii(bytes,i+1,6)==='vorbis'){ parseVorbisComments(bytes, i+7, meta, findings, 'Vorbis'); break; }
  }
  return {meta:meta, findings:findings};
}

/* ---------- GZIP ---------- */
function parseGZIP(bytes){
  var meta={}, findings=[];
  if(bytes.length<18) return {meta:meta, findings:findings};
  var flg=bytes[3];
  var mtime=u32le(bytes,4);
  if(mtime>0){
    meta['[GZIP] 元ファイルの更新日時']=new Date(mtime*1000).toLocaleString('ja-JP');
  }
  var p=10;
  if(flg&4){ p+=2+u16le(bytes,p); }
  if(flg&8){
    var s=''; while(p<bytes.length && bytes[p]!==0 && s.length<300){ s+=String.fromCharCode(bytes[p]); p++; }
    p++;
    if(s){
      meta['[GZIP] 元ファイル名']=s;
      findings.push(F('GZIP: 元ファイル名', s,
        '圧縮前のファイル名(パスを含む場合あり)が記録されています。', RISK.MEDIUM, 'アーカイブメタデータ'));
    }
  }
  if(flg&16){
    var c=''; while(p<bytes.length && bytes[p]!==0 && c.length<300){ c+=String.fromCharCode(bytes[p]); p++; }
    if(clean(c)){
      meta['[GZIP] コメント']=clean(c);
      findings.push(F('GZIP: コメント', clean(c), 'コメントが埋め込まれています。', RISK.LOW, 'アーカイブメタデータ'));
    }
  }
  return {meta:meta, findings:findings};
}

/* ---------- PE ---------- */
function parsePE(bytes){
  var meta={}, findings=[];
  if(!(bytes[0]===0x4D && bytes[1]===0x5A)) return {meta:meta, findings:findings};
  meta['[PE] 形式']='Windows PE実行ファイル';
  var peOff=u32le(bytes,0x3C);
  if(peOff+24<bytes.length && bytes[peOff]===0x50 && bytes[peOff+1]===0x45 && bytes[peOff+2]===0 && bytes[peOff+3]===0){
    var machine=u16le(bytes,peOff+4);
    var mmap={0x014C:'x86(32bit)',0x8664:'x64(64bit)',0x01C0:'ARM',0xAA64:'ARM64'};
    meta['[PE] アーキテクチャ']=mmap[machine]||('不明(0x'+machine.toString(16)+')');
    var ts=u32le(bytes,peOff+8);
    if(ts>0 && ts<0xFFFFFFF0){
      var dt=new Date(ts*1000);
      var dts=dt.toLocaleString('ja-JP');
      meta['[PE] コンパイル日時']=dts;
      if(dt.getFullYear()>=1993 && dt.getTime()<Date.now()+86400000){
        findings.push(F('PE: コンパイル日時', dts, 'ビルド日時が分かります。作成時期の特定につながります。', RISK.LOW, 'PEヘッダー'));
      } else {
        findings.push(F('PE: 不審なタイムスタンプ', dts,
          'コンパイル日時が改ざんされている可能性があります(未来日付/異常値)。', RISK.MEDIUM, 'PEヘッダー'));
      }
    }
    var optMagic=u16le(bytes,peOff+24);
    if(optMagic===0x10B) meta['[PE] フォーマット']='PE32';
    else if(optMagic===0x20B) meta['[PE] フォーマット']='PE32+ (64bit)';
    findings.push(F('PE実行ファイル', 'アーキテクチャ: '+meta['[PE] アーキテクチャ'],
      'Windows実行可能ファイルです。出所が不明な場合は実行前にウイルススキャンを推奨します。', RISK.MEDIUM, 'PEヘッダー'));
  } else {
    findings.push(F('PE: ヘッダー異常', 'MZヘッダーはあるがPEシグネチャが見つかりません',
      '破損または特殊な形式(DOS実行ファイル等)の可能性があります。', RISK.LOW, 'PEヘッダー'));
  }
  /* 埋め込みビルドパス (PDB等) */
  var scanLen=Math.min(bytes.length, 4*1024*1024);
  var peText=decode(bytes.slice(0,scanLen),'latin1');
  var pdbM=peText.match(/[A-Za-z]:\\[^\x00-\x1F"<>|?*]{2,150}\.pdb/g);
  var pathM=peText.match(/[A-Za-z]:\\Users\\[^\x00-\x1F"<>|?*\\]{1,40}[^\x00-\x1F"<>|?*]{0,100}/g);
  var paths=[].concat(pdbM||[], pathM||[]);
  if(paths.length){
    var uniq=[]; paths.forEach(function(p){ if(uniq.indexOf(p)===-1) uniq.push(p); });
    uniq=uniq.slice(0,3);
    meta['[PE] 埋め込みパス']=uniq.join(' | ');
    findings.push(F('PE: ビルドパス埋め込み', uniq[0],
      'コンパイル時のソースコードパス(ユーザー名・ディレクトリ)が埋め込まれています。', RISK.HIGH, 'PEヘッダー'));
  }
  return {meta:meta, findings:findings};
}

/* ---------- OLE (旧Office / MSI) ---------- */
function parseOLE(bytes, ext){
  var meta={}, findings=[];
  meta['[OLE] 形式']='OLE複合ファイル';
  if(/^(doc|xls|ppt)$/.test(ext)){
    findings.push(F('旧Office形式', '.'+ext+' (OLE複合ファイル)',
      '旧形式のOfficeファイルはマクロウイルスを含む場合があります。出所を確認してください。', RISK.HIGH, 'Officeセキュリティ'));
  }
  var u16text=decode(bytes.slice(0,Math.min(bytes.length,2*1024*1024)),'utf-16le');
  if(/Macros|VBA_PROJECT|ThisDocument/i.test(u16text) || /\x00V\x00B\x00A/.test(ascii(bytes,0,Math.min(bytes.length,2*1024*1024)))){
    findings.push(F('VBAマクロの痕跡', 'VBA関連ストリーム名を検出',
      'マクロが含まれている可能性があります。', RISK.CRITICAL, 'Officeセキュリティ'));
  }
  return {meta:meta, findings:findings};
}

/* ---------- LNK ---------- */
function parseLNK(bytes){
  var meta={}, findings=[];
  meta['[LNK] 形式']='Windowsショートカット';
  findings.push(F('ショートカットファイル(LNK)', 'リンクターゲットを確認してください',
    'LNKファイルは任意のコマンドを引数付きで起動でき、マルウェア配布によく使われます。', RISK.HIGH, 'LNKセキュリティ'));
  /* ターゲットパス・引数らしき文字列を抽出 */
  var u16text=decode(bytes,'utf-16le');
  var atext=decode(bytes,'latin1');
  var paths=[];
  [u16text,atext].forEach(function(t){
    var m=t.match(/[A-Za-z]:\\[^\x00-\x1F"<>|*　]{3,200}/g);
    if(m) m.forEach(function(p){ if(paths.indexOf(p)===-1) paths.push(p); });
    var net=t.match(/\\\\[A-Za-z0-9._-]{2,40}\\[^\x00-\x1F"<>|*]{1,150}/g);
    if(net) net.forEach(function(p){ if(paths.indexOf(p)===-1) paths.push(p); });
  });
  if(paths.length){
    meta['[LNK] 参照パス']=paths.slice(0,5).join(' | ');
    findings.push(F('LNK: 参照パス', paths.slice(0,3).join(' | '),
      'リンク先パスにユーザー名・ホスト名・ネットワーク構成が含まれることがあります。', RISK.HIGH, 'LNKメタデータ'));
  }
  if(/powershell|cmd\.exe|mshta|wscript|cscript|rundll32|certutil|bitsadmin/i.test(u16text+atext)){
    findings.push(F('LNK: スクリプト実行の痕跡', 'PowerShell/cmd等の呼び出しを検出',
      'ショートカットがスクリプトインタープリターを起動します。悪性LNKの典型的な手口です。', RISK.CRITICAL, 'LNKセキュリティ'));
  }
  /* Trackerデータブロックのマシン名 (sig 0xA0000003) */
  for(var i=0;i<bytes.length-90;i++){
    if(u32le(bytes,i+4)===0xA0000003 && u32le(bytes,i)>=0x58){
      var mid=clean(ascii(bytes,i+16,16).replace(/\x00.*$/,''));
      if(mid && /^[a-zA-Z0-9_-]{2,16}$/.test(mid)){
        meta['[LNK] 作成元コンピューター名']=mid;
        findings.push(F('LNK: 作成元コンピューター名', mid,
          'ショートカット作成元PCのNetBIOS名が記録されています。', RISK.HIGH, 'LNKメタデータ'));
      }
      break;
    }
  }
  return {meta:meta, findings:findings};
}

/* ---------- RTF ---------- */
function parseRTF(bytes){
  var meta={}, findings=[];
  var text=decode(bytes.slice(0,Math.min(bytes.length,512*1024)),'latin1');
  var rules=[
    {re:/\{\\author ([^}]{1,200})\}/, l:'作成者', r:RISK.HIGH, w:'文書の作成者名が含まれています。'},
    {re:/\{\\operator ([^}]{1,200})\}/, l:'最終更新者', r:RISK.HIGH, w:'最後に編集したユーザー名が含まれています。'},
    {re:/\{\\company ([^}]{1,200})\}/, l:'会社名', r:RISK.HIGH, w:'組織名が埋め込まれています。'},
    {re:/\{\\title ([^}]{1,200})\}/, l:'タイトル', r:RISK.LOW, w:'文書タイトルが含まれています。'},
    {re:/\{\\doccomm ([^}]{1,200})\}/, l:'コメント', r:RISK.MEDIUM, w:'文書コメントが含まれています。'}
  ];
  for(var i=0;i<rules.length;i++){
    var m=text.match(rules[i].re);
    if(m && clean(m[1])){
      meta['[RTF] '+rules[i].l]=clean(m[1]);
      findings.push(F('RTF: '+rules[i].l, clean(m[1]), rules[i].w, rules[i].r, 'RTFメタデータ'));
    }
  }
  var cm=text.match(/\{\\creatim\\yr(\d+)\\mo(\d+)\\dy(\d+)/);
  if(cm){
    meta['[RTF] 作成日']=cm[1]+'-'+('0'+cm[2]).slice(-2)+'-'+('0'+cm[3]).slice(-2);
    findings.push(F('RTF: 作成日', meta['[RTF] 作成日'], '文書の作成日が特定できます。', RISK.MEDIUM, 'RTFメタデータ'));
  }
  if(/\\objupdate|\\objemb|\\objdata/.test(text)){
    findings.push(F('RTF: 埋め込みオブジェクト', 'OLEオブジェクトを検出',
      'RTFの埋め込みオブジェクトは脆弱性悪用(CVE-2017-11882等)に使われた実績があります。', RISK.HIGH, 'RTFセキュリティ'));
  }
  return {meta:meta, findings:findings};
}

/* ---------- SVG / HTML ---------- */
function parseMarkup(bytes, kind){
  var meta={}, findings=[];
  var text=decode(bytes.slice(0,Math.min(bytes.length,1024*1024)));
  if(kind==='svg'){
    if(/<script[\s>]/i.test(text)){
      findings.push(F('SVG: スクリプト埋め込み', '<script>タグ検出',
        'SVG内のJavaScriptはブラウザで開いた際に実行されます(XSS)。', RISK.CRITICAL, 'SVGセキュリティ'));
    }
    if(/\son(load|click|error|mouseover)\s*=/i.test(text)){
      findings.push(F('SVG: イベントハンドラー', 'on*属性検出',
        'イベントハンドラー経由でスクリプトが実行される可能性があります。', RISK.HIGH, 'SVGセキュリティ'));
    }
    if(/<foreignObject/i.test(text)){
      findings.push(F('SVG: foreignObject', '<foreignObject>検出',
        '任意のHTMLを埋め込めるためフィッシングに悪用されることがあります。', RISK.MEDIUM, 'SVGセキュリティ'));
    }
  }
  var gen=text.match(/<meta\s+name=["']generator["']\s+content=["']([^"']{1,150})["']/i);
  if(gen){
    meta['[HTML] ジェネレーター']=gen[1];
    findings.push(F('HTML: ジェネレーター', gen[1], '作成ソフトウェア・CMSのバージョンが特定できます。', RISK.MEDIUM, 'HTMLメタデータ'));
  }
  var inkscape=text.match(/inkscape:version="([^"]{1,80})"/);
  if(inkscape){
    meta['[SVG] Inkscapeバージョン']=inkscape[1];
    findings.push(F('SVG: 作成ソフト', 'Inkscape '+inkscape[1], '使用ソフトウェアが特定できます。', RISK.LOW, 'SVGメタデータ'));
  }
  var sodipodi=text.match(/sodipodi:docname="([^"]{1,150})"/);
  if(sodipodi){
    meta['[SVG] 元ファイル名']=sodipodi[1];
    findings.push(F('SVG: 元ファイル名', sodipodi[1], '編集時の元ファイル名が残っています。', RISK.MEDIUM, 'SVGメタデータ'));
  }
  var xmp=parseXMP(text);
  Object.assign(meta,xmp.meta); findings.push.apply(findings,xmp.findings);
  return {meta:meta, findings:findings};
}

/* ---------- 汎用パターンスキャン ---------- */
function luhnOk(numStr){
  var s=numStr.replace(/[^0-9]/g,'');
  if(s.length<13 || s.length>19) return false;
  var sum=0, alt=false;
  for(var i=s.length-1;i>=0;i--){
    var d=+s[i];
    if(alt){ d*=2; if(d>9) d-=9; }
    sum+=d; alt=!alt;
  }
  return sum%10===0;
}
function scanPatterns(bytes, isTextFile){
  var findings=[];
  var maxScan=Math.min(bytes.length, 1024*1024);
  var text=decode(bytes.slice(0,maxScan));
  /* 大きいファイルは末尾も見る(ログ末尾の認証情報等) */
  if(bytes.length>maxScan){
    text+='\n'+decode(bytes.slice(Math.max(maxScan, bytes.length-256*1024)));
  }
  /* バイナリファイルはUTF-16LE文字列も拾う(Windows系バイナリに多い) */
  if(!isTextFile){
    text+='\n'+decode(bytes.slice(0,Math.min(bytes.length,512*1024)),'utf-16le').replace(/[\x00-\x08\x0E-\x1F]/g,'\n');
  }
  var pats=[
    {re:/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, k:'メールアドレス', w:'個人を特定できるメールアドレスが含まれています。', r:RISK.HIGH, c:'個人情報',
     filter:function(v){ return !/@(example\.(com|org|net)|w3\.org|openxmlformats\.org|adobe\.com|purl\.org)/i.test(v); }},
    {re:/\b(?:\+81[-\s]?\d{1,4}|0\d{1,4})-\d{2,4}-\d{3,4}\b/g, k:'電話番号', w:'電話番号が含まれている可能性があります。', r:RISK.HIGH, c:'個人情報'},
    {re:/(?:password|passwd|pwd)\s*["']?\s*[:=]\s*["']?[^\n\s"']{4,60}/gi, k:'パスワード', w:'パスワードのプレーンテキストが含まれている可能性があります。', r:RISK.CRITICAL, c:'認証情報'},
    {re:/(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token)\s*["']?\s*[:=]\s*["']?[A-Za-z0-9\-_.]{16,}/gi, k:'APIキー/トークン', w:'APIキー・シークレットが含まれている可能性があります。', r:RISK.CRITICAL, c:'認証情報'},
    {re:/-----BEGIN [A-Z ]*PRIVATE KEY-----/g, k:'秘密鍵(PEM)', w:'秘密鍵がファイルに含まれています。', r:RISK.CRITICAL, c:'暗号鍵'},
    {re:/-----BEGIN PGP PRIVATE KEY BLOCK-----/g, k:'PGP秘密鍵', w:'PGP秘密鍵ブロックが含まれています。', r:RISK.CRITICAL, c:'暗号鍵'},
    {re:/PuTTY-User-Key-File-[23]:/g, k:'PuTTY秘密鍵(PPK)', w:'PuTTY形式の秘密鍵が含まれています。', r:RISK.CRITICAL, c:'暗号鍵'},
    {re:/aws_secret_access_key\s*[=:]\s*["']?[A-Za-z0-9/+=]{35,45}/gi, k:'AWSシークレットアクセスキー', w:'AWSのシークレットキーが含まれています。アクセスキーIDとセットで悪用されます。', r:RISK.CRITICAL, c:'クラウド認証情報'},
    {re:/AccountKey=[A-Za-z0-9+/=]{60,}/g, k:'Azureストレージキー', w:'Azureストレージアカウントキーが含まれています。', r:RISK.CRITICAL, c:'クラウド認証情報'},
    {re:/"type"\s*:\s*"service_account"/g, k:'GCPサービスアカウントJSON', w:'Google Cloudのサービスアカウント認証ファイルの可能性があります(private_keyを含む形式)。', r:RISK.CRITICAL, c:'クラウド認証情報'},
    {re:/AKIA[A-Z0-9]{16}/g, k:'AWSアクセスキーID', w:'AWS認証キーが含まれています。不正利用される可能性があります。', r:RISK.CRITICAL, c:'クラウド認証情報'},
    {re:/gh[pousr]_[A-Za-z0-9]{36,}/g, k:'GitHubトークン', w:'GitHubアクセストークンが含まれています。', r:RISK.CRITICAL, c:'クラウド認証情報'},
    {re:/AIza[A-Za-z0-9\-_]{35}/g, k:'Google APIキー', w:'Google APIキーが含まれています。', r:RISK.CRITICAL, c:'クラウド認証情報'},
    {re:/sk-(?:proj-)?[A-Za-z0-9_-]{32,}/g, k:'OpenAI/Anthropic系APIキーの疑い', w:'AIサービスのAPIキーの可能性があります。', r:RISK.CRITICAL, c:'クラウド認証情報'},
    {re:/xox[bpoas]-[A-Za-z0-9-]{10,}/g, k:'Slackトークン', w:'Slack APIトークンが含まれています。', r:RISK.CRITICAL, c:'クラウド認証情報'},
    {re:/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, k:'JWTトークン', w:'JSON Web Tokenが含まれています。セッション乗っ取りに悪用される可能性があります。', r:RISK.HIGH, c:'認証情報'},
    {re:/(?:jdbc:|mongodb(?:\+srv)?:|redis:|postgres(?:ql)?:|mysql:|amqp:|ftp:)\/\/[^\s"'<>]{5,150}/gi, k:'接続文字列URL', w:'DB等の接続文字列(認証情報を含む場合がある)が検出されました。', r:RISK.CRITICAL, c:'認証情報',
     filter:function(v){ return /@|:\/\/[^/]*:[^/@]*@/.test(v) || !/^ftp:\/\/(ftp\.|anonymous)/i.test(v); }},
    {re:/\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})){3}\b/g, k:'IPアドレス', w:'サーバー・クライアントのIPアドレスが含まれています。', r:RISK.MEDIUM, c:'ネットワーク情報',
     filter:function(v){
       if(v==='0.0.0.0' || v==='255.255.255.255' || v.indexOf('127.')===0) return false;
       /* 全オクテットが10未満はバージョン番号(1.2.3.4等)の可能性が高いので除外 */
       return !v.split('.').every(function(o){ return +o<10; });
     }},
    {re:/https?:\/\/(?:192\.168|10\.|172\.(?:1[6-9]|2\d|3[01]))\.[^\s"'<>]{1,100}/g, k:'内部URL(プライベートIP)', w:'内部ネットワークのURLが含まれています。ネットワーク構成が露見します。', r:RISK.HIGH, c:'ネットワーク情報'},
    {re:/(?:\/home\/|\/Users\/|[A-Za-z]:\\Users\\)[^\s"'<>:/\\]{1,40}/g, k:'ホームディレクトリパス', w:'ユーザー名を含むファイルパスが埋め込まれています。', r:RISK.HIGH, c:'ファイルパス'},
    {re:/(?:lat(?:itude)?|lng|lon(?:gitude)?)["']?\s*[:=]\s*["']?-?\d{1,3}\.\d{4,}/gi, k:'GPS座標(テキスト)', w:'緯度・経度座標が含まれています。', r:RISK.HIGH, c:'位置情報'},
    {re:/\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{2,4}\b/g, k:'クレジットカード番号の疑い', w:'カード番号らしき数字列が含まれています(Luhn検査通過)。', r:RISK.CRITICAL, c:'個人情報',
     filter:luhnOk},
    {re:/-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}/gi, k:'PowerShellエンコードコマンド', w:'Base64でエンコードされたPowerShellコマンドはマルウェアの典型的手口です。', r:RISK.CRITICAL, c:'スクリプトセキュリティ'}
  ];
  for(var i=0;i<pats.length;i++){
    var p=pats[i];
    var ms=text.match(p.re);
    if(ms && ms.length){
      var uniq=[];
      for(var j=0;j<ms.length;j++){
        var v=ms[j];
        if(p.filter && !p.filter(v)) continue;
        if(uniq.indexOf(v)===-1) uniq.push(v);
        if(uniq.length>=3) break;
      }
      if(uniq.length){
        var total=ms.length;
        findings.push(F(p.k, uniq.join(' / ')+(total>3?'  (他'+(total-3)+'件)':''), p.w, p.r, p.c));
      }
    }
  }
  return findings;
}

/* ---------- 秘密鍵・キーストアの検出 (テキストPEM以外) ---------- */
function detectKeyFiles(bytes, ext, name){
  var findings=[];
  var base=(name||'').split(/[\\/]/).pop().toLowerCase();
  /* ファイル名ヒューリスティック */
  if(/^(id_rsa|id_ed25519|id_ecdsa|id_dsa)(\.|$)/.test(base) && !/\.pub$/.test(base)){
    findings.push(F('SSH秘密鍵ファイルの可能性', base,
      'ファイル名がSSH秘密鍵の標準名です。アップロード対象に紛れ込んでいないか確認してください。',
      RISK.CRITICAL, '暗号鍵'));
  } else if(base==='.env' || base==='credentials' || base==='.npmrc' || base==='.netrc' ||
            /\.(pem|ppk|jks|keystore)$/.test(base)){
    findings.push(F('認証情報ファイルの可能性', base,
      '鍵・認証情報を保存する種類のファイルです。内容と共有先を確認してください。',
      RISK.HIGH, '暗号鍵'));
  }
  /* バイナリ形式のキーストア */
  if(bytes.length>4){
    if(bytes[0]===0xFE && bytes[1]===0xED && bytes[2]===0xFE && bytes[3]===0xED){
      findings.push(F('Javaキーストア(JKS)', 'マジックバイト検出',
        '秘密鍵・証明書を格納するキーストアファイルです。', RISK.CRITICAL, '暗号鍵'));
    }
    if((ext==='pfx'||ext==='p12') && bytes[0]===0x30 && bytes[1]===0x82){
      findings.push(F('PKCS#12キーストア', '.'+ext+' (ASN.1構造)',
        '秘密鍵と証明書を格納するファイルです。パスワードが弱い場合は解読される可能性があります。', RISK.CRITICAL, '暗号鍵'));
    }
    if((ext==='der'||ext==='key') && bytes[0]===0x30 && bytes[1]===0x82){
      findings.push(F('DER形式の鍵データの可能性', '.'+ext+' (ASN.1構造)',
        'バイナリ形式(DER)の秘密鍵・証明書の可能性があります。', RISK.HIGH, '暗号鍵'));
    }
  }
  return findings;
}

/* ---------- ファイル名解析 ---------- */
function analyzeFileName(name){
  var findings=[];
  if(/\.(exe|bat|vbs|js|jse|wsf|ps1|cmd|scr|com|hta|pif|lnk)$/i.test(name) &&
     /\.(jpe?g|png|gif|pdf|docx?|xlsx?|pptx?|txt|zip|mp[34])\.[a-z0-9]{2,4}$/i.test(name)){
    findings.push(F('二重拡張子', name,
      '文書・画像に見せかけた実行ファイルの可能性が高いです(例: file.pdf.exe)。', RISK.CRITICAL, 'ファイル名偽装'));
  } else if(/\.[a-z0-9]{2,5}\.(exe|bat|vbs|js|jse|wsf|ps1|cmd|scr|com|hta|pif)$/i.test(name)){
    findings.push(F('二重拡張子の疑い', name,
      '拡張子を偽装する二重拡張子の可能性があります。', RISK.HIGH, 'ファイル名偽装'));
  }
  var BIDI=/[‪-‮‎‏​⁦-⁩]/;
  if(BIDI.test(name)){
    findings.push(F('Unicode方向制御文字', name.replace(/[‪-‮‎‏​⁦-⁩]/g,'�'),
      'RLO等の不可視制御文字でファイル名・拡張子を偽装している可能性があります。', RISK.CRITICAL, 'ファイル名偽装'));
  }
  if(/\s{4,}\.[a-z0-9]+$/i.test(name)){
    findings.push(F('大量スペースで拡張子隠蔽の疑い', name,
      '多数のスペースで本当の拡張子を画面外に押し出す偽装の可能性があります。', RISK.HIGH, 'ファイル名偽装'));
  }
  return findings;
}

/* ---------- エントロピー ---------- */
function calcEntropy(bytes){
  if(!bytes.length) return 0;
  var freq=new Array(256).fill(0);
  for(var i=0;i<bytes.length;i++) freq[bytes[i]]++;
  var e=0, len=bytes.length;
  for(var j=0;j<256;j++){
    if(freq[j]>0){ var p=freq[j]/len; e-=p*Math.log2(p); }
  }
  return e;
}
/* もともと圧縮されている形式では高エントロピーは正常 */
var COMPRESSED_KINDS={jpeg:1,png:1,gif:1,webp:1,heic:1,avif:1,zip:1,'7z':1,rar:1,gzip:1,bz2:1,xz:1,zstd:1,
                      mp3:1,mp4:1,mkv:1,flac:1,ogg:1,wasm:1,tiff:1,bmp:0};

/* =========================================================
 * メインエントリーポイント
 * ========================================================= */
function analyzeBuffer(bytes, info, depth){
  info=info||{};
  depth=depth||0;
  var name=info.name||'';
  var dotIdx=name.lastIndexOf('.');
  var ext=(dotIdx>0 && dotIdx<name.length-1) ? name.slice(dotIdx+1).toLowerCase() : '';
  var meta={}, findings=[], thumbnail=null;

  meta['ファイル名']=name||'(不明)';
  meta['サイズ']=fmtBytes(info.size!=null?info.size:bytes.length);
  meta['MIMEタイプ']=info.type||'不明';
  if(info.lastModified) meta['最終更新']=new Date(info.lastModified).toLocaleString('ja-JP');
  meta['拡張子']=ext||'なし';

  var magic=detectMagic(bytes);
  var kind=magic?magic.id:null;
  if(magic){
    meta['ファイル形式（マジック）']=magic.label;
    checkMismatch(ext, magic, findings);
  }

  function merge(r){
    if(!r) return;
    Object.assign(meta,r.meta||{});
    if(r.findings) findings.push.apply(findings,r.findings);
    if(r.thumb && !thumbnail) thumbnail=r.thumb;
  }
  function safe(fn){
    try{
      var r=fn();
      if(r && typeof r.then==='function') return r.then(function(v){merge(v);}).catch(function(){});
      merge(r);
    }catch(e){}
    return Promise.resolve();
  }

  var tasks=[];
  if(kind==='jpeg') tasks.push(safe(function(){return parseJPEG(bytes);}));
  else if(kind==='png') tasks.push(safe(function(){return parsePNG(bytes);}));
  else if(kind==='gif') tasks.push(safe(function(){return parseGIF(bytes);}));
  else if(kind==='tiff') tasks.push(safe(function(){return parseTIFF(bytes,0);}));
  else if(kind==='webp'||kind==='wav'||kind==='avi'||kind==='riff') tasks.push(safe(function(){return parseRIFF(bytes);}));
  else if(kind==='heic'||kind==='avif') tasks.push(safe(function(){return parseHEIC(bytes);}));
  else if(kind==='mp4') tasks.push(safe(function(){return parseMP4(bytes);}));
  else if(kind==='pdf') tasks.push(safe(function(){return parsePDF(bytes);}));
  else if(kind==='zip') tasks.push(safe(function(){return parseZIPFamily(bytes,ext,depth);}));
  else if(kind==='7z') tasks.push(safe(function(){return parse7z(bytes,depth);}));
  else if(kind==='rar') tasks.push(safe(function(){return parseRAR(bytes);}));
  else if(kind==='mp3') tasks.push(safe(function(){return parseMP3(bytes);}));
  else if(kind==='flac') tasks.push(safe(function(){return parseFLAC(bytes);}));
  else if(kind==='ogg') tasks.push(safe(function(){return parseOGG(bytes);}));
  else if(kind==='gzip') tasks.push(safe(function(){return parseGZIP(bytes);}));
  else if(kind==='pe') tasks.push(safe(function(){return parsePE(bytes);}));
  else if(kind==='ole') tasks.push(safe(function(){return parseOLE(bytes,ext);}));
  else if(kind==='lnk') tasks.push(safe(function(){return parseLNK(bytes);}));
  else if(kind==='rtf') tasks.push(safe(function(){return parseRTF(bytes);}));
  else if(kind==='svg'||kind==='html'||kind==='xml') tasks.push(safe(function(){return parseMarkup(bytes,kind);}));
  /* ID3はMP3判定漏れ(壊れたフレーム同期)でもextがmp3なら試す */
  if(kind!=='mp3' && ext==='mp3') tasks.push(safe(function(){return parseMP3(bytes);}));

  var isTextLike=(kind==='text'||kind==='utf16'||kind==='html'||kind==='svg'||kind==='xml'||kind==='rtf');
  findings.push.apply(findings, scanPatterns(bytes, isTextLike));
  findings.push.apply(findings, detectKeyFiles(bytes, ext, name));
  findings.push.apply(findings, analyzeFileName(name));

  var entropy=calcEntropy(bytes.slice(0, Math.min(65536, bytes.length)));
  meta['エントロピー（先頭64KB）']=entropy.toFixed(3)+' bits/byte';
  if(entropy>7.5 && !COMPRESSED_KINDS[kind]){
    if(kind==='pe'){
      findings.push(F('PE: パッカー/難読化の可能性', entropy.toFixed(3)+' bits/byte',
        '実行ファイルが高エントロピーです。UPX等のパッカーや難読化(マルウェアの典型的特徴)の可能性があります。',
        RISK.HIGH, 'バイナリ解析'));
    } else {
      findings.push(F('高エントロピー検出', entropy.toFixed(3)+' bits/byte',
        '暗号化・圧縮・難読化されたデータの可能性があります。', RISK.MEDIUM, 'バイナリ解析'));
    }
  }

  /* SHA-256 (ハードウェア支援)。再帰スキャンの子ファイルでは省略 */
  if(depth===0 && typeof crypto!=='undefined' && crypto.subtle && bytes.length>0){
    tasks.push(crypto.subtle.digest('SHA-256', bytes).then(function(buf){
      var h=new Uint8Array(buf), hex='';
      for(var i=0;i<h.length;i++) hex+=(h[i]<16?'0':'')+h[i].toString(16);
      meta['SHA-256']=hex;
    }).catch(function(){}));
  }

  return Promise.all(tasks).then(function(){
    /* 重複除去・上限 */
    var seen={}, dedup=[];
    for(var i=0;i<findings.length;i++){
      var f=findings[i];
      var k=f.key+'|'+f.val;
      if(seen[k]) continue;
      seen[k]=1;
      dedup.push(f);
      if(dedup.length>=80) break;
    }
    return {metadata:meta, findings:dedup, thumbnail:thumbnail};
  });
}

var api={
  analyzeBuffer:analyzeBuffer, detectMagic:detectMagic, RISK:RISK, fmtBytes:fmtBytes,
  /* cleaner.js が利用するZIP低レベルAPI */
  zip:{ listEntries:listZipEntries, readEntry:zipReadEntry, inflateRaw:inflateRaw }
};
if(typeof module!=='undefined' && module.exports) module.exports=api;
else global.MetaScanEngine=api;

})(typeof window!=='undefined'?window:globalThis);
