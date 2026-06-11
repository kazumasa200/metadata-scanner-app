/* =========================================================
 * MetaScan クリーナー — メタデータを除去した安全なコピーを生成する
 * 公開API:
 *   supports(name, bytes) -> {ok:true} | {ok:false, reason}
 *   clean(bytes, name) -> Promise<{bytes:Uint8Array, removed:[string]}>
 * 対応: JPEG / PNG / WebP / MP3 / docx,xlsx,pptx / odt,ods,odp
 * 非対応: PDF・MP4(構造的にオフセット修正が必要で破損リスクがあるため)
 * ========================================================= */
(function(global){
'use strict';

var Engine = (typeof module!=='undefined' && module.exports) ? require('./engine.js') : global.MetaScanEngine;

function u16le(b,o){ return b[o] | (b[o+1]<<8); }
function u32be(b,o){ return ((b[o]<<24)|(b[o+1]<<16)|(b[o+2]<<8)|b[o+3])>>>0; }
function ascii(b,o,n){
  var s=''; for(var i=0;i<n && o+i<b.length;i++) s+=String.fromCharCode(b[o+i]);
  return s;
}
function concat(parts){
  var total=0;
  parts.forEach(function(p){ total+=p.length; });
  var out=new Uint8Array(total), off=0;
  parts.forEach(function(p){ out.set(p,off); off+=p.length; });
  return out;
}

/* ---------- CRC32 (ZIP再構築用) ---------- */
var CRC_TABLE=(function(){
  var t=new Uint32Array(256);
  for(var n=0;n<256;n++){
    var c=n;
    for(var k=0;k<8;k++) c = (c&1) ? (0xEDB88320 ^ (c>>>1)) : (c>>>1);
    t[n]=c>>>0;
  }
  return t;
})();
function crc32(data){
  var c=0xFFFFFFFF;
  for(var i=0;i<data.length;i++) c = CRC_TABLE[(c ^ data[i]) & 0xFF] ^ (c>>>8);
  return (c ^ 0xFFFFFFFF)>>>0;
}

/* deflate-raw 圧縮 (Nodeはzlib、ブラウザはCompressionStream) */
function deflateRaw(data){
  if(typeof require!=='undefined' && typeof process!=='undefined' && process.versions && process.versions.node){
    try{ return Promise.resolve(new Uint8Array(require('zlib').deflateRawSync(data))); }catch(e){ return Promise.resolve(null); }
  }
  if(typeof CompressionStream==='undefined') return Promise.resolve(null);
  try{
    var cs=new CompressionStream('deflate-raw');
    return new Response(new Blob([data]).stream().pipeThrough(cs)).arrayBuffer()
      .then(function(b){ return new Uint8Array(b); }).catch(function(){ return null; });
  }catch(e){ return Promise.resolve(null); }
}

/* ---------- JPEG ---------- */
function cleanJPEG(bytes){
  var removed=[];
  var out=[bytes.slice(0,2)]; /* SOI */
  var i=2;
  while(i+2<=bytes.length){
    if(bytes[i]!==0xFF){ i++; continue; }
    var marker=bytes[i+1];
    if(marker===0xFF){ i++; continue; }
    if(marker===0x01 || (marker>=0xD0 && marker<=0xD8)){ out.push(bytes.slice(i,i+2)); i+=2; continue; }
    if(marker===0xD9){ out.push(bytes.slice(i,i+2)); break; }
    if(i+4>bytes.length) break; /* セグメント長を読めない */
    if(marker===0xDA){
      /* SOS以降は真のEOIまでコピーし、終端以降の余剰データは捨てる */
      var eoi=-1;
      for(var j=i+2;j<bytes.length-1;j++){
        if(bytes[j]===0xFF && bytes[j+1]===0xD9){ eoi=j; break; }
      }
      if(eoi===-1){ out.push(bytes.slice(i)); }
      else{
        out.push(bytes.slice(i,eoi+2));
        if(bytes.length-(eoi+2)>4) removed.push('終端以降の余剰データ('+(bytes.length-eoi-2)+' bytes)');
      }
      break;
    }
    var segLen=(bytes[i+2]<<8)|bytes[i+3];
    if(segLen<2) break;
    var segEnd=Math.min(i+2+segLen, bytes.length);
    var drop=false;
    if(marker===0xE1){
      var hdr=ascii(bytes,i+4,28);
      if(hdr.indexOf('Exif')===0){ drop=true; removed.push('EXIF(撮影情報・GPS・サムネイル)'); }
      else if(hdr.indexOf('http://ns.adobe.com/xap/')===0){ drop=true; removed.push('XMP'); }
    } else if(marker===0xED){ drop=true; removed.push('IPTC/Photoshop(APP13)'); }
    else if(marker===0xFE){ drop=true; removed.push('コメント(COM)'); }
    if(!drop) out.push(bytes.slice(i, i+2+segLen));
    i=i+2+segLen;
  }
  return Promise.resolve({ bytes:concat(out), removed:dedupe(removed) });
}

/* ---------- PNG ---------- */
var PNG_DROP={ tEXt:1, iTXt:1, zTXt:1, eXIf:1, tIME:1 };
function cleanPNG(bytes){
  var removed=[];
  var out=[bytes.slice(0,8)];
  var i=8, guard=0;
  while(i+12<=bytes.length && guard++<10000){
    var len=u32be(bytes,i);
    var type=ascii(bytes,i+4,4);
    if(len>0x7FFFFFFF || i+12+len>bytes.length) break;
    if(PNG_DROP[type]){
      removed.push('PNG '+type+'チャンク');
    } else {
      out.push(bytes.slice(i, i+12+len)); /* CRCごとそのままコピーするので壊れない */
    }
    if(type==='IEND'){
      if(bytes.length-(i+12+len)>4) removed.push('終端以降の余剰データ');
      break;
    }
    i+=12+len;
  }
  return Promise.resolve({ bytes:concat(out), removed:dedupe(removed) });
}

/* ---------- WebP (RIFF) ---------- */
function cleanWebP(bytes){
  var removed=[];
  var chunks=[];
  var i=12, guard=0;
  while(i+8<=bytes.length && guard++<5000){
    var id=ascii(bytes,i,4);
    var size=(bytes[i+4]|(bytes[i+5]<<8)|(bytes[i+6]<<16)|(bytes[i+7]<<24))>>>0;
    if(size>bytes.length-i-8+1) break;
    var chunk=bytes.slice(i, i+8+size+(size&1));
    if(id==='EXIF'){ removed.push('EXIF'); }
    else if(id==='XMP '){ removed.push('XMP'); }
    else {
      if(id==='VP8X' && chunk.length>=9){
        chunk=chunk.slice(); /* コピーしてフラグのEXIF/XMPビットを落とす */
        chunk[8]=chunk[8] & ~0x0C;
      }
      chunks.push(chunk);
    }
    i+=8+size+(size&1);
  }
  var body=concat(chunks);
  var header=new Uint8Array(12);
  header.set(bytes.slice(0,4),0); /* RIFF */
  var total=body.length+4;
  header[4]=total&255; header[5]=(total>>8)&255; header[6]=(total>>16)&255; header[7]=(total>>>24)&255;
  header.set(bytes.slice(8,12),8); /* WEBP */
  return Promise.resolve({ bytes:concat([header,body]), removed:dedupe(removed) });
}

/* ---------- MP3 ---------- */
function cleanMP3(bytes){
  var removed=[];
  var start=0, end=bytes.length;
  if(bytes[0]===0x49 && bytes[1]===0x44 && bytes[2]===0x33){
    var tagSize=((bytes[6]&0x7F)<<21)|((bytes[7]&0x7F)<<14)|((bytes[8]&0x7F)<<7)|(bytes[9]&0x7F);
    start=10+tagSize;
    if(bytes[5]&0x10) start+=10; /* フッター */
    if(start>=bytes.length) start=0;
    else removed.push('ID3v2タグ');
  }
  if(end>=128 && ascii(bytes,end-128,3)==='TAG'){
    end-=128;
    removed.push('ID3v1タグ');
    if(end>=227 && ascii(bytes,end-227,4)==='TAG+'){ end-=227; removed.push('ID3v1拡張タグ'); }
  }
  return Promise.resolve({ bytes:bytes.slice(start,end), removed:dedupe(removed) });
}

/* ---------- Office (docx/xlsx/pptx) & ODF ---------- */
function blankTag(xml, tag, replacement){
  var re=new RegExp('(<'+tag+'(?:\\s[^>]*)?>)[\\s\\S]*?(</'+tag+'>)');
  return xml.replace(re, function(_, a, b){ return a+(replacement||'')+b; });
}
function transformOfficeXml(name, xml, removed){
  var before=xml;
  if(name==='docProps/core.xml'){
    xml=blankTag(xml,'dc:creator');
    xml=blankTag(xml,'cp:lastModifiedBy');
    xml=blankTag(xml,'dc:description');
    xml=blankTag(xml,'cp:keywords');
    xml=blankTag(xml,'cp:category');
    xml=blankTag(xml,'dcterms:created','2000-01-01T00:00:00Z');
    xml=blankTag(xml,'dcterms:modified','2000-01-01T00:00:00Z');
    if(xml!==before) removed.push('作成者・更新者・日時(core.xml)');
  } else if(name==='docProps/app.xml'){
    xml=blankTag(xml,'Company');
    xml=blankTag(xml,'Manager');
    xml=blankTag(xml,'TotalTime','0');
    xml=xml.replace(/(<Template>)[\s\S]*?(<\/Template>)/, function(_, a, b, _o){
      var m=before.match(/<Template>([\s\S]*?)<\/Template>/);
      var base=m ? m[1].split(/[\\/]/).pop() : '';
      return a+base+b;
    });
    if(xml!==before) removed.push('会社名・テンプレートパス(app.xml)');
  } else if(name==='word/people.xml'){
    xml=xml.replace(/w15:author="[^"]*"/g,'w15:author="Author"');
    if(xml!==before) removed.push('変更履歴の著者名(people.xml)');
  } else if(name==='word/document.xml' || /^word\/comments\d*\.xml$/.test(name)){
    xml=xml.replace(/w:author="[^"]*"/g,'w:author="Author"')
           .replace(/w:initials="[^"]*"/g,'w:initials="A"');
    if(xml!==before) removed.push('コメント・変更履歴の著者名('+name.split('/').pop()+')');
  } else if(name==='meta.xml'){ /* ODF */
    xml=blankTag(xml,'dc:creator');
    xml=blankTag(xml,'meta:initial-creator');
    xml=blankTag(xml,'meta:generator');
    xml=blankTag(xml,'meta:creation-date','2000-01-01T00:00:00Z');
    xml=blankTag(xml,'dc:date','2000-01-01T00:00:00Z');
    if(xml!==before) removed.push('作成者・日時(meta.xml)');
  }
  return xml;
}

var OFFICE_XML_TARGETS=/^(docProps\/(core|app)\.xml|word\/(people|document)\.xml|word\/comments\d*\.xml|meta\.xml)$/;

function cleanOfficeZip(bytes){
  var removed=[];
  var zi=Engine.zip.listEntries(bytes);
  var entries=zi.entries;
  if(!entries.length) return Promise.reject(new Error('ZIP構造を読み取れませんでした'));
  if(entries.some(function(e){ return e.encrypted; })) return Promise.reject(new Error('暗号化されたエントリがあるため再構築できません'));
  if(zi.comment) removed.push('ZIPコメント');

  /* 全エントリを読み出し → 対象XMLを変換 → ZIPを丸ごと再構築 (内部タイムスタンプも消える) */
  return Promise.all(entries.map(function(e){
    return Engine.zip.readEntry(bytes,e).then(function(d){
      if(d==null) throw new Error('エントリの展開に失敗: '+e.name);
      if(OFFICE_XML_TARGETS.test(e.name)){
        var xml=new TextDecoder().decode(d);
        var t=transformOfficeXml(e.name, xml, removed);
        if(t!==xml) d=new TextEncoder().encode(t);
      }
      return { name:e.name, data:d };
    });
  })).then(function(items){
    return buildZip(items).then(function(zipBytes){
      removed.push('ZIP内部のタイムスタンプ');
      return { bytes:zipBytes, removed:dedupe(removed) };
    });
  });
}

function buildZip(items){
  /* 各エントリをdeflate圧縮(縮まない場合はSTORE)、日時は1980-01-01に固定 */
  return Promise.all(items.map(function(it){
    return deflateRaw(it.data).then(function(comp){
      var useDeflate = comp && comp.length<it.data.length;
      return {
        name:it.name, data:it.data,
        comp:useDeflate?comp:it.data,
        method:useDeflate?8:0,
        crc:crc32(it.data),
      };
    });
  })).then(function(list){
    var locals=[], centrals=[], offset=0;
    list.forEach(function(f){
      var nameB=new TextEncoder().encode(f.name);
      var local=new Uint8Array(30+nameB.length);
      var dv=new DataView(local.buffer);
      dv.setUint32(0,0x04034B50,true);
      dv.setUint16(4,20,true);          /* version needed */
      dv.setUint16(6,0x0800,true);      /* UTF-8フラグ */
      dv.setUint16(8,f.method,true);
      dv.setUint16(10,0,true); dv.setUint16(12,0x0021,true); /* time=0, date=1980-01-01 */
      dv.setUint32(14,f.crc,true);
      dv.setUint32(18,f.comp.length,true);
      dv.setUint32(22,f.data.length,true);
      dv.setUint16(26,nameB.length,true);
      dv.setUint16(28,0,true);
      local.set(nameB,30);
      locals.push(local, f.comp);

      var central=new Uint8Array(46+nameB.length);
      var cv=new DataView(central.buffer);
      cv.setUint32(0,0x02014B50,true);
      cv.setUint16(4,20,true); cv.setUint16(6,20,true);
      cv.setUint16(8,0x0800,true);
      cv.setUint16(10,f.method,true);
      cv.setUint16(12,0,true); cv.setUint16(14,0x0021,true);
      cv.setUint32(16,f.crc,true);
      cv.setUint32(20,f.comp.length,true);
      cv.setUint32(24,f.data.length,true);
      cv.setUint16(28,nameB.length,true);
      cv.setUint32(42,offset,true);
      central.set(nameB,46);
      centrals.push(central);
      offset+=local.length+f.comp.length;
    });
    var cd=concat(centrals);
    var eocd=new Uint8Array(22);
    var ev=new DataView(eocd.buffer);
    ev.setUint32(0,0x06054B50,true);
    ev.setUint16(8,list.length,true);
    ev.setUint16(10,list.length,true);
    ev.setUint32(12,cd.length,true);
    ev.setUint32(16,offset,true);
    return concat([concat(locals), cd, eocd]);
  });
}

/* ---------- ディスパッチャー ---------- */
function dedupe(arr){
  var seen={}, out=[];
  arr.forEach(function(v){ if(!seen[v]){ seen[v]=1; out.push(v); } });
  return out;
}
var OFFICE_EXTS=/^(docx|xlsx|pptx|docm|xlsm|pptm|odt|ods|odp)$/;
var UNSUPPORTED_REASON={
  pdf:'PDFは内部のオフセット参照が壊れやすいため自動除去に対応していません。「印刷→PDF」での再作成を推奨します。',
  mp4:'MP4/MOVはオフセットテーブル(stco)の修正が必要なため自動除去に対応していません。再エンコード(例: ffmpeg -map_metadata -1)を推奨します。',
};

function supports(name, bytes){
  var magic=Engine.detectMagic(bytes);
  var kind=magic?magic.id:null;
  var ext=(name.lastIndexOf('.')>0)?name.slice(name.lastIndexOf('.')+1).toLowerCase():'';
  if(kind==='jpeg'||kind==='png'||kind==='webp'||kind==='mp3') return {ok:true, kind:kind};
  if(kind==='zip' && OFFICE_EXTS.test(ext)) return {ok:true, kind:'office'};
  if(UNSUPPORTED_REASON[kind]) return {ok:false, reason:UNSUPPORTED_REASON[kind]};
  return {ok:false, reason:'この形式のメタデータ除去には対応していません。'};
}

function clean(bytes, name){
  var s=supports(name, bytes);
  if(!s.ok) return Promise.reject(new Error(s.reason));
  switch(s.kind){
    case 'jpeg': return cleanJPEG(bytes);
    case 'png': return cleanPNG(bytes);
    case 'webp': return cleanWebP(bytes);
    case 'mp3': return cleanMP3(bytes);
    case 'office': return cleanOfficeZip(bytes);
  }
  return Promise.reject(new Error('未対応'));
}

var api={ supports:supports, clean:clean, crc32:crc32 };
if(typeof module!=='undefined' && module.exports) module.exports=api;
else global.MetaScanCleaner=api;

})(typeof window!=='undefined'?window:globalThis);
