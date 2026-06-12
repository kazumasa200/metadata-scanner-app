/* =========================================================
 * 最小LZMA1/LZMA2デコーダー (7zのヘッダー/内包ファイル展開用)
 * 公開API:
 *   decodeLZMA(props, data, outSize)  -> Uint8Array | null  (生LZMA1)
 *   decodeLZMA2(data, outSize)        -> Uint8Array | null  (LZMA2チャンク列)
 * 参考: LZMA SDK (public domain) のアルゴリズム
 * ========================================================= */
(function(global){
'use strict';

var kNumBitModelTotalBits = 11;
var kBitModelTotal = 1 << kNumBitModelTotalBits;
var kNumMoveBits = 5;
var kTopValue = 1 << 24;

function newProb(n){
  var a = new Uint16Array(n);
  for(var i=0;i<n;i++) a[i] = kBitModelTotal >>> 1;
  return a;
}

/* ---------- 確率モデル (チャンクをまたいで保持できるようオブジェクト化) ---------- */
function createModel(propsByte){
  var d = propsByte & 0xFF;
  if(d >= 9*5*5) return null;
  var m = {};
  m.lc = d % 9; d = (d/9)|0;
  m.lp = d % 5; d = (d/5)|0;
  m.pb = d;
  resetModelState(m);
  return m;
}
function resetModelState(m){
  m.state = 0;
  m.rep0 = 0; m.rep1 = 0; m.rep2 = 0; m.rep3 = 0;
  m.IsMatch = newProb(12 << 4);
  m.IsRep = newProb(12);
  m.IsRepG0 = newProb(12);
  m.IsRepG1 = newProb(12);
  m.IsRepG2 = newProb(12);
  m.IsRep0Long = newProb(12 << 4);
  m.PosSlot = newProb(4 * 64);
  m.SpecPos = newProb(115);
  m.Align = newProb(16);
  m.LenChoice = newProb(2);
  m.LenLow = newProb(16 * 8);
  m.LenMid = newProb(16 * 8);
  m.LenHigh = newProb(256);
  m.RepLenChoice = newProb(2);
  m.RepLenLow = newProb(16 * 8);
  m.RepLenMid = newProb(16 * 8);
  m.RepLenHigh = newProb(256);
  m.Literal = newProb(0x300 << (m.lc + m.lp));
}

/* ---------- 1チャンク分のLZMAデータを out[outStart..outLimit) に展開 ----------
 * m         : createModel()のモデル (state/reps/probsは呼び出し間で保持される)
 * dictStart : 辞書リセット位置 (posState・リテラル位置・距離の基準)
 * 戻り値    : 展開済み末尾位置 / -1 = エラー
 */
function decodeChunk(m, data, inPos, inEnd, out, outStart, outLimit, dictStart){
  var posStateMask = (1 << m.pb) - 1;
  var literalPosMask = (1 << m.lp) - 1;
  var lc = m.lc;

  /* range decoder init (各チャンク先頭の5バイト) */
  if(inPos + 5 > inEnd) return -1;
  if(data[inPos] !== 0) return -1;
  inPos++;
  var code = 0, range = 0xFFFFFFFF;
  for(var i=0;i<4;i++){ code = ((code << 8) | (data[inPos++]&0xFF)) >>> 0; }

  function normalize(){
    if(range < kTopValue){
      range = (range << 8) >>> 0;
      code = ((code << 8) | (data[inPos++]&0xFF)) >>> 0;
    }
  }
  function decodeBit(probs, idx){
    var prob = probs[idx];
    var bound = (range >>> kNumBitModelTotalBits) * prob;
    var symbol;
    if((code >>> 0) < (bound >>> 0)){
      range = bound >>> 0;
      probs[idx] = prob + ((kBitModelTotal - prob) >>> kNumMoveBits);
      symbol = 0;
    } else {
      range = (range - bound) >>> 0;
      code = (code - bound) >>> 0;
      probs[idx] = prob - (prob >>> kNumMoveBits);
      symbol = 1;
    }
    normalize();
    return symbol;
  }
  function decodeDirectBits(numBits){
    var res = 0;
    do{
      range = (range >>> 1) >>> 0;
      code = (code - range) >>> 0;
      var t = (0 - (code >>> 31)) >>> 0;
      code = (code + (range & t)) >>> 0;
      normalize();
      res = ((res << 1) + t + 1) >>> 0;
    }while(--numBits);
    return res >>> 0;
  }
  function bitTreeDecode(probs, off, numBits){
    var v = 1;
    for(var i=0;i<numBits;i++) v = (v << 1) + decodeBit(probs, off+v);
    return v - (1 << numBits);
  }
  function bitTreeReverseDecode(probs, off, numBits){
    var v = 1, symbol = 0;
    for(var i=0;i<numBits;i++){
      var b = decodeBit(probs, off+v);
      v = (v << 1) + b;
      symbol |= b << i;
    }
    return symbol;
  }
  function decodeLen(choice, low, mid, high, posState){
    if(decodeBit(choice, 0) === 0) return bitTreeDecode(low, posState << 3, 3);
    if(decodeBit(choice, 1) === 0) return 8 + bitTreeDecode(mid, posState << 3, 3);
    return 16 + bitTreeDecode(high, 0, 8);
  }

  var outPos = outStart;
  while(outPos < outLimit){
    if(inPos > inEnd) return -1;
    var relPos = outPos - dictStart;
    var posState = relPos & posStateMask;
    if(decodeBit(m.IsMatch, (m.state << 4) + posState) === 0){
      /* literal */
      var prevByte = outPos > dictStart ? out[outPos-1] : 0;
      var litState = ((relPos & literalPosMask) << lc) + (prevByte >>> (8 - lc));
      var probsOff = 0x300 * litState;
      var symbol = 1;
      if(m.state >= 7){
        var matchByte = out[outPos - m.rep0 - 1];
        do{
          var matchBit = (matchByte >>> 7) & 1;
          matchByte = (matchByte << 1) & 0xFF;
          var bit = decodeBit(m.Literal, probsOff + ((1 + matchBit) << 8) + symbol);
          symbol = (symbol << 1) | bit;
          if(matchBit !== bit) break;
        }while(symbol < 0x100);
      }
      while(symbol < 0x100) symbol = (symbol << 1) | decodeBit(m.Literal, probsOff + symbol);
      out[outPos++] = symbol & 0xFF;
      m.state = m.state < 4 ? 0 : m.state < 10 ? m.state - 3 : m.state - 6;
      continue;
    }
    /* match */
    var len;
    if(decodeBit(m.IsRep, m.state) !== 0){
      if(decodeBit(m.IsRepG0, m.state) === 0){
        if(decodeBit(m.IsRep0Long, (m.state << 4) + posState) === 0){
          m.state = m.state < 7 ? 9 : 11;
          out[outPos] = out[outPos - m.rep0 - 1];
          outPos++;
          continue;
        }
      } else {
        var dist;
        if(decodeBit(m.IsRepG1, m.state) === 0){ dist = m.rep1; }
        else {
          if(decodeBit(m.IsRepG2, m.state) === 0){ dist = m.rep2; }
          else { dist = m.rep3; m.rep3 = m.rep2; }
          m.rep2 = m.rep1;
        }
        m.rep1 = m.rep0; m.rep0 = dist;
      }
      len = decodeLen(m.RepLenChoice, m.RepLenLow, m.RepLenMid, m.RepLenHigh, posState) + 2;
      m.state = m.state < 7 ? 8 : 11;
    } else {
      m.rep3 = m.rep2; m.rep2 = m.rep1; m.rep1 = m.rep0;
      len = decodeLen(m.LenChoice, m.LenLow, m.LenMid, m.LenHigh, posState) + 2;
      m.state = m.state < 7 ? 7 : 10;
      var lenToPosState = len < 6 ? len - 2 : 3;
      var posSlot = bitTreeDecode(m.PosSlot, lenToPosState << 6, 6);
      if(posSlot < 4){
        m.rep0 = posSlot;
      } else {
        var numDirect = (posSlot >> 1) - 1;
        m.rep0 = (2 | (posSlot & 1)) << numDirect;
        if(posSlot < 14){
          m.rep0 += bitTreeReverseDecode(m.SpecPos, m.rep0 - posSlot - 1, numDirect);
        } else {
          m.rep0 += decodeDirectBits(numDirect - 4) << 4;
          m.rep0 += bitTreeReverseDecode(m.Align, 0, 4);
        }
        m.rep0 = m.rep0 >>> 0;
      }
      if(m.rep0 === 0xFFFFFFFF) break; /* end marker */
    }
    if(m.rep0 > outPos - dictStart - 1) return -1; /* 不正な距離 */
    for(var c=0;c<len && outPos<outLimit;c++){
      out[outPos] = out[outPos - m.rep0 - 1];
      outPos++;
    }
  }
  return outPos;
}

/* ---------- 生LZMA1 (7zヘッダー等: propsは別添、サイズ既知) ---------- */
function decodeLZMA(props, data, outSize){
  try{
    var m = createModel(props[0]);
    if(!m) return null;
    var out = new Uint8Array(outSize);
    var end = decodeChunk(m, data, 0, data.length, out, 0, outSize, 0);
    return end < 0 ? null : out;
  }catch(e){ return null; }
}

/* ---------- LZMA2 (チャンク列) ---------- */
function decodeLZMA2(data, outSize){
  try{
    var out = new Uint8Array(outSize);
    var m = null;
    var pos = 0, outPos = 0, dictStart = 0;
    var guard = 0;
    while(pos < data.length && outPos < outSize && guard++ < 100000){
      var ctrl = data[pos++];
      if(ctrl === 0) break; /* 終端 */
      if(ctrl === 1 || ctrl === 2){
        /* 非圧縮チャンク (1=辞書リセット) */
        if(pos+2 > data.length) return null;
        var usize = ((data[pos]<<8) | data[pos+1]) + 1; pos += 2;
        if(pos+usize > data.length || outPos+usize > outSize) return null;
        if(ctrl === 1) dictStart = outPos;
        out.set(data.subarray(pos, pos+usize), outPos);
        outPos += usize; pos += usize;
        if(m) resetModelState(m); /* 非圧縮チャンクの後はstateリセット */
      } else if(ctrl >= 0x80){
        if(pos+4 > data.length) return null;
        var unp = (((ctrl & 0x1F) << 16) | (data[pos]<<8) | data[pos+1]) + 1; pos += 2;
        var pack = ((data[pos]<<8) | data[pos+1]) + 1; pos += 2;
        var resetMode = (ctrl >>> 5) & 3;
        if(resetMode >= 2){
          if(pos >= data.length) return null;
          var propByte = data[pos++];
          m = createModel(propByte);
          if(!m) return null;
        }
        if(!m) return null; /* propsなしで圧縮チャンクは不正 */
        if(resetMode === 1) resetModelState(m);
        if(resetMode === 3) dictStart = outPos;
        if(pos+pack > data.length || outPos+unp > outSize) return null;
        var end = decodeChunk(m, data, pos, pos+pack, out, outPos, outPos+unp, dictStart);
        if(end < 0) return null;
        outPos = end;
        pos += pack;
      } else {
        return null; /* 不正な制御バイト */
      }
    }
    return out;
  }catch(e){ return null; }
}

var api = { decodeLZMA: decodeLZMA, decodeLZMA2: decodeLZMA2 };
if(typeof module!=='undefined' && module.exports) module.exports = api;
else global.MetaScanLZMA = api;

})(typeof window!=='undefined'?window:globalThis);
