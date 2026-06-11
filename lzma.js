/* =========================================================
 * 最小LZMA1デコーダー (7zの圧縮ヘッダー/内包ファイル展開用)
 * 出力サイズが既知の生LZMAストリームを展開する。
 * 公開API: decodeLZMA(props, data, outSize) -> Uint8Array | null
 *   props : 1バイト以上 (先頭バイト = (pb*5+lp)*9+lc)
 *   data  : LZMA範囲符号化データ (先頭5バイトの初期化バイト含む)
 * 参考: LZMA SDK (public domain) のアルゴリズム
 * ========================================================= */
(function(global){
'use strict';

var kNumBitModelTotalBits = 11;
var kBitModelTotal = 1 << kNumBitModelTotalBits;
var kNumMoveBits = 5;
var kTopValue = 1 << 24;

function decodeLZMA(props, data, outSize){
  try{
    return run(props, data, outSize);
  }catch(e){ return null; }
}

function run(props, data, outSize){
  var d = props[0] & 0xFF;
  if(d >= 9*5*5) return null;
  var lc = d % 9; d = (d/9)|0;
  var lp = d % 5; d = (d/5)|0;
  var pb = d;

  /* --- range decoder state --- */
  var inPos = 0;
  var code = 0, range = 0xFFFFFFFF;
  /* 先頭バイトは0、続く4バイトがcode */
  inPos++; /* skip first byte */
  for(var i=0;i<4;i++){ code = ((code<<8) | (data[inPos++]&0xFF)) >>> 0; }

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
    var m = 1;
    for(var i=0;i<numBits;i++) m = (m << 1) + decodeBit(probs, off+m);
    return m - (1 << numBits);
  }
  function bitTreeReverseDecode(probs, off, numBits){
    var m = 1, symbol = 0;
    for(var i=0;i<numBits;i++){
      var b = decodeBit(probs, off+m);
      m = (m << 1) + b;
      symbol |= b << i;
    }
    return symbol;
  }

  /* --- probability models --- */
  var numStates = 12;
  var posStateMask = (1 << pb) - 1;
  var literalPosMask = (1 << lp) - 1;

  var IsMatch = newProb(numStates << 4);
  var IsRep = newProb(numStates);
  var IsRepG0 = newProb(numStates);
  var IsRepG1 = newProb(numStates);
  var IsRepG2 = newProb(numStates);
  var IsRep0Long = newProb(numStates << 4);
  var PosSlot = newProb(4 * 64);
  var SpecPos = newProb(115);
  var Align = newProb(16);

  var LenChoice = newProb(2);
  var LenLow = newProb(16 * 8);
  var LenMid = newProb(16 * 8);
  var LenHigh = newProb(256);
  var RepLenChoice = newProb(2);
  var RepLenLow = newProb(16 * 8);
  var RepLenMid = newProb(16 * 8);
  var RepLenHigh = newProb(256);

  var numLiteralStates = 0x300 << (lc + lp);
  var Literal = newProb(numLiteralStates);

  function newProb(n){
    var a = new Uint16Array(n);
    for(var i=0;i<n;i++) a[i] = kBitModelTotal >>> 1;
    return a;
  }

  function decodeLen(choice, low, mid, high, posState){
    if(decodeBit(choice, 0) === 0) return bitTreeDecode(low, posState << 3, 3);
    if(decodeBit(choice, 1) === 0) return 8 + bitTreeDecode(mid, posState << 3, 3);
    return 16 + bitTreeDecode(high, 0, 8);
  }

  /* --- main decode loop --- */
  var out = new Uint8Array(outSize);
  var outPos = 0;
  var state = 0;
  var rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0;

  while(outPos < outSize){
    var posState = outPos & posStateMask;
    if(decodeBit(IsMatch, (state << 4) + posState) === 0){
      /* literal */
      var prevByte = outPos > 0 ? out[outPos-1] : 0;
      var litState = ((outPos & literalPosMask) << lc) + (prevByte >>> (8 - lc));
      var probsOff = 0x300 * litState;
      var symbol = 1;
      if(state >= 7){
        var matchByte = out[outPos - rep0 - 1];
        do{
          var matchBit = (matchByte >>> 7) & 1;
          matchByte = (matchByte << 1) & 0xFF;
          var bit = decodeBit(Literal, probsOff + ((1 + matchBit) << 8) + symbol);
          symbol = (symbol << 1) | bit;
          if(matchBit !== bit) break;
        }while(symbol < 0x100);
      }
      while(symbol < 0x100) symbol = (symbol << 1) | decodeBit(Literal, probsOff + symbol);
      out[outPos++] = symbol & 0xFF;
      state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
      continue;
    }
    /* match */
    var len;
    if(decodeBit(IsRep, state) !== 0){
      /* rep match */
      if(decodeBit(IsRepG0, state) === 0){
        if(decodeBit(IsRep0Long, (state << 4) + posState) === 0){
          state = state < 7 ? 9 : 11;
          out[outPos] = out[outPos - rep0 - 1];
          outPos++;
          continue;
        }
      } else {
        var dist;
        if(decodeBit(IsRepG1, state) === 0){ dist = rep1; }
        else {
          if(decodeBit(IsRepG2, state) === 0){ dist = rep2; }
          else { dist = rep3; rep3 = rep2; }
          rep2 = rep1;
        }
        rep1 = rep0; rep0 = dist;
      }
      len = decodeLen(RepLenChoice, RepLenLow, RepLenMid, RepLenHigh, posState) + 2;
      state = state < 7 ? 8 : 11;
    } else {
      /* new match */
      rep3 = rep2; rep2 = rep1; rep1 = rep0;
      len = decodeLen(LenChoice, LenLow, LenMid, LenHigh, posState) + 2;
      state = state < 7 ? 7 : 10;
      var lenToPosState = len < 6 ? len - 2 : 3;
      var posSlot = bitTreeDecode(PosSlot, lenToPosState << 6, 6);
      if(posSlot < 4){
        rep0 = posSlot;
      } else {
        var numDirect = (posSlot >> 1) - 1;
        rep0 = (2 | (posSlot & 1)) << numDirect;
        if(posSlot < 14){
          rep0 += bitTreeReverseDecode(SpecPos, rep0 - posSlot - 1, numDirect);
        } else {
          rep0 += decodeDirectBits(numDirect - 4) << 4;
          rep0 += bitTreeReverseDecode(Align, 0, 4);
        }
        rep0 = rep0 >>> 0;
      }
      if(rep0 === 0xFFFFFFFF) break; /* end marker */
    }
    /* copy match */
    if(rep0 >= outPos) return null; /* 不正な距離 */
    for(var c=0;c<len && outPos<outSize;c++){
      out[outPos] = out[outPos - rep0 - 1];
      outPos++;
    }
  }
  return out;
}

var api = { decodeLZMA: decodeLZMA };
if(typeof module!=='undefined' && module.exports) module.exports = api;
else global.MetaScanLZMA = api;

})(typeof window!=='undefined'?window:globalThis);
