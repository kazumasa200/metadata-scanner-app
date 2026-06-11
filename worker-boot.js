/* Web Worker側エントリー: engine.js と連結してBlobワーカーとして起動される */
self.onmessage = function(ev){
  var d = ev.data;
  try{
    MetaScanEngine.analyzeBuffer(new Uint8Array(d.buffer), d.info).then(function(r){
      self.postMessage({ id:d.id, ok:true, metadata:r.metadata, findings:r.findings, thumbnail:r.thumbnail||null });
    }).catch(function(e){
      self.postMessage({ id:d.id, ok:false, error:String(e && e.message || e) });
    });
  }catch(e){
    self.postMessage({ id:d.id, ok:false, error:String(e && e.message || e) });
  }
};
