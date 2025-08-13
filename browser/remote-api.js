// runs in main process via ipc handlers
const { ipcMain } = require('electron');
const http = require('http');

const SAMMAN_NODES = (process.env.SAMMAN_NODES || process.env.SAMMAN_NODE || "http://127.0.0.1:7742")
  .split(",").map(n => n.trim()).filter(n => n.length > 0);

function jsonPost(path, obj) {
  return new Promise((res, rej) => {
    const data = JSON.stringify(obj);
    let i = 0;
    const tryNext = () => {
      if (i >= SAMMAN_NODES.length) return rej(new Error("all nodes failed"));
      const url = new URL(SAMMAN_NODES[i] + path);
      const opts = { method: 'POST', headers: {'Content-Type':'application/json','Content-Length':Buffer.byteLength(data)} };
      const req = http.request(url, opts, r => {
        let body='';
        r.on('data', c=>body+=c.toString());
        r.on('end', ()=>res({status: r.statusCode, body}));
      });
      req.on('error', e=>{ i++; tryNext(); });
      req.write(data);
      req.end();
    };
    tryNext();
  });
}
function postRaw(path, body) {
  return new Promise((res, rej) => {
    let i = 0;
    const tryNext = () => {
      if (i >= SAMMAN_NODES.length) return rej(new Error("all nodes failed"));
      const url = new URL(SAMMAN_NODES[i] + path);
      const opts = { method: 'POST', headers: {'Content-Type':'text/plain','Content-Length':Buffer.byteLength(body)} };
      const req = http.request(url, opts, r => {
        let b=''; r.on('data',c=>b+=c); r.on('end',()=>res({status:r.statusCode, body:b}));
      });
      req.on('error',e=>{ i++; tryNext(); });
      req.write(body);
      req.end();
    };
    tryNext();
  });
}
let i = 0;
const tryNext = () => {
  if (i >= SAMMAN_NODES.length) return rej(new Error("all nodes failed"));
  const url = new URL(SAMMAN_NODES[i] + path);
  http.get(url, r => {
    let b='';
    r.on('data',c=>b+=c); r.on('end',()=>res({status:r.statusCode, body:b}));
  }).on('error', e=>{ i++; tryNext(); });
};
tryNext();

ipcMain.handle('upload', async (ev, domain, content) => {
  return await postRaw('/upload?cid=', content).catch(e=>({status:0,body:String(e)}));
});
ipcMain.handle('register', async (ev, tx) => {
  return await jsonPost('/register', tx).catch(e=>({status:0,body:String(e)}));
});
ipcMain.handle('resolve', async (ev, domain) => {
  return await get('/resolve?domain=' + encodeURIComponent(domain)).catch(e=>({status:0,body:String(e)}));
});
ipcMain.handle('fetchCid', async (ev, cid) => {
  return await get('/fetch?cid=' + encodeURIComponent(cid)).catch(e=>({status:0,body:String(e)}));
});

// Added minimal protocol publish helper to forward to node /protocol/publish
async function publishProtocol(pm) {
  // delegate to node-side HTTP endpoint using existing jsonPost helper
  return await jsonPost('/protocol/publish', pm);
}

// Added minimal protocol publish helper to forward to node /protocol/publish
async function publishProtocol(pm) {
  // delegate to node-side HTTP endpoint using existing jsonPost helper
  return await jsonPost('/protocol/publish', pm);
}
