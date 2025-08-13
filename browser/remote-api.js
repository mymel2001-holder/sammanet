// runs in main process via ipc handlers
const { ipcMain } = require('electron');
const http = require('http');

const NODE = process.env.SAMMAN_NODE || "http://127.0.0.1:7742";

function jsonPost(path, obj) {
  return new Promise((res, rej) => {
    const data = JSON.stringify(obj);
    const url = new URL(NODE + path);
    const opts = { method: 'POST', headers: {'Content-Type':'application/json','Content-Length':Buffer.byteLength(data)} };
    const req = http.request(url, opts, r => {
      let body='';
      r.on('data', c=>body+=c.toString());
      r.on('end', ()=>res({status: r.statusCode, body}));
    });
    req.on('error', e=>rej(e));
    req.write(data);
    req.end();
  });
}
function postRaw(path, body) {
  return new Promise((res, rej) => {
    const url = new URL(NODE + path);
    const opts = { method: 'POST', headers: {'Content-Type':'text/plain','Content-Length':Buffer.byteLength(body)} };
    const req = http.request(url, opts, r => {
      let b=''; r.on('data',c=>b+=c); r.on('end',()=>res({status:r.statusCode, body:b}));
    });
    req.on('error',e=>rej(e));
    req.write(body);
    req.end();
  });
}
function get(path) {
  return new Promise((res, rej) => {
    const url = new URL(NODE + path);
    http.get(url, r => {
      let b=''; r.on('data',c=>b+=c); r.on('end',()=>res({status:r.statusCode, body:b}));
    }).on('error', e=>rej(e));
  });
}

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
