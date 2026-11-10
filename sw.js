// Kharcha app shell (2.6).
// · Opens instantly from the saved copy, then refreshes that copy from the network in the background.
// · Every downloaded copy of the app page is checked (size + a marker) before it is saved, so an empty or
//   cut-off file from the server can never replace a working app: the last good copy keeps being served.
const C="kharcha-v16", F=["./","index.html","manifest.webmanifest","icon-192.png","icon-512.png"];
const MIN={"./":40000,"index.html":40000}, MARK="APP_VERSION";
const keyOf=u=>u.pathname.endsWith("/")?"./":u.pathname.replace(/^.*\//,"");
/* resolves to the Response only if it looks like a real copy of that file */
function good(key,r){ if(!r||!r.ok) return Promise.resolve(null); if(!MIN[key]) return Promise.resolve(r);
  return r.clone().text().then(t=>t.length>=MIN[key]&&t.indexOf(MARK)>=0?r:null,()=>null); }
self.addEventListener("install",e=>{ e.waitUntil(caches.open(C).then(c=>Promise.all(F.map(k=>fetch(new Request(k,{cache:"reload"})).then(r=>good(k,r)).then(r=>r?c.put(k,r):null).catch(()=>null)))).then(()=>self.skipWaiting())); });
/* older Kharcha caches are removed only once this one holds a good copy of the app page */
self.addEventListener("activate",e=>{ e.waitUntil(caches.open(C).then(c=>c.match("index.html")).then(ok=>ok?caches.keys().then(ks=>Promise.all(ks.filter(k=>k.startsWith("kharcha-")&&k!==C).map(k=>caches.delete(k)))):null).then(()=>self.clients.claim())); });
self.addEventListener("fetch",e=>{ const u=new URL(e.request.url);
  if(e.request.method!=="GET"||u.origin!==location.origin||u.pathname.endsWith("version.json")||u.pathname.endsWith("sw.js")) return;
  const key=keyOf(u); if(F.indexOf(key)<0) return;
  const saved=()=>caches.match(key,{ignoreSearch:true}).then(m=>m||(key==="./"?caches.match("index.html",{ignoreSearch:true}):null));
  e.respondWith(saved().then(m=>{
    const net=fetch(u.href,{cache:"no-cache"}).then(r=>good(key,r)).then(r=>{ if(r){ const cp=r.clone(); caches.open(C).then(c=>c.put(key,cp)); } return r; }).catch(()=>null);
    if(m){ e.waitUntil(net); return m; }
    return net.then(r=>r||fetch(u.href)); })); });
