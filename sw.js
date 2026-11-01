// Kharcha app shell: open instantly from cache, then refresh the cached copy from the network (bypassing the browser cache).
const C="kharcha-v6",F=["./","index.html","manifest.webmanifest","icon-192.png","icon-512.png"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(F.map(u=>new Request(u,{cache:"reload"})))).then(()=>self.skipWaiting()));});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==C).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));});
self.addEventListener("fetch",e=>{ const u=new URL(e.request.url); if(e.request.method!=="GET"||u.origin!==location.origin||u.pathname.endsWith("version.json")) return;
  const key=u.pathname.endsWith("/")?"./":e.request;
  e.respondWith(caches.match(key,{ignoreSearch:true}).then(m=>{
    const net=fetch(u.href,{cache:"no-cache"}).then(r=>{ if(r.ok){ const cp=r.clone(); caches.open(C).then(c=>c.put(key,cp)); } return r; }).catch(()=>m||caches.match("index.html"));
    return m||net; })); });
