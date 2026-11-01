const C="kharcha-v2",F=["./","index.html","manifest.webmanifest","icon-192.png","icon-512.png"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(F)).then(()=>self.skipWaiting()));});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==C).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));});
self.addEventListener("fetch",e=>{ const u=new URL(e.request.url); if(e.request.method!=="GET"||u.origin!==location.origin) return;
  e.respondWith(caches.match(e.request,{ignoreSearch:true}).then(m=>{ const net=fetch(e.request).then(r=>{ const cp=r.clone(); caches.open(C).then(c=>c.put(e.request,cp)); return r; }).catch(()=>m||caches.match("index.html")); return m||net; })); });
