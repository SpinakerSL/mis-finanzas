const C='mis-finanzas-1.8.1',A=['./','./index.html','./styles.css','./extras.css?v=1.8.1','./app.js?v=1.8.1','./manifest.webmanifest','./icon-192.png','./icon-512.png','./apple-touch-icon.png'];
/* Instalación tolerante: si un archivo falla, el resto igual se cachea */
self.addEventListener('install',e=>e.waitUntil(caches.open(C).then(c=>Promise.all(A.map(u=>c.add(u).catch(()=>{})))).then(()=>self.skipWaiting())));
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',e=>{if(e.request.method!=='GET')return;e.respondWith(fetch(e.request).then(r=>{if(r.ok){const q=r.clone();caches.open(C).then(c=>c.put(e.request,q)).catch(()=>{})}return r}).catch(()=>caches.match(e.request).then(r=>r||caches.match('./index.html'))))});
