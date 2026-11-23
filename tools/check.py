#!/usr/bin/env python3
"""Kharcha release check. Nothing may be published unless this passes.

  python3 tools/check.py          check only (exit 1 on any failure)
  python3 tools/check.py --fix    also refresh the inline-script hashes in the Content-Security-Policy

Checks: files present and not truncated (sw.js was published empty in 2.2–2.4), versions consistent, every script
parses, CSP hashes match the inline scripts, and the app really starts in a headless browser with no errors.
"""
import base64, hashlib, http.server, json, os, re, socketserver, subprocess, sys, tempfile, threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAIL = []
def ok(c, m):
    print(("PASS " if c else "FAIL ") + m)
    if not c: FAIL.append(m)
def rd(p): return open(os.path.join(ROOT, p), encoding="utf-8").read()

# 1. files present and not truncated
MIN = {"index.html": 80000, "sw.js": 1200, "manifest.webmanifest": 100, "version.json": 20, "icon-192.png": 1000, "icon-512.png": 1000}
for f, n in MIN.items():
    sz = os.path.getsize(os.path.join(ROOT, f)) if os.path.exists(os.path.join(ROOT, f)) else 0
    ok(sz >= n, f"{f} present and not truncated ({sz} bytes, min {n})")
idx, sw = rd("index.html"), rd("sw.js")
ok(idx.rstrip().endswith("</html>"), "index.html is complete (ends with </html>)")
for m in ['id="gate"', 'id="upd"', 'navigator.serviceWorker.register("sw.js")']:
    ok(m in idx, f"index.html contains {m}")

# 2. versions agree
v = json.loads(rd("version.json"))["v"]
av = re.search(r'const APP_VERSION="([^"]+)"', idx)
ok(av and av.group(1) == v, f"APP_VERSION matches version.json ({v})")
ok(re.search(r'const C="kharcha-v\d+"', sw) is not None, "sw.js has a cache name")
ok('"APP_VERSION"' in sw and "skipWaiting" in sw and '"fetch"' in sw, "sw.js checks downloaded copies and handles requests")

# 3. JavaScript parses (the worker and every inline script)
inl = re.findall(r"<script>(.*?)</script>", idx, re.S)
def parses(src, name):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as t: t.write(src)
    r = subprocess.run(["node", "-e", f"new (require('vm').Script)(require('fs').readFileSync({json.dumps(t.name)},'utf8'))"], capture_output=True, text=True)
    os.unlink(t.name)
    ok(r.returncode == 0, f"{name} parses" + ("" if r.returncode == 0 else ": " + (r.stderr.strip().splitlines() or ["?"])[-1]))
parses(sw, "sw.js")
for i, s in enumerate(inl): parses(s, f"inline script {i + 1}")

# 4. CSP hashes for the inline scripts
hashes = ["'sha256-" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode() + "'" for s in inl]
m = re.search(r"script-src 'self' (.*?) https://accounts", idx)
if "--fix" in sys.argv and m:
    idx = idx.replace(m.group(0), "script-src 'self' " + " ".join(hashes) + " https://accounts")
    with open(os.path.join(ROOT, "index.html"), "w", encoding="utf-8") as fh: fh.write(idx)
    m = re.search(r"script-src 'self' (.*?) https://accounts", idx)
ok(m is not None and set(m.group(1).split()) == set(hashes), f"CSP allows exactly the {len(inl)} inline scripts")

# 5. it really starts in a headless browser (no backend: the sign-in gate must appear, with no errors)
class Q(http.server.SimpleHTTPRequestHandler):
    def __init__(s, *a, **k): super().__init__(*a, directory=ROOT, **k)
    def log_message(s, *a): pass
try:
    from playwright.sync_api import sync_playwright
except Exception:
    sync_playwright = None
if sync_playwright is None:
    ok(False, "playwright is installed (needed for the start-up check)")
else:
    srv = socketserver.TCPServer(("127.0.0.1", 0), Q); port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    exe = os.environ.get("CHROME") or next((p for p in ["/usr/bin/google-chrome", "/usr/bin/chromium"] if os.path.exists(p)), None)
    with sync_playwright() as p:
        b = p.chromium.launch(**({"executable_path": exe} if exe else {}))
        ctx = b.new_context(viewport={"width": 412, "height": 900}, has_touch=True)
        pg = ctx.new_page(); errs, csp = [], []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.on("console", lambda m: csp.append(m.text) if "Content Security Policy" in m.text and "fonts.g" not in m.text else None)
        pg.route("https://script.google.com/**", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps({"ok": False, "error": "SIGNIN: test"})))
        pg.route("https://accounts.google.com/**", lambda r: r.fulfill(status=200, content_type="text/javascript", body=""))
        pg.route("https://fonts.googleapis.com/**", lambda r: r.fulfill(status=200, content_type="text/css", body=""))
        pg.goto(f"http://127.0.0.1:{port}/index.html"); pg.wait_for_timeout(4000)
        ok(not errs, "no JavaScript errors on start" + ("" if not errs else ": " + errs[0][:160]))
        ok(not csp, "no Content-Security-Policy violations" + ("" if not csp else ": " + csp[0][:200]))
        ok(pg.evaluate("document.getElementById('verTxt').textContent") == "Version " + v, "the app ran to the end of its script (version shown in the menu)")
        ok(pg.evaluate("document.body.innerText.trim().length") > 20, "something is on screen (not a blank page)")
        sw_ok = pg.evaluate("navigator.serviceWorker.ready.then(r=>!!(r.active||r.installing||r.waiting)).catch(()=>false)")
        pg.wait_for_timeout(1500)
        ok(sw_ok and pg.evaluate("caches.keys().then(k=>k.some(x=>x.startsWith('kharcha-v')))"), "the service worker installs and saves the app for offline use")
        ctx.set_offline(True); pg.reload(); pg.wait_for_timeout(2500)
        ok(pg.evaluate("document.getElementById('verTxt')&&document.getElementById('verTxt').textContent") == "Version " + v, "opens with no internet from the saved copy")
        pg.screenshot(path=os.path.join(os.environ.get("CHECK_OUT", tempfile.gettempdir()), "kharcha-check.png"))
        ctx.close()
        # signed in, against a fake backend: the Artha look, taps that answer, and the saved moment
        import datetime
        ym = datetime.date.today().strftime("%Y-%m")
        ROWS = [[ym + "-02", 18300, "Aditya", "House", "Need", "Rent", "Both", "House - Rent", ym + "-02T09:00:00", 2, "a", "", ""],
                [ym + "-03", 640, "Choti", "Eating Out", "Want", "Dinner", "Both", "", ym + "-03T21:00:00", 3, "a", "", ""]]
        ctx = b.new_context(viewport={"width": 412, "height": 900}, has_touch=True, service_workers="block")
        pg = ctx.new_page(); errs = []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.route("https://script.google.com/**", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps({"ok": True, "d": {"rows": ROWS, "user": "Aditya", "email": "a", "at": "2026-11-10T10:00:00Z", "url": ""}})))
        pg.route("https://accounts.google.com/**", lambda r: r.fulfill(status=200, content_type="text/javascript", body=""))
        pg.route("https://fonts.googleapis.com/**", lambda r: r.fulfill(status=200, content_type="text/css", body=""))
        pg.add_init_script("localStorage.setItem('acx:tok',JSON.stringify('" + "a" * 64 + "'));localStorage.setItem('acx:me',JSON.stringify('Aditya'))")
        pg.goto(f"http://127.0.0.1:{port}/index.html"); pg.wait_for_timeout(3000)
        ok(pg.evaluate("document.documentElement.getAttribute('data-skin')") == "deck", "a phone opening Kharcha for the first time gets the 3D Space look")
        ok("₹" in pg.evaluate("document.getElementById('stage').textContent"), "the spending ring shows amounts when signed in")
        ok(pg.evaluate("(()=>{const c=document.getElementById('bgk');const d=c.getContext('2d').getImageData(0,0,c.width,c.height).data;for(let i=3;i<d.length;i+=400)if(d[i])return true;return false;})()"), "the moving background is drawing")
        pg.evaluate("(()=>{const e=document.getElementById('addBtn'),r=e.getBoundingClientRect();e.dispatchEvent(new PointerEvent('pointerdown',{bubbles:true,clientX:r.left+20,clientY:r.top+10}));})()")
        ok(pg.evaluate("!!document.querySelector('.tapd')&&document.querySelector('.rip').classList.contains('go')"), "a tap tilts the control and starts the light ripple")
        pg.evaluate("dispatchEvent(new PointerEvent('pointerup'))"); pg.click("#addBtn"); pg.wait_for_timeout(700)
        for k in "450": pg.evaluate("k=>[...document.querySelectorAll('#addSheet button')].find(b=>b.innerText.trim()===k).click()", k)
        pg.click("#aChoose"); pg.wait_for_timeout(500)
        pg.evaluate("[...document.querySelectorAll('.card')].filter(c=>c.offsetParent&&/Eating|Transport|Bills/.test(c.innerText))[0].click()"); pg.wait_for_timeout(1700)
        y = pg.evaluate("(document.querySelector('.yay')||{}).innerText||''")
        ok("₹450" in y and "This month so far" in y, "saving an expense shows the saved moment (" + y.replace("\n", " · ")[:70] + ")")
        ok(pg.evaluate("getComputedStyle(document.querySelector('.yay')).pointerEvents") == "none", "the saved moment lets touches through")
        pg.evaluate("dispatchEvent(new PointerEvent('pointerdown',{bubbles:true,clientX:5,clientY:300}))"); pg.wait_for_timeout(600)
        ok(pg.evaluate("!document.querySelector('.yay')"), "the next touch sends the saved moment away")
        pg.evaluate("localStorage.setItem('acx:skin',JSON.stringify('simple'))"); pg.reload(); pg.wait_for_timeout(2500)
        ok(pg.evaluate("document.documentElement.getAttribute('data-skin')") == "simple" and pg.evaluate("getComputedStyle(document.getElementById('bgk')).display") == "none", "another theme chosen in the menu is kept, with the background off")
        # 2.7: Paid by starts with the signed-in person; one "Other" bucket; half-width View panel; category screen; swipe left to edit
        pg.evaluate("localStorage.setItem('acx:skin',JSON.stringify('deck'))"); pg.reload(); pg.wait_for_timeout(2000)
        pg.click("#addBtn"); pg.wait_for_timeout(500); w1 = pg.inner_text("#aWho"); pg.click("#aWhoBtn"); pg.evaluate("history.back()"); pg.wait_for_timeout(500)
        pg.click("#addBtn"); pg.wait_for_timeout(500); w2 = pg.inner_text("#aWho"); pg.evaluate("history.back()"); pg.wait_for_timeout(500)
        ok(w1 == "Aditya" and w2 == "Aditya", f"Paid by starts with the signed-in person every time ({w1}, then {w2} after switching once)")
        pg.click("#menuBtn"); pg.wait_for_timeout(700)
        fo = pg.evaluate("[...document.querySelectorAll('#fFor button')].map(b=>b.innerText.trim())")
        ok("Other" in fo and "Unspecified" not in fo, "Expense for has one Other bucket (no Unspecified): " + ", ".join(fo))
        dw = pg.evaluate("document.getElementById('drawer').getBoundingClientRect().width/innerWidth")
        ok(0.38 <= dw <= 0.55 and pg.evaluate("document.body.classList.contains('dopen')"), f"the View panel takes about half the screen ({dw:.0%}) and the app slides aside")
        pg.mouse.click(380, 500); pg.wait_for_timeout(700)
        ok(not pg.evaluate("document.body.classList.contains('dopen')"), "tapping the app beside the panel closes it")
        ok("Sync" not in pg.evaluate("document.querySelector('header.top').innerText"), "no Sync button in the header (pull down or tap the status line)")
        pg.evaluate("document.querySelector('#legend .lrow').click()"); pg.wait_for_timeout(600)
        ok(pg.evaluate("!document.getElementById('cSheet').hidden&&document.querySelectorAll('#cBody .txw').length>0"), "a category opens on its own screen with its entries")
        pg.evaluate("history.back()"); pg.wait_for_timeout(500)
        ok(pg.evaluate("document.getElementById('cSheet').hidden"), "back closes the category screen")
        # 2.8: clean home, swipe between periods, category breakdown
        ok(pg.evaluate("!document.getElementById('prevBtn')&&!document.getElementById('nextBtn')&&!document.getElementById('pseg')"), "home has no previous/next labels and no period switch")
        ok(pg.evaluate("document.getElementById('sync').hidden"), "the sync line is hidden when all is well")
        t0 = pg.inner_text("#curBtn")
        pg.evaluate("""(()=>{const t=document.getElementById('todayBtn'); const T=x=>new Touch({identifier:1,target:t,clientX:x,clientY:160});
          t.dispatchEvent(new TouchEvent('touchstart',{bubbles:true,touches:[T(330)],changedTouches:[T(330)]}));
          for(let x=320;x>=90;x-=23) t.dispatchEvent(new TouchEvent('touchmove',{bubbles:true,touches:[T(x)],changedTouches:[T(x)]}));
          t.dispatchEvent(new TouchEvent('touchend',{bubbles:true,touches:[],changedTouches:[T(90)]}));})()""")
        pg.wait_for_timeout(900); t1 = pg.inner_text("#curBtn")
        ok(t1 != t0, f"swiping left moves to the next period ({t0} → {t1})")
        pg.keyboard.press("ArrowLeft"); pg.wait_for_timeout(900)
        ok(pg.inner_text("#curBtn") == t0, "and back again")
        # 2.9: swipe across the ring changes period; tap picks a slice; a long press peeks and lets go; one-colour title
        ok(pg.evaluate("getComputedStyle(document.querySelector('.brand h1')).backgroundImage")=="none", "the title is one colour")
        RT = """(kind,pts)=>{const s=document.querySelector('#stage svg'),n=s.querySelector('.seg[data-i="0"]'),r=n.getBoundingClientRect();
          const T=(x,y)=>new Touch({identifier:7,target:n,clientX:x,clientY:y}); const [x,y]=pts[0];
          n.dispatchEvent(new TouchEvent(kind,{bubbles:true,cancelable:true,touches:kind==='touchend'?[]:[T(x,y)],changedTouches:[T(x,y)]}));}"""
        pt = pg.evaluate("""(()=>{const s=document.querySelector('#stage svg'); for(let a=0;a<360;a+=3){const r=s.getBoundingClientRect(),k=r.width/300,t=(a-90)*Math.PI/180;
          const x=r.left+(150+108*Math.cos(t))*k,y=r.top+(150+108*Math.sin(t))*k,e=document.elementFromPoint(x,y); if(e&&e.classList.contains('seg')&&e.dataset.i==='0') return [x,y];} return null;})()""")
        ok(pt is not None, "found the first slice on the ring")
        x, y = pt
        t0 = pg.inner_text("#curBtn")
        pg.evaluate(f"({RT})('touchstart',[[{x},{y}]])")
        for k in range(1, 11): pg.evaluate(f"({RT})('touchmove',[[{x-k*22},{y+k*4}]])")
        pg.evaluate(f"({RT})('touchend',[[{x-220},{y+40}]])"); pg.wait_for_timeout(900)
        ok(pg.inner_text("#curBtn") != t0 and pg.evaluate("(document.querySelector('#stage svg .seg.on')?+document.querySelector('#stage svg .seg.on').dataset.i:-1)")==-1, "a swipe that starts on the ring moves to the next period without picking a slice")
        pg.keyboard.press("ArrowLeft"); pg.wait_for_timeout(900)
        pg.mouse.click(x, y); pg.wait_for_timeout(450)
        ok(pg.evaluate("(document.querySelector('#stage svg .seg.on')?+document.querySelector('#stage svg .seg.on').dataset.i:-1)===0&&document.querySelector('#stage svg').classList.contains('sel')"), "a tap on a slice picks it")
        pg.mouse.click(x, y); pg.wait_for_timeout(450)
        ok(pg.evaluate("(document.querySelector('#stage svg .seg.on')?+document.querySelector('#stage svg .seg.on').dataset.i:-1)===-1"), "tapping it again clears it")
        pg.evaluate(f"({RT})('touchstart',[[{x},{y}]])"); pg.wait_for_timeout(520)
        held = pg.evaluate("(document.querySelector('#stage svg .seg.on')?+document.querySelector('#stage svg .seg.on').dataset.i:-1)===0&&document.querySelector('#stage svg').classList.contains('held')")
        pg.evaluate(f"({RT})('touchend',[[{x},{y}]])"); pg.wait_for_timeout(450)
        ok(held and pg.evaluate("(document.querySelector('#stage svg .seg.on')?+document.querySelector('#stage svg .seg.on').dataset.i:-1)===-1"), "a long press shows the slice while held and lets go on release")
        pg.evaluate("[...document.querySelectorAll('#legend .lrow')][0].click()"); pg.wait_for_timeout(600)
        ok(pg.evaluate("/Where it went/.test(document.getElementById('cBody').innerText)&&!document.querySelector('#cBody svg.bars')"), "a category shows where the money went (no per-day bar chart)")
        pg.evaluate("history.back()"); pg.wait_for_timeout(400)
        ok(not errs, "no JavaScript errors in the 2.7 screens" + ("" if not errs else ": " + errs[0][:160]))
        ok(not errs, "no JavaScript errors signed in" + ("" if not errs else ": " + errs[0][:160]))
        pg.screenshot(path=os.path.join(os.environ.get("CHECK_OUT", tempfile.gettempdir()), "kharcha-signed-in.png"))
        ctx.close(); b.close()
    srv.shutdown()

print("\n" + ("ALL CHECKS PASSED" if not FAIL else f"{len(FAIL)} CHECK(S) FAILED — do not publish"))
sys.exit(1 if FAIL else 0)
