// Check the demo page's upload handler without a browser: shim the browser APIs,
// eval app.js, and drive up-go.onclick. Two things matter here:
//   1. An oversized file is refused CLIENT-SIDE before any upload, with a clear
//      message stating the cap -- so every browser behaves the same (Chrome,
//      Firefox and Safari otherwise disagree on a 413 that arrives mid-upload).
//   2. If the server still answers 413 mid-upload (the cap drifted), the request
//      never completes, so onload never fires -- the page must read the status
//      when the response HEADERS arrive, or it hangs.
//
//   node app_test.mjs [path-to-app.js]      (defaults to ./app.js)
import fs from "node:fs";

const APP = process.argv[2] || new URL("app.js", import.meta.url).pathname;
const src = fs.readFileSync(APP, "utf8");

let fails = 0;
const check = (label, ok) => { console.log((ok ? "ok   " : "FAIL ") + label); if (!ok) fails++; };

// element shim -- textContent and innerHTML are NOT independent: setting one
// clears the other's content, as a real node does.
function mkEl() {
  return {
    _text: "", _html: "",
    get textContent() { return this._text; },
    set textContent(v) { this._text = String(v); this._html = ""; },
    get innerHTML() { return this._html; },
    set innerHTML(v) { this._html = String(v); this._text = ""; },
    classList: { add() {}, remove() {} },
    style: {}, hidden: false, disabled: false,
    setAttribute() {}, onclick: null, onchange: null, files: [],
  };
}
const els = {};
["rand-go","rand-out","up-file","up-out","up-go","up-progress","up-fill",
 "up-cancel","up-limit","ws-count","ws-status","ws-go"].forEach(id => els[id] = mkEl());

// XMLHttpRequest shim -- the test fires its events to script a scenario.
let lastXhr = null;
class FakeXHR {
  constructor() {
    this.HEADERS_RECEIVED = 2; this.readyState = 0; this.status = 0;
    this.responseText = ""; this.timeout = 0; this.upload = {};
    this.onreadystatechange = this.onload = this.onerror = this.ontimeout = this.onabort = null;
    lastXhr = this;
  }
  open() {} setRequestHeader() {} send() {}
  abort() { if (this.onabort) this.onabort(); }
}

const ctx = {
  document: { getElementById: id => els[id] },
  performance: { now: () => 0, getEntriesByType: () => [] },
  XMLHttpRequest: FakeXHR,
  WebSocket: function () { this.close = () => {}; },
  location: { host: "example.test" },
  window: null, setTimeout: () => {}, console, JSON,
};
ctx.window = ctx;                       // app.js reads window.crypto (undefined -> digest skipped)
new Function(...Object.keys(ctx), src)(...Object.values(ctx));

const fileOver  = { name: "big.bin",   size: 1500000, arrayBuffer: async () => new ArrayBuffer(0) };
const fileUnder = { name: "small.bin", size: 500000,  arrayBuffer: async () => new ArrayBuffer(0) };
const tick = () => new Promise(r => setImmediate(r));

// 1) The cap is stated on load, from the constant in app.js.
check("states the cap on load: " + JSON.stringify(els["up-limit"].textContent),
      els["up-limit"].textContent.includes("1 MiB"));

// 2) An oversized file is refused client-side -- no upload is even started.
els["up-out"].textContent = "";
els["up-file"].files = [fileOver];
lastXhr = null;
await els["up-go"].onclick();
check("oversized file refused before any upload (no XHR created)", lastXhr === null);
check("...with a clear message naming the cap: " + JSON.stringify(els["up-out"].textContent),
      els["up-out"].textContent.includes("1 MiB") && /cap/i.test(els["up-out"].textContent));

// 3) Fallback: an in-limit file the server 413s MID-UPLOAD (cap drifted). onload
//    never fires; the page must settle from the response headers, not hang.
async function serverRefusesMidUpload() {
  els["up-out"].textContent = "";
  els["up-file"].files = [fileUnder];
  let settled = false;
  els["up-go"].onclick().then(() => { settled = true; });   // do NOT await -- may hang
  const x = lastXhr;
  if (x.upload.onprogress) x.upload.onprogress({ lengthComputable: true, loaded: 130891, total: fileUnder.size });
  x.readyState = x.HEADERS_RECEIVED; x.status = 413;
  if (x.onreadystatechange) x.onreadystatechange();
  for (let i = 0; i < 5; i++) await tick();
  return { settled, text: els["up-out"].textContent };
}
const r413 = await serverRefusesMidUpload();
check("a server 413 mid-upload settles the page (does not hang)", r413.settled === true);
check("...and shows the refusal: " + JSON.stringify(r413.text),
      r413.text === "refused: too large (413)");

// 4) A normal 200 still shows the result.
els["up-out"].textContent = "";
els["up-file"].files = [fileUnder];
const p200 = els["up-go"].onclick();
{
  const x = lastXhr;
  if (x.upload.onload) x.upload.onload();
  x.readyState = x.HEADERS_RECEIVED; x.status = 200;
  if (x.onreadystatechange) x.onreadystatechange();          // 200 must NOT take the early path
  x.responseText = JSON.stringify({ name: "small.bin", size: 500000, checksum: "abc" });
  if (x.onload) x.onload();
}
await p200; await tick();
const out200 = els["up-out"].innerHTML || els["up-out"].textContent;
check("a normal 200 still shows the result: " + JSON.stringify(out200.slice(0, 28)),
      out200.includes("small.bin") && out200.includes("500,000"));

console.log(fails ? `\n${fails} failed` : "\nOK");
process.exit(fails ? 1 : 0);
