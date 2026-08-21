// Page behaviour for linnea.amberbio.com: the two /api demos and the shared
// WebSocket counter. Loaded at the end of <body>, so every element it looks
// up already exists.

// Which protocol actually carried a request. Resource timing knows, and it is
// the interesting part of the demo: the same fetch runs over h2 or h3
// depending on what the browser settled on.
function via(url) {
    const e = performance.getEntriesByType("resource")
                         .filter(r => r.name.endsWith(url)).pop();
    return e && e.nextHopProtocol ? " over " + e.nextHopProtocol : "";
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
}

document.getElementById("rand-go").onclick = async () => {
    const out = document.getElementById("rand-out");
    out.textContent = "…";
    try {
        const r = await fetch("/api/random", { cache: "no-store" });
        if (!r.ok) { out.textContent = "HTTP " + r.status; return; }
        const j = await r.json();
        out.textContent = j.value + via("/api/random");
    } catch (e) {
        out.textContent = "request failed: " + e;
    }
};

const upFile = document.getElementById("up-file");
const upOut = document.getElementById("up-out");
const upGo = document.getElementById("up-go");
const upBar = document.getElementById("up-progress");
const upFill = document.getElementById("up-fill");
const upCancel = document.getElementById("up-cancel");

// The upload in flight, so Cancel has something to abort. One at a time —
// upGo is disabled for the duration — so a single reference is enough.
let upXhr = null;

// Which of h2 and h3 is quicker for the SAME file is the question these
// numbers exist to answer, so the one that matters is the SEND time: start to
// last byte handed to the network. The total additionally covers the server
// reading the body and hashing it, which is identical work whichever protocol
// carried it and so only blurs the comparison — reported, but second.
function upRate(bps) {
    if (bps >= 1e6) { return (bps / 1e6).toFixed(1) + " MB/s"; }
    if (bps >= 1e3) { return (bps / 1e3).toFixed(0) + " kB/s"; }
    return bps.toFixed(0) + " B/s";
}

function upTiming(bytes, m) {
    const send = (m.sent - m.start) / 1000;
    const total = (m.done - m.start) / 1000;
    let s = "<br>sent in " + send.toFixed(2) + " s";
    if (send > 0) { s += " (" + upRate(bytes / send) + ")"; }
    s += ", total " + total.toFixed(2) + " s";
    return s;
}

// null hides the bar; otherwise 0..1. aria-valuenow carries the same number,
// because the width alone says nothing to a screen reader.
function upProgress(frac) {
    upBar.classList.remove("waiting");
    if (frac === null) {
        upBar.hidden = true;
        upFill.style.width = "0";
        upBar.setAttribute("aria-valuenow", "0");
        return;
    }
    const pct = Math.max(0, Math.min(100, Math.round(frac * 100)));
    upBar.hidden = false;
    upFill.style.width = pct + "%";
    upBar.setAttribute("aria-valuenow", String(pct));
}

// A new selection is a different file, so the name, size and digest sitting
// under it are no longer about anything on screen. Left there they read as
// this file's result until the upload finishes and replaces them.
upFile.onchange = () => {
    upOut.textContent = "";
    upProgress(null);
};

// XMLHttpRequest rather than fetch, purely for the progress bar: fetch reports
// nothing about a request body on its way out. (A ReadableStream body does,
// but only in Chromium, and it splits the body across DATA frames — a shape
// this server deadlocked on until 9500185.) XHR has reported bytes-sent since
// long before either.
function upSend(f, m) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        upXhr = xhr;
        // A stalled request must never hang the page forever. 60 s is far more
        // than a body capped at max_body needs, so this only fires when
        // something is genuinely wrong, not on a slow-but-progressing upload.
        xhr.timeout = 60000;
        xhr.open("POST", "/api/upload");
        // a header may not carry arbitrary bytes, so the name is
        // percent-encoded here and decoded by the backend
        xhr.setRequestHeader("X-Filename", encodeURIComponent(f.name));
        xhr.upload.onprogress = e => {
            if (e.lengthComputable) { upProgress(e.loaded / e.total); }
        };
        xhr.upload.onload = () => {
            m.sent = performance.now();
            // Every byte is handed to the network, but the answer is still to
            // come: the server has the whole body and is hashing it. A bar
            // that simply sat full here read as a finished upload whose result
            // had gone missing.
            upProgress(1);
            upBar.classList.add("waiting");
            upOut.textContent = "sent — waiting for the server's digest…";
        };
        // Exactly one of the paths below settles the promise.
        let settled = false;
        const done = v => {
            if (!settled) { settled = true; m.done = performance.now(); resolve(v); }
        };
        const fail = e => { if (!settled) { settled = true; reject(e); } };
        // The server can answer BEFORE the upload finishes: a body over max_body
        // is refused with 413 while the browser is still sending, and the stream
        // is reset under it. onload then never fires -- the request never
        // "completes" cleanly -- so the page would sit at "uploading…" forever.
        // Read the status the moment its HEADERS arrive instead, and abort the
        // doomed send. (A 2xx does not take this path: onload handles it.)
        xhr.onreadystatechange = () => {
            if (!settled && xhr.readyState === xhr.HEADERS_RECEIVED
                         && xhr.status >= 400) {
                done({ status: xhr.status, text: "" });
                try { xhr.abort(); } catch (e) {}   // onabort is now a no-op
            }
        };
        xhr.onload = () => done({ status: xhr.status, text: xhr.responseText });
        xhr.onerror = () => fail(new Error("network error"));
        xhr.ontimeout = () => fail(new Error("timed out"));
        // Distinguished from a failure on purpose: a cancel is something the
        // reader just did, not something that went wrong.
        xhr.onabort = () => fail(new Error("cancelled"));
        xhr.send(f);
    });
}

upGo.onclick = async () => {
    const f = upFile.files[0];
    if (!f) { upOut.textContent = "choose a file first"; upProgress(null); return; }
    upGo.disabled = true;                     // one upload at a time, or the
    upCancel.disabled = false;                // bar is reporting on two
    upOut.textContent =
        "uploading " + f.size.toLocaleString() + " bytes…";
    upProgress(0);
    // Taken here rather than inside upSend so it covers everything the reader
    // waited for after pressing the button.
    const m = { start: performance.now(), sent: 0, done: 0 };
    try {
        const r = await upSend(f, m);
        if (r.status === 413) {
            // Deliberately does not name a size. This said "8 MiB" long after
            // max_body became 80, because the number was written here and
            // nowhere the server could correct it — so a 413 for an unrelated
            // reason was reported as a size the cap had not been at for hours.
            upOut.textContent = "refused: too large (413)";
            upProgress(null);
            return;
        }
        if (r.status < 200 || r.status > 299) {
            upOut.textContent = "HTTP " + r.status;
            upProgress(null);
            return;
        }
        const j = JSON.parse(r.text);

        // Hash it here too. If the two digests agree, every byte survived the
        // trip — which is the whole point of the exercise. A disagreement has
        // to LOOK like one: shown in the same green as a match, a corrupted
        // upload would read as a success at a glance.
        let agree = "", cls = "agree";
        if (window.crypto && crypto.subtle) {
            upProgress(1);
            upOut.textContent = "checking this browser's digest…";
            const buf = await crypto.subtle.digest("SHA-256", await f.arrayBuffer());
            const mine = [...new Uint8Array(buf)]
                .map(b => b.toString(16).padStart(2, "0")).join("");
            if (mine === j.checksum) {
                agree = " ✓ matches this browser's digest";
            } else {
                agree = " ✗ DIFFERS from this browser's digest";
                cls = "disagree";
            }
        }
        upProgress(1);
        upOut.innerHTML =
            escapeHtml(j.name) + " — " + j.size.toLocaleString() + " bytes" +
            via("/api/upload") + upTiming(j.size, m) +
            "<br>sha256 " + escapeHtml(j.checksum) +
            "<span class=\"" + cls + "\">" + escapeHtml(agree) + "</span>";
    } catch (e) {
        upOut.textContent =
            e.message === "cancelled" ? "cancelled" : "upload failed: " + e.message;
        upProgress(null);
    } finally {
        upGo.disabled = false;
        upCancel.disabled = true;
        upXhr = null;
    }
};

// Abort the request outright: the browser resets the h2/h3 stream, so the
// server stops reading a body nobody wants any more rather than draining it.
upCancel.onclick = () => { if (upXhr) { upXhr.abort(); } };

// The counter socket. It reconnects on its own, because the backend is
// restarted whenever it is rebuilt and a page that needs reloading to come
// back would hide exactly the behaviour this is meant to show.
(function () {
    const out = document.getElementById("ws-count");
    const status = document.getElementById("ws-status");
    const btn = document.getElementById("ws-go");
    let sock = null, wait = 500;

    function connect() {
        status.textContent = "connecting…";
        // Same origin as the page, so this follows the host it was served
        // from rather than naming one. Captured in a local as well: a handler
        // belonging to a socket we have already replaced must not close or
        // reconnect on behalf of the current one.
        const s = new WebSocket("wss://" + location.host + "/ws");
        sock = s;
        s.onopen = () => {
            wait = 500;
            btn.disabled = false;
            status.textContent = "connected";
        };
        s.onmessage = ev => {
            let st;
            try { st = JSON.parse(ev.data); } catch (e) { return; }
            out.textContent = st.count;
            status.textContent = st.clients === 1
                ? "connected — you are the only one here"
                : "connected — " + st.clients + " sockets open";
        };
        s.onerror = () => s.close();
        s.onclose = () => {
            if (sock !== s) { return; }
            btn.disabled = true;
            status.textContent = "disconnected — retrying…";
            setTimeout(connect, wait);
            wait = Math.min(wait * 2, 10000);
        };
    }

    btn.onclick = () => {
        if (sock && sock.readyState === WebSocket.OPEN) { sock.send("inc"); }
    };
    connect();
})();
