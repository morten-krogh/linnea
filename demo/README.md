# The linnea demo page

**This is the web page served at [linnea.amberbio.com](https://linnea.amberbio.com)
— it is NOT the linnea server.** It is plain HTML, CSS and JavaScript that runs
in the browser to *show linnea off*: a couple of `/api` demos and a WebSocket
counter, each reporting whether it was carried over HTTP/2 or HTTP/3. The server
itself — the actual product — is the assembly under [`../src/`](../src); nothing
in this directory is part of it or runs on the server.

It lives in the repo only so page changes are tracked and reproducible like the
rest. linnea does not need it and does not read it; it is served as ordinary
static files from the web root.

## What's here

| File | What it is |
|---|---|
| `index.html` | The page. |
| `app.js` | Its behaviour: the `/api/random` and `/api/upload` demos, and the WebSocket counter. |
| `style.css` | Its styles. |
| `favicon.ico` | The tab icon. |
| `deploy.sh` | Copies the above to the web root and regenerates the precompressed variants. |
| `app_test.mjs` | A node check of the upload handler's status/error handling (no browser needed). |

## What's deliberately NOT here

- **The precompressed variants** (`index.html.br`, `app.js.br`, `style.css.gz`).
  linnea content-negotiates on `Accept-Encoding` and serves these when a browser
  accepts them. They are build artifacts — `deploy.sh` regenerates them — so they
  are not committed, exactly as the compiled binary is not.
- **The gallery images and the video.** `index.html` references a handful of
  ~0.6 MB PNGs and a ~31 MB video; those large static assets live in the web root
  and are kept out of the repo to keep it small. Bring your own, or drop them in
  the web root beside the page.

## Deploying

The web root is `/var/www/linnea` (owned by `linnea`, so no `sudo`):

```sh
./deploy.sh                 # to /var/www/linnea
./deploy.sh /path/to/root   # somewhere else
```

It installs the four source files and regenerates the `.br`/`.gz` variants,
checking each decompresses back to its source. No server reload is needed —
linnea opens these files per request. The gotcha it exists to prevent: editing a
source without regenerating its variant, so browsers sending `Accept-Encoding:
br` keep getting the old page. (linnea now serves the newer of source and
variant, so a stale variant is corrected rather than served — but regenerating
keeps the compressed path working.)

## Testing the JavaScript

There is no browser here, so `app.js` is checked by shimming the browser APIs
and driving the handlers under node:

```sh
node app_test.mjs app.js
```

It reproduces the case that once hung the page — an upload the server refuses
with `413` *mid-send*, so the `XMLHttpRequest` never fires `onload` — and
confirms the page now reads the status from the response headers and shows
"refused: too large (413)" instead of stalling. A real over-limit upload still
has to be tried by a human: a file `<input>` cannot be driven from a script.
