# web-hhj

A single-page **Web Bluetooth** tool that drives the "HHJ" white-label Bluetooth
GPS gadget from the browser: connect over BLE, authenticate, and inject a
location — a single point or an animated track — onto an **OpenStreetMap** map,
with address search. It is the browser counterpart to the reverse-engineering
write-up in [`hhj_protocol.md`](hhj_protocol.md) and the Python/`bleak` port in
[`hhj_gps.py`](hhj_gps.py).

> Built from analysis of a **delisted** App Store app. This is
> interoperability / security-research tooling for a device you own. Feeding
> fabricated coordinates into systems that rely on genuine location may be
> illegal or violate terms of service — use only with hardware you are
> authorised to test.

## What it does

- Scans for the gadget (advertised name `AAAAA`, or containing `br29`) and connects.
- Runs the handshake: writes `"<unix_seconds>_dsfds123"` to the auth-write
  characteristic and waits for `"authSuc"` on the notify characteristic.
- Streams NMEA `$GPGGA` + `$GPRMC` sentences to the location characteristic
  (`000032e1-…`) with write-without-response, exactly as the original app.
- Map UI: search an address (OSM Nominatim), click to drop a point, **Inject
  once** or **Stream point**, or add waypoints and **Play track** to simulate
  movement. Optional China WGS-84 → GCJ-02 shift and optional NMEA checksums.

## Browser requirements

Web Bluetooth needs a **Chromium** browser (Chrome / Edge, desktop or Android)
and a **secure context** — served over `https://` (Cloudflare Pages provides
this) or opened as a local `file://`. Safari and Firefox do not support Web
Bluetooth.

## Deploy to Cloudflare Pages

This is a static site — no build step. `index.html` is served at the root and
`_headers` sets sensible security headers (and keeps the Bluetooth permission
policy enabled for same-origin).

**Option A — Git integration (recommended)**

1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Pages** →
   **Connect to Git** → pick `iebb/web-hhj`.
2. Build settings:
   - Framework preset: **None**
   - Build command: *(leave empty)*
   - Build output directory: **`/`**
3. **Save and Deploy**. Every push to `main` redeploys.

**Option B — Direct upload with Wrangler**

```bash
npx wrangler pages deploy . --project-name web-hhj
```

## Local use

```bash
# from the repo root
python3 -m http.server 8000    # then open http://localhost:8000
# or just open index.html directly in Chrome/Edge (file:// is a secure context)
```

## Files

| File | Purpose |
|------|---------|
| `index.html` | The Web-BLE injector app (self-contained; Leaflet + OSM via CDN) |
| `_headers` | Cloudflare Pages security headers |
| `hhj_protocol.md` | Full protocol reverse-engineering write-up |
| `hhj_gps.py` | Command-line Python/`bleak` implementation of the same protocol |
