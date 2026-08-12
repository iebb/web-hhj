#!/usr/bin/env python3
"""
hhj_gps.py — Reimplementation of the "HHJ" white-label Bluetooth GPS gadget app.

This is a clean-room Python port of the BLE + location protocol used by the iOS
app "HHJ" (bundle sidvuwennfnwe.sadjcjas.bbnhh, binary "MapBlue"), recovered by
reverse engineering. See hhj_protocol.md for the full analysis and the exact
offsets in the decompiled binary.

What the app does
-----------------
The phone acts as a BLE *central*. It connects to a small BLE *peripheral*
(a "GPS gadget"), authenticates with a shared secret + timestamp, then streams
the phone's location to the gadget as plain-ASCII NMEA-0183 sentences
($GPGGA + $GPRMC) written to a "location" characteristic. Inside mainland China
the WGS-84 coordinate is first shifted to GCJ-02 (the standard China offset).

Protocol summary (all values verified against the binary)
---------------------------------------------------------
  Auth service        0000faa1-0000-1000-8000-00805f8c12ab
    Auth write char   000021e1-0000-1000-8000-00805f8a12fb   (write w/ response)
    Auth notify char  000021e2-0000-1000-8000-00805f8a12fb   (notify)
  Data service        0000fbb2-0000-1000-8000-00805f8c12ab
    Location char     000032e1-0000-1000-8000-00805f8a12fb   (write w/o response)

  Handshake : central writes  "<unix_epoch_seconds>_dsfds123"  to the auth-write
              characteristic; the gadget replies with the ASCII "authSuc" on the
              auth-notify characteristic -> considered connected.
  Location  : central writes NMEA text to the location characteristic, e.g.
              "$GPGGA,<utc>,<ddmm.mmmmmm>,<N|S>,<dddmm.mmmmmm>,<E|W>,1,09,0.6,"
              "<alt>,M,-27.0,M,,$GPRMC,<utc>,A,<lat>,<N|S>,<lon>,<E|W>,"
              "0.0,0.0,<ddmmyy>,0.0,E,A"
              (the app appends no *checksum and no CRLF; both are optional here).

  Scan filter: the app keeps advertised peripherals whose name == "AAAAA" or
               whose name contains "br29".

Usage
-----
  pip install bleak
  python3 hhj_gps.py --scan
  python3 hhj_gps.py --lat 31.230416 --lon 121.473701            # stream fixed point
  python3 hhj_gps.py --address <MAC/UUID> --lat 31.23 --lon 121.47
  python3 hhj_gps.py --lat 31.23 --lon 121.47 --dry-run          # no BLE; print frames
  python3 hhj_gps.py --track track.csv                           # stream lat,lon[,alt] rows

The --dry-run mode needs no hardware and prints exactly the bytes the app would
put on the wire, so the protocol can be inspected/validated without a gadget.
"""

from __future__ import annotations

import argparse
import asyncio
import math
import sys
import time
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants recovered from the binary (BlueService.init, FUN_10001d8a8)
# ---------------------------------------------------------------------------

AUTH_SERVICE_UUID = "0000faa1-0000-1000-8000-00805f8c12ab"
AUTH_WRITE_UUID   = "000021e1-0000-1000-8000-00805f8a12fb"   # write (with response)
AUTH_NOTIFY_UUID  = "000021e2-0000-1000-8000-00805f8a12fb"   # notify
DATA_SERVICE_UUID = "0000fbb2-0000-1000-8000-00805f8c12ab"
LOCATION_UUID     = "000032e1-0000-1000-8000-00805f8a12fb"   # write (without response)

SECRET_KEY   = "dsfds123"   # BlueService.secretKey
SUCCESS_VALUE = "authSuc"   # BlueService.sucValue

# didDiscoverPeripheral keeps a device if name == "AAAAA" or "br29" in name.
NAME_EXACT    = "AAAAA"
NAME_CONTAINS = "br29"

# ---------------------------------------------------------------------------
# Coordinate handling
# ---------------------------------------------------------------------------

# China bounding box used by the app before applying the GCJ-02 offset
# (the classic "out of China" guard: lon 72.004..137.8347, lat 0.8293..55.8271).
_CN_LON = (72.004, 137.8347)
_CN_LAT = (0.8293, 55.8271)

# GCJ-02 constants
_GCJ_A = 6378137.0                    # semi-major axis
_GCJ_EE = 0.00669342162296594323      # eccentricity squared


def _out_of_china(lat: float, lon: float) -> bool:
    return not (_CN_LON[0] < lon < _CN_LON[1] and _CN_LAT[0] < lat < _CN_LAT[1])


def _transform_lat(x: float, y: float) -> float:
    ret = (-100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y
           + 0.1 * x * y + 0.2 * math.sqrt(abs(x)))
    ret += (20.0 * math.sin(6.0 * x * math.pi) + 20.0 * math.sin(2.0 * x * math.pi)) * 2.0 / 3.0
    ret += (20.0 * math.sin(y * math.pi) + 40.0 * math.sin(y / 3.0 * math.pi)) * 2.0 / 3.0
    ret += (160.0 * math.sin(y / 12.0 * math.pi) + 320.0 * math.sin(y * math.pi / 30.0)) * 2.0 / 3.0
    return ret


def _transform_lon(x: float, y: float) -> float:
    ret = (300.0 + x + 2.0 * y + 0.1 * x * x
           + 0.1 * x * y + 0.1 * math.sqrt(abs(x)))
    ret += (20.0 * math.sin(6.0 * x * math.pi) + 20.0 * math.sin(2.0 * x * math.pi)) * 2.0 / 3.0
    ret += (20.0 * math.sin(x * math.pi) + 40.0 * math.sin(x / 3.0 * math.pi)) * 2.0 / 3.0
    ret += (150.0 * math.sin(x / 12.0 * math.pi) + 300.0 * math.sin(x / 30.0 * math.pi)) * 2.0 / 3.0
    return ret


def wgs84_to_gcj02(lat: float, lon: float) -> Tuple[float, float]:
    """WGS-84 -> GCJ-02, matching FUN_100034b04 (the app's inline delta calc)."""
    if _out_of_china(lat, lon):
        return lat, lon
    dlat = _transform_lat(lon - 105.0, lat - 35.0)
    dlon = _transform_lon(lon - 105.0, lat - 35.0)
    radlat = lat / 180.0 * math.pi
    magic = math.sin(radlat)
    magic = 1.0 - _GCJ_EE * magic * magic
    sqrtmagic = math.sqrt(magic)
    dlat = (dlat * 180.0) / ((_GCJ_A * (1.0 - _GCJ_EE)) / (magic * sqrtmagic) * math.pi)
    dlon = (dlon * 180.0) / (_GCJ_A / sqrtmagic * math.cos(radlat) * math.pi)
    return lat + dlat, lon + dlon


def format_coordinate(value: float, strip_leading_zero: bool = True) -> str:
    """
    Decimal degrees -> NMEA ddmm.mmmmmm, reproducing BlueService's formatter
    (FUN_100055960): "%02d%09.6f" % (abs(int(deg)), abs(frac)*60), then, if the
    result starts with '0', drop that single leading zero (the app does exactly
    this via hasPrefix("0")+removeFirst()).
    """
    deg = int(value)                      # truncation toward zero, like (long)double
    minutes = abs((value - deg) * 60.0)
    s = "%02d%09.6f" % (abs(deg), minutes)
    if strip_leading_zero and s.startswith("0"):
        s = s[1:]
    return s


# ---------------------------------------------------------------------------
# NMEA sentence assembly (FUN_10001f9cc)
# ---------------------------------------------------------------------------

@dataclass
class Fix:
    lat: float
    lon: float
    alt: float = 0.0            # metres; GGA altitude field
    when: Optional[float] = None  # unix epoch seconds; defaults to now


def _nmea_checksum(sentence_body: str) -> str:
    cs = 0
    for ch in sentence_body:
        cs ^= ord(ch)
    return "%02X" % cs


def build_payload(fix: Fix,
                  convert_gcj02: bool = True,
                  checksum: bool = False,
                  crlf: bool = False) -> bytes:
    """
    Build the exact ASCII payload the app writes to the location characteristic.

    By default this reproduces the app byte-for-byte: $GPGGA immediately followed
    by $GPRMC, no '*' checksum, no CRLF. Pass checksum=True / crlf=True to emit
    standards-compliant NMEA for stricter parsers.
    """
    lat, lon = (wgs84_to_gcj02(fix.lat, fix.lon) if convert_gcj02
                else (fix.lat, fix.lon))

    ns = "N" if lat >= 0 else "S"
    ew = "E" if lon >= 0 else "W"
    lat_s = format_coordinate(lat)
    lon_s = format_coordinate(lon)

    t = time.gmtime(fix.when if fix.when is not None else time.time())
    utc = time.strftime("%H%M%S", t) + ".00"    # hhmmss.ss
    date = time.strftime("%d%m%y", t)           # ddmmyy
    alt_s = ("%g" % fix.alt)

    # Field layout and constant fillers (1,09,0.6 / -27.0 / A / 0.0,E,A) are the
    # literals decoded from the sender in FUN_10001f9cc.
    gga_body = ("GPGGA,%s,%s,%s,%s,%s,1,09,0.6,%s,M,-27.0,M,,"
                % (utc, lat_s, ns, lon_s, ew, alt_s))
    rmc_body = ("GPRMC,%s,A,%s,%s,%s,%s,0.0,0.0,%s,0.0,E,A"
                % (utc, lat_s, ns, lon_s, ew, date))

    if checksum:
        gga = "$" + gga_body + "*" + _nmea_checksum(gga_body)
        rmc = "$" + rmc_body + "*" + _nmea_checksum(rmc_body)
    else:
        gga = "$" + gga_body
        rmc = "$" + rmc_body

    sep = "\r\n" if crlf else ""
    text = gga + sep + rmc + (("\r\n") if crlf else "")
    return text.encode("utf-8")


def build_auth_payload(now: Optional[float] = None) -> bytes:
    """"<unix_epoch_seconds>_dsfds123"  (FUN_10001ee08 / auth-write)."""
    ts = int(now if now is not None else time.time())
    return ("%d_%s" % (ts, SECRET_KEY)).encode("utf-8")


# ---------------------------------------------------------------------------
# BLE client (bleak)
# ---------------------------------------------------------------------------

def _name_matches(name: Optional[str]) -> bool:
    if not name:
        return False
    return name == NAME_EXACT or NAME_CONTAINS in name


async def scan(timeout: float = 8.0, show_all: bool = False):
    from bleak import BleakScanner
    print("Scanning for %.0fs ..." % timeout)
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    hits = []
    for dev, adv in devices.values():
        matched = _name_matches(adv.local_name or dev.name)
        if matched or show_all:
            tag = "  <-- HHJ gadget" if matched else ""
            print("  %-40s  rssi=%-4s  %s%s"
                  % (dev.address, getattr(adv, "rssi", "?"),
                     adv.local_name or dev.name or "(no name)", tag))
            if matched:
                hits.append(dev)
    if not hits and not show_all:
        print("No HHJ gadget found (name == 'AAAAA' or containing 'br29'). "
              "Use --scan-all to list everything.")
    return hits


class HHJClient:
    """Central-side driver: connect -> authenticate -> stream NMEA."""

    def __init__(self, address: Optional[str] = None,
                 convert_gcj02: bool = True,
                 checksum: bool = False,
                 crlf: bool = False,
                 verbose: bool = True):
        self.address = address
        self.convert_gcj02 = convert_gcj02
        self.checksum = checksum
        self.crlf = crlf
        self.verbose = verbose
        self._client = None
        self._authed = asyncio.Event()

    async def _find_address(self) -> str:
        from bleak import BleakScanner
        if self.address:
            return self.address
        if self.verbose:
            print("Scanning for HHJ gadget ...")
        found = await BleakScanner.discover(timeout=8.0, return_adv=True)
        for dev, adv in found.values():
            if _name_matches(adv.local_name or dev.name):
                if self.verbose:
                    print("Found %s (%s)" % (dev.address, adv.local_name or dev.name))
                return dev.address
        raise RuntimeError("No HHJ gadget found; pass --address explicitly.")

    def _on_notify(self, _char, data: bytearray):
        try:
            text = bytes(data).decode("utf-8", "replace")
        except Exception:
            text = repr(bytes(data))
        if self.verbose:
            print("  notify <- %r" % text)
        if text.strip() == SUCCESS_VALUE:
            self._authed.set()

    async def __aenter__(self):
        from bleak import BleakClient
        addr = await self._find_address()
        self._client = BleakClient(addr)
        await self._client.connect()
        if self.verbose:
            print("Connected to %s" % addr)

        # Subscribe to the auth-notify characteristic, then write the handshake.
        await self._client.start_notify(AUTH_NOTIFY_UUID, self._on_notify)
        auth = build_auth_payload()
        if self.verbose:
            print("  auth  -> %r" % auth.decode())
        await self._client.write_gatt_char(AUTH_WRITE_UUID, auth, response=True)

        try:
            await asyncio.wait_for(self._authed.wait(), timeout=10.0)
            if self.verbose:
                print("Authenticated ('authSuc' received).")
        except asyncio.TimeoutError:
            print("WARNING: no 'authSuc' within 10s; continuing anyway "
                  "(some firmware never acks).", file=sys.stderr)
        return self

    async def __aexit__(self, *exc):
        if self._client is not None:
            try:
                await self._client.stop_notify(AUTH_NOTIFY_UUID)
            except Exception:
                pass
            await self._client.disconnect()
            if self.verbose:
                print("Disconnected.")

    async def send_fix(self, fix: Fix):
        payload = build_payload(fix, self.convert_gcj02, self.checksum, self.crlf)
        if self.verbose:
            print("  loc   -> %s" % payload.decode("utf-8", "replace"))
        # location characteristic uses write-without-response (type 1 in the app)
        await self._client.write_gatt_char(LOCATION_UUID, payload, response=False)

    async def stream(self, fixes: Iterable[Fix], interval: float = 1.0):
        for fix in fixes:
            await self.send_fix(fix)
            await asyncio.sleep(interval)


# ---------------------------------------------------------------------------
# Fix sources
# ---------------------------------------------------------------------------

def repeat_fix(lat: float, lon: float, alt: float) -> Iterable[Fix]:
    while True:
        yield Fix(lat=lat, lon=lon, alt=alt, when=time.time())


def track_from_csv(path: str, loop: bool = True) -> Iterable[Fix]:
    """Yield fixes from a CSV of 'lat,lon[,alt]' rows (header line optional)."""
    def rows():
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.lower().startswith("lat"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                lat = float(parts[0]); lon = float(parts[1])
                alt = float(parts[2]) if len(parts) > 2 and parts[2] else 0.0
                yield Fix(lat=lat, lon=lon, alt=alt, when=time.time())
    while True:
        yielded = False
        for fx in rows():
            yielded = True
            yield fx
        if not loop or not yielded:
            return


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def _amain(args) -> int:
    if args.scan or args.scan_all:
        await scan(timeout=args.scan_timeout, show_all=args.scan_all)
        return 0

    # Build the fix source.
    if args.track:
        fixes = track_from_csv(args.track, loop=not args.once)
    elif args.lat is not None and args.lon is not None:
        if args.once:
            fixes = [Fix(lat=args.lat, lon=args.lon, alt=args.alt, when=time.time())]
        else:
            fixes = repeat_fix(args.lat, args.lon, args.alt)
    else:
        print("Provide --lat/--lon, or --track FILE, or --scan.", file=sys.stderr)
        return 2

    convert = not args.no_gcj02

    if args.dry_run:
        # No BLE: just print the auth + location bytes the app would send.
        print("auth  -> %r" % build_auth_payload().decode())
        count = 0
        for fix in fixes:
            payload = build_payload(fix, convert, args.checksum, args.crlf)
            print("loc   -> %s" % payload.decode("utf-8", "replace"))
            count += 1
            if args.once or count >= args.dry_count:
                break
        return 0

    async with HHJClient(address=args.address,
                         convert_gcj02=convert,
                         checksum=args.checksum,
                         crlf=args.crlf) as client:
        if args.once:
            for fix in fixes:
                await client.send_fix(fix)
                break
        else:
            print("Streaming every %.1fs (Ctrl-C to stop)..." % args.interval)
            await client.stream(fixes, interval=args.interval)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description="Reimplementation of the HHJ Bluetooth GPS gadget protocol.")
    p.add_argument("--scan", action="store_true",
                   help="Scan and list matching HHJ gadgets, then exit.")
    p.add_argument("--scan-all", action="store_true",
                   help="Scan and list ALL BLE devices (marks HHJ matches).")
    p.add_argument("--scan-timeout", type=float, default=8.0)
    p.add_argument("--address", help="BLE address/UUID of the gadget (skip scan).")

    p.add_argument("--lat", type=float, help="Latitude (WGS-84 decimal degrees).")
    p.add_argument("--lon", type=float, help="Longitude (WGS-84 decimal degrees).")
    p.add_argument("--alt", type=float, default=0.0, help="Altitude in metres.")
    p.add_argument("--track", help="CSV file of 'lat,lon[,alt]' rows to stream.")

    p.add_argument("--interval", type=float, default=1.0,
                   help="Seconds between location writes (default 1.0).")
    p.add_argument("--once", action="store_true", help="Send a single fix and exit.")

    p.add_argument("--no-gcj02", action="store_true",
                   help="Do NOT apply the China WGS-84->GCJ-02 shift.")
    p.add_argument("--checksum", action="store_true",
                   help="Append NMEA *XX checksums (app does not).")
    p.add_argument("--crlf", action="store_true",
                   help="Separate/terminate sentences with CRLF (app does not).")

    p.add_argument("--dry-run", action="store_true",
                   help="Print the frames without any BLE I/O.")
    p.add_argument("--dry-count", type=int, default=3,
                   help="How many location frames to print in --dry-run.")

    args = p.parse_args()
    try:
        return asyncio.run(_amain(args))
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0
    except Exception as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
