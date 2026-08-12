# HHJ Bluetooth GPS Gadget — Reverse-Engineering & Protocol

Target: iOS app **HHJ** (`CFBundleIdentifier = sidvuwennfnwe.sadjcjas.bbnhh`,
executable **`MapBlue`**, v4.0.0, Swift/arm64). Analysis is from the decompiled
binary (`MapBlue.c`, Ghidra) cross-checked against the raw Mach-O
(`MapBlue.app/MapBlue`, verified with `otool -tvV`). Line numbers below refer to
`MapBlue.c`; addresses are file VM addresses.

The companion script **`hhj_gps.py`** reimplements everything here and can be
inspected with `--dry-run` (no hardware needed).

---

## 1. What the product is

A "white-label" location gadget: a cheap **BLE peripheral** paired with a
rebrandable phone app. The phone is the BLE **central**; it reads its own GPS
(or a point the user drops on the map) and **streams that location to the gadget
as ASCII NMEA-0183 sentences**. The gadget then re-emits/consumes the position
(e.g. presents itself as an external GPS to other equipment, or announces the
coordinates — the app's Chinese permission strings literally say it uses
Bluetooth "to transmit your location data" and needs location "to obtain
lat/lng for broadcast").

Evidence:
- `Info.plist`: `NSBluetoothAlwaysUsageDescription`,
  `NSLocationAlwaysAndWhenInUseUsageDescription`, `LSApplicationQueriesSchemes = baidumap`.
- Frameworks: Realm (local storage), SnapKit/Masonry/MJRefresh/YYText (UI).
- Source paths leaked in strings: `/Users/mengmeng/Desktop/HHJ/project3/MapBlue/Modules/{Home,Index,Setting,Collect,Privacy,Statement}/...`.
- The core class is Swift **`MapBlue.BlueService`** (`_TtC7MapBlue11BlueService`).

---

## 2. GATT profile

Two services, five UUIDs. The base is non-standard (`…8a12fb` / `…8c12ab`
instead of the SIG `…9b34fb`). Mapping recovered from `BlueService.init`
(`FUN_10001d8a8`, disassembly `0x10001d8c8`–`0x10001dacc`, literal-pool comments
resolved by `otool`):

| Role (ivar) | UUID | Use |
|---|---|---|
| `authServiceUUID` | `0000faa1-0000-1000-8000-00805f8c12ab` | Auth service |
| `authWriteCharacteristicUUID` | `000021e1-0000-1000-8000-00805f8a12fb` | Write (with response) — send handshake |
| `authNotifyCharacteristicUUID` | `000021e2-0000-1000-8000-00805f8a12fb` | Notify — receive `authSuc` |
| `dataServiceUUID` | `0000fbb2-0000-1000-8000-00805f8c12ab` | Data service |
| `locationCharacteristicUUID` | `000032e1-0000-1000-8000-00805f8a12fb` | Write (without response) — stream NMEA |

Two embedded secrets (Swift small-strings, `0x10001da0c`–`0x10001da44`):

- `secretKey = "dsfds123"`  (ivar `secretKey`)
- `sucValue  = "authSuc"`   (ivar `sucValue`)

---

## 3. Connection & authentication state machine

`BlueService` is a `CBCentralManagerDelegate` + `CBPeripheralDelegate`.

1. **Scan** — `scanForPeripheralsWithServices: nil` (no service filter; line 31242),
   so it discovers *all* peripherals and filters by advertised name.
2. **Filter** (`FUN_100022444`, the `didDiscoverPeripheral` body, lines 34270–34294):
   read `peripheral.name`; **keep it only if `name == "AAAAA"` or `name` contains
   `"br29"`** (constants `0x4141414141`/count 5 = `"AAAAA"`, `0x39327262`/count 4 =
   `"br29"`). Matches are added to `discoveredDevices` and shown for the user to pick.
3. **Connect** → `didConnectPeripheral` (line 33038) → `discoverServices`.
4. **Discover characteristics** (`peripheral_didDiscoverCharacteristicsForService`,
   real body `FUN_100021388`, lines 33310–33474):
   - For the **auth service** (`faa1`): iterate characteristics —
     - if UUID == `authWrite` (`21e1`) → **write the handshake** (`FUN_10001ee08`);
     - if UUID == `authNotify` (`21e2`) **and** it has the Notify property
       (`properties & 0x10`) → `setNotifyValue:true`.
   - For the **data service** (`fbb2`): store the location characteristic
     (`32e1`) into `locationCharacteristic`.
5. **Handshake write** (`FUN_10001ee08`, lines 31823–31876):
   ```
   ts      = Int(Date().timeIntervalSince1970)     // unix epoch seconds
   payload = "\(ts)" + "_" + secretKey             // e.g. "1723526400_dsfds123"
   peripheral.writeValue(payload.utf8, authWrite, .withResponse)   // type 0
   ```
   (The timestamp makes each handshake unique — a light anti-replay measure.)
6. **Success** (`didUpdateValueForCharacteristic`, real body `FUN_100021388`,
   lines 33628–33666): when the value on `authNotify` decoded as UTF-8 **equals
   `"authSuc"`**, set `isConnect = true`, invalidate the reconnect timer, and post
   the `blueNotification`. The gadget is now connected and ready for location.
7. **Reconnect**: a `reconnectTimer` retries while `isConnecting`.

---

## 4. Location payload (the "protocol" proper)

### 4.1 Coordinate → NMEA field
`FUN_100055960` (formatter, disasm `0x100055960`–`0x100055a78`) converts one
decimal-degree value to an NMEA `ddmm.mmmmmm` field:

```
deg     = (long)value                       # truncate toward zero
minutes = |frac(value)| * 60.0
field   = "%02d%09.6f" % (|deg|, minutes)   # format string @ 0x100055a38: "%02d%09.6f"
if field.startswith("0"): field = field[1:] # hasPrefix("0") -> removeFirst()
```
So `31.230416 → "3113.824960"`, `121.473701 → "12128.422060"`. (The leading-zero
strip is a quirk that only affects single-degree latitudes; reproduced faithfully.)

### 4.2 China shift (WGS-84 → GCJ-02)
Caller `FUN_10005601c` / `FUN_100055b04` (lines 71837, 71539). If the point is
inside the box **lon ∈ (72.004, 137.8347), lat ∈ (0.8293, 55.8271)**, it applies
the standard GCJ-02 offset (`FUN_100034b04`, lines 47952–47971 — the textbook
`a=6378137.0`, `ee=0.00669342162296594323` delta calc) before formatting. Outside
China the coordinate is sent unshifted. It also derives `N`/`S` from
`lat >= 0` and `E`/`W` from `lon >= 0` (`0x4e/0x53`, `0x45/0x57`).

### 4.3 Sentence assembly
`FUN_10001f9cc` (lines 32327–32619) builds **two** sentences into one string and
writes them to `locationCharacteristic` with **write-without-response** (type 1,
line 32608). Literal fragments decoded from the builder:

```
$GPGGA,<utc>,<lat>,<N|S>,<lon>,<E|W>,1,09,0.6,<alt>,M,-27.0,M,,
$GPRMC,<utc>,A,<lat>,<N|S>,<lon>,<E|W>,0.0,0.0,<ddmmyy>,0.0,E,A
```
- GGA fixed fields decoded verbatim: fix quality `1`, satellites `09`, HDOP `0.6`,
  altitude units `M`, geoid separation `-27.0`, units `M`, empty DGPS fields.
- RMC: status `A` (valid), speed/course, date, magnetic variation `0.0,E`, mode `A`.
- **The app appends no `*` checksum and no CRLF** — the two sentences are written
  back-to-back in a single UTF-8 GATT write. The gadget's firmware is lenient
  (splits on `$`). `hhj_gps.py` matches this by default; `--checksum`/`--crlf`
  produce standards-compliant output for strict parsers.

Location is (re)sent on every Core Location update / map interaction
(`HomeIndexViewController.locationManager:didUpdateLocations:`, line 37596, and
the map-drag dispatcher), i.e. roughly once per second while active.

---

## 5. End-to-end sequence

```
Central (phone/script)                     Peripheral (gadget, name "AAAAA"/*br29*)
  | scan (no filter), keep name match         |
  | connect ------------------------------->  |
  | discover services/characteristics ----->  |
  | subscribe notify 000021e2 ------------->  |
  | write "1723526400_dsfds123" -> 000021e1 ->|  (with response)
  | <----------- notify "authSuc" on 000021e2 |  => isConnect = true
  | write "$GPGGA,...$GPRMC,..." -> 000032e1 ->|  (no response, ~1 Hz)
  | ... repeat per location update ...         |
```

---

## 6. `hhj_gps.py` — usage

```bash
pip install bleak

python3 hhj_gps.py --scan                                  # find the gadget
python3 hhj_gps.py --lat 31.230416 --lon 121.473701        # stream a fixed point (~1 Hz)
python3 hhj_gps.py --address <MAC/UUID> --lat 31.23 --lon 121.47
python3 hhj_gps.py --track track.csv                       # stream "lat,lon[,alt]" rows
python3 hhj_gps.py --lat 31.23 --lon 121.47 --dry-run      # print exact frames, no BLE
```

Flags: `--no-gcj02` (skip China shift), `--checksum` / `--crlf` (strict NMEA),
`--once`, `--interval SEC`, `--scan-all`.

The script mirrors the app exactly: same UUIDs, same `"<ts>_dsfds123"` handshake,
waits for `"authSuc"`, same `%02d%09.6f` coordinate formatting, same GCJ-02 guard,
same GGA+RMC layout and write types.

---

## 7. Confidence notes

- **Exact (byte-verified against the binary):** all 5 UUIDs and their roles,
  `secretKey`/`sucValue`, the `"<ts>_" + secretKey` handshake, the `"authSuc"`
  success check, the `%02d%09.6f` formatter + leading-zero strip, the China box,
  the GCJ-02 constants, the `$GPGGA`/`$GPRMC` fixed fillers, write types, the
  `"AAAAA"`/`"br29"` scan filter, and the no-checksum/no-CRLF framing.
- **Reconstructed (sensible reading of the decompiler):** the precise source of
  the UTC-time and date fields (the app pulls them from a shared date formatter;
  the script fills them from the system clock, which is what a valid sentence
  needs) and the exact speed/course values (defaulted to `0.0`). None of these
  affect the fields the gadget keys on (lat/lon/N-S/E-W). The GCJ-02 direction is
  addition (`gcj = wgs + delta`), matching the standard `wgs84ToGcj02` the app
  bundles (`JZLocationConverter`, lines 10404+); the decompiler renders the
  struct-return math as a subtraction, an artifact of register aliasing.

### Ethics / scope
This documents a device-companion protocol for interoperability and analysis.
Feeding fabricated coordinates into systems that rely on genuine location
(safety, compliance, anti-fraud, or "trust" checks) may be illegal or against
terms of service — use only with hardware you own and are authorized to test.
