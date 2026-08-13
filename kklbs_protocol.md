# KKlbs Bluetooth GPS — Reverse-Engineering Notes

Target: iOS app **KKlbs** (`com.lbs.KKlbs`, v3.6 build 29, Swift/arm64, decrypted).
Companion to the HHJ analysis in [`hhj_protocol.md`](hhj_protocol.md). Same product
category — a BLE gadget that receives an injected GPS position. Evidence is from
the app binary (`strings`, `otool -tvV`); addresses are file VM addresses.

## App

- Bundle `com.lbs.KKlbs`; permission strings: "使用蓝牙连接和调试硬件设备的参数"
  (use Bluetooth to connect/debug the hardware device's parameters).
- Core class **`KKlbs.BluetoothManager`** (`_TtC5KKlbs16BluetoothManager`), with
  ivars incl. `centralManager, discoveredPeripherals, connectedPeripheral,
  isAuthenticated, authenticationTimer, writeCharacteristic, writeType,
  targetServiceUUID, targetCharacteristicUUID, protocolVersion, pendingCommand,
  deviceInfo, isCheckingDeviceInfo, expectedDeviceInfoCount, lastUnAuthSendTime,
  unAuthSendInterval, reconnectAttempts, isAutoReconnecting`.

## GATT profile (confirmed)

Classic serial-module layout. UUIDs recovered from the three `+[CBUUID
UUIDWithString:]` calls at `0x100012704 / 0x1000128ec / 0x100012940` (Swift
small-string immediates → `"FFF1"`, `"FFF0"`, `"FFF2"`):

| Role | UUID |
|------|------|
| Service | `0000fff0-0000-1000-8000-00805f9b34fb` (FFF0) |
| Characteristic | `0000fff1-0000-1000-8000-00805f9b34fb` (FFF1) |
| Characteristic | `0000fff2-0000-1000-8000-00805f9b34fb` (FFF2) |

FFF1/FFF2 are the write and notify characteristics; the app selects them by
property at discovery time (`targetCharacteristicUUID`), so the web client picks
the writable one (write / write-without-response) and subscribes to the
notifying one rather than hard-coding which is which.

**Scan filter:** the device advertises a name starting with **`KKlbs`**
(literals `KKlbs`, `KKlbs1`, `KKlbs2`, `KKlbs3` in the binary).

## Location payload (confirmed format)

Format string at `0x10003dc20`, built via `String(format:)` at `0x1000140b0`,
written with `writeValue:forCharacteristic:type:` **type 1 (write without
response)** at `0x100014530`:

```
%02d%02d.%06d,%@,%03d%02d.%06d,%@,%@
  →  ddmm.mmmmmm,N,dddmm.mmmmmm,E,<field>
```

- Latitude `ddmm.mmmmmm` (degrees `%02d`, integer minutes `%02d`, fractional
  minutes `%06d`), longitude `dddmm.mmmmmm` (degrees `%03d`).
- `N`/`S` from `lat >= 0` (`0x4e`/`0x53`), `E`/`W` from `lon >= 0`
  (`0x45`/`0x57`) — the sign-select `csel`s at `0x100013fb0` / `0x100014060`.
- Minutes = `frac(deg) * 60`, `%06d` = the 6-digit fractional part × 1e6.

This is the same NMEA-style `ddmm.mmmmmm` coordinate as HHJ, but sent as a bare
5-field CSV rather than full `$GPGGA/$GPRMC` sentences, and with **no secret
handshake**.

## Authentication

Unlike HHJ (which writes `"<ts>_dsfds123"` and waits for `"authSuc"`), KKlbs has
**no secret-key handshake**. `isAuthenticated` is driven by a device-info /
`protocolVersion` query (`deviceInfo`, `expectedDeviceInfoCount`), and the
manager can send location even before that completes, rate-limited via
`lastUnAuthSendTime` / `unAuthSendInterval`. So the web client treats "write
characteristic found" as ready and simply streams the coordinate string.

## Confidence

- **Confirmed (byte-verified):** the FFF0/FFF1/FFF2 UUIDs, the `KKlbs*` name
  filter, the `%02d%02d.%06d,%@,%03d%02d.%06d,%@,%@` coordinate format, the
  N/S/E/W sign logic, write-without-response, and the absence of a secret
  handshake.
- **Best-effort:** the exact trailing `%@` field (the web client sends the
  altitude there) and whether the write carries any additional wrapper — the app
  assembles the payload via `Array<String>.joined(separator:"")` with heavy
  interleaved debug logging that obscures the final framing. The web client's
  **Wire log** shows the exact bytes it sends, so this is easy to confirm and
  adjust against a real device.

## Web client support

`index.html` supports both gadgets from one **Connect** button:
- `requestDevice` filters include `AAAAA` / `br29` / auth-service (HHJ) **and**
  `KKlbs*` / FFF0 (KKlbs).
- After connect it enumerates primary services and **auto-detects**: `faa1`
  present → HHJ path (secret handshake), else `fff0` → KKlbs path (discover
  write+notify chars, no handshake). The detected type is shown next to the
  device name.
- Injection uses the active type's encoder; the China GCJ-02 toggle applies to
  both. NMEA checksum/CRLF options are HHJ-only.
