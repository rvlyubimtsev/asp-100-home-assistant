# Syncleo / Ballu breezer local protocol

Technical description of the local (LAN) protocol used by Ballu ASP-100 /
Electrolux EASP-100 breezers on the Syncleo IoT platform, reconstructed by
observing the official app's behaviour. The reference implementation is
[`tools/asp100_proto.py`](tools/asp100_proto.py).

All multi-byte integers are **little-endian** unless noted. Transport is **UDP**.

---

## 1. Discovery (mDNS / DNS-SD)

Devices advertise the service type **`_syncleo._udp`**. Resolving a service gives:

- the device **IPv4/IPv6 address** and the **control port** (from the SRV record;
  observed value `41122`, but always read it from SRV — it is not hardcoded);
- a set of **TXT records** describing the device:

| TXT key | Meaning |
|---------|---------|
| `macaddr` | MAC address (device identity) |
| `vendor` | platform vendor string |
| `devtype` | model/type id (ASP-100 = `69`) |
| `protocol` | protocol version (`1` = plaintext, `≥2` = encrypted) |
| `curve` | ECDH curve id (`29` = Curve25519/X25519) |
| `public` | device X25519 public key, hex, 32 bytes (big-endian, see §2) |
| `pairing` | advertised pairing state (present in SoftAP mode) |
| `firmware`, `basetype` | informational |

If `protocol ≥ 2` but `curve ≠ 29` or the public key is not 32 bytes, treat the
device as plaintext (`protocol 1`).

## 2. Session crypto (protocol ≥ 2)

Each connection establishes a fresh session:

1. Generate an **ephemeral X25519 key pair**.
2. Compute the shared secret. **Three byte-reversals are required** (the device
   represents keys big-endian while standard X25519 is little-endian):
   - reverse the device's advertised public key before the exchange;
   - reverse your own public key before sending it to the device;
   - reverse the shared secret before hashing.
   ```
   shared  = X25519(ephemeral_priv, reverse(device_pub))
   digest  = SHA256(reverse(shared))          # 32 bytes
   ```
3. Split the digest into two 16-byte halves:
   ```
   H0 = digest[0:16]
   H1 = digest[16:32]
   ```
4. **Directional AES-128-CBC keys** (app ↔ device use opposite halves):
   - **app → device:** key `H1`, IV `H0`
   - **device → app:** key `H0`, IV `H1`
5. Per frame, the key and IV are **left-rotated by the sequence number**:
   - key rotated by `seq & 0x0F` bytes
   - IV rotated by `(seq >> 4) & 0x0F` bytes

Normal command payloads use **PKCS#7** padding. The handshake's inner token uses
**no padding** (it is exactly one 16-byte block).

## 3. Framing

Every datagram is one frame:

```
[ seq : 1 ][ type : 1 ][ length : 2 (LE) ][ payload : length ]
```

`type` byte on the wire:

| value | frame |
|-------|-------|
| `0x00` | ACK |
| `0x01` | CMD (data / handshake; length ≥ 1) |
| `0x02` | AUX |
| `0xFF` | NAK |

- Sequence numbers increment `(n + 1) & 0xFF`; the first frame is `seq = 0`.
- For **CMD** frames (protocol ≥ 2) the payload is `AES( [seq][cmd][cmd_payload] )`.
  On receipt, decrypt, verify the first plaintext byte equals `seq`, strip it, and
  you are left with `[cmd][cmd_payload]`.
- Every received CMD frame must be **ACK**'d: send a frame with the same `seq`,
  `type = 0x00`, and an (encrypted) empty payload.
- The **handshake** CMD frame is special — see §4.

## 4. Handshake, pairing, and authentication

The handshake is `cmd = 0x00`. Its CMD frame is **not** wrapped in the normal
frame-level encryption; instead the payload is built directly:

```
[ 0x00 ][ app_public_key : 32 ][ AES-NoPadding(key=H1, iv=H0, token) : 16 ]
```

- **Pairing:** send an all-zero 16-byte token. A device in pairing mode mints and
  returns a fresh token.
- **Authentication:** send your stored token to prove ownership.

The device replies with a normal encrypted CMD frame (`cmd = 0x00`) whose
decrypted body is:

```
[ protocol : 2 (LE) ][ fw_major : 1 ][ fw_minor : 1 ][ mode : 1 ][ token : 16 ]
```

A **non-zero** returned token means success. A **zero** token means auth
required / rejected (e.g. wrong token, or the device is bound and not in pairing
mode). The token is a permanent per-device credential; store it and replay it on
every future connect. A factory reset wipes it and re-opens pairing.

After a successful handshake the app sends a **TimeSync** command
(`cmd = 0x80`), payload `int32(unix_seconds) + int16(tz_offset_minutes)`.

## 5. Commands

Inside a CMD frame the plaintext is `[cmd][cmd_payload]`. The same opcode is used
to read state (device → app) and to set it (app → device).

Common opcodes:

| cmd | name | payload |
|----:|------|---------|
| `0x01` | Mode / **program** | 1 byte (see §6) |
| `0x02` | Target temperature | 2 bytes, fixed-point |
| `0x0F` | Fan speed | 1 byte (1–7) |
| `0x14` | Current temperature | 2 bytes, fixed-point |
| `0x13` | Current humidity | 1 byte % |
| `0x16` | CO₂ | 2 bytes |
| `0x20` | PM2.5 | 2 bytes |
| `0x22` | Filter life | 1 byte % |
| `0x07` | Error | 1 byte |
| `0x1C` | Auto-off indication | 1 byte bool (`1` = enable auto-off, `0` = disable) |
| `0x1E` | Child lock | 1 byte bool |
| `0x00` | Handshake | see §4 |
| `0x80` | TimeSync | see §4 |
| `0xFF` | Ping (keepalive) | empty |

**Temperature (2 bytes):**
```
byte0 = integer degrees (absolute value)
byte1 = round(fraction * 100); bit 7 (0x80) set => negative
value = (byte0 + (byte1 & 0x7F)/100) * (byte1 & 0x80 ? -1 : +1)
```
e.g. `22.5 °C` → `16 32`; `-3.2 °C` → `03 A0`.

## 6. Programs (operating modes)

The breezer's operating mode is selected via `cmd = 0x01`:

| value | program |
|------:|---------|
| 0 | Off (fan stops) |
| 1 | Manual — fan speed 1–7 is user-controllable |
| 2 | Auto |
| 3 | Night |
| 4 | **Turbo** — max speed, firmware runs it ~15 min (a timer counts down) then reverts |
| 5 | Fan |

So "power off" is `cmd 0x01 → 0`, and "turbo" is `cmd 0x01 → 4` (not a fan speed
and not a separate opcode). Fan speed (`0x0F`) is meaningful in Manual.

## 7. SoftAP onboarding + Wi-Fi provisioning

A factory-reset unit hosts its own Wi-Fi access point and still speaks the
encrypted protocol there (at the AP gateway, port `41122`). Onboarding while
joined to that AP:

1. Discover the device (mDNS works on the AP too), do the §2/§4 pairing handshake
   with a zero token, and **capture the returned token**.
2. Send the Wi-Fi-config command (`cmd = 0x82`) as a normal encrypted frame:
   ```
   [ bssid : 6 ][ ssid_len : 1 ][ ssid ][ pwd_len : 1 ][ password ]
   ```
   `bssid` may be `FF FF FF FF FF FF` to mean "any AP with this SSID".
3. The device reboots, joins your Wi-Fi, and reappears on the LAN via mDNS.

From then on, control happens on the home LAN using the captured token (§4).
