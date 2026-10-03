#!/usr/bin/env python3
"""
control.py — encrypted LAN control of a paired breezer using the saved token.

Prereq: the device is on your home Wi-Fi (pair.py done) and asp100.token sits
next to these scripts. Run this on the same LAN as the breezer.

Flow (all on the home LAN, protocol 2 / encrypted):
  1. discover the device -> ip, port 41122, current pubkey
  2. fresh ECDH session (same Session crypto as pairing)
  3. handshake presenting the SAVED token (non-zero) -> device authenticates us
  4. TimeSync, then listen: the device pushes its current state as Cmd* frames
  5. optionally send a command (fan speed / program / target temp / backlight auto-off) and watch the echo

Read-by-default and safe; it only writes if you pass a --set-* flag.
Programs (--set-mode): 0=Off 1=Manual 2=Auto 3=Night 4=Turbo 5=Fan.

Requirements: pip install zeroconf cryptography

Examples:
    python control.py                                  # read state (only device on LAN)
    python control.py --set-speed 2                    # fan speed (Manual program)
    python control.py --set-mode 4                     # Turbo program (~15 min)
    python control.py --set-target-temp 23.5
"""

import argparse
import socket
import struct
import sys
import time

from asp100_proto import Session, parse_handshake_reply, discover, token_path, TYPE_CMD

CMD_TIMESYNC = 0x80


# ---- value decoders (from app/api/commands/*) ----
def dec_u8(p):   return p[0] if p else None
def dec_bool(p): return bool(p[0]) if p else None

def dec_temp(p):
    if len(p) < 2:
        return None
    deg, b1 = p[0], p[1]
    val = deg + (b1 & 0x7F) / 100.0
    return -val if (b1 & 0x80) else val

def dec_u16le(p):
    return struct.unpack("<H", p[:2])[0] if len(p) >= 2 else (p[0] if p else None)

def dec_u32le(p): return struct.unpack("<I", p[:4])[0] if len(p) >= 4 else None
def dec_hex(p):   return p.hex()

# opcode -> (name, decoder).  Signed Java bytes shown as their unsigned hex.
COMMANDS = {
    0x01: ("Mode", dec_u8),
    0x02: ("TargetTemperature", dec_temp),
    0x03: ("TargetTime", dec_u32le),
    0x07: ("Error", dec_u8),
    0x09: ("Volume", dec_u8),
    0x0B: ("Amount", dec_u16le),
    0x0F: ("Speed", dec_u8),
    0x12: ("TargetHumidity", dec_u8),
    0x13: ("CurrentHumidity", dec_u8),
    0x14: ("CurrentTemperature", dec_temp),
    0x16: ("CurrentCo2", dec_u16le),
    0x18: ("Ionization", dec_bool),
    0x1A: ("TotalTime", dec_u16le),
    0x1C: ("Backlight", dec_u8),
    0x1E: ("ChildLock", dec_bool),
    0x20: ("CurrentPm2", dec_u16le),
    0x22: ("Expendables/filter", dec_u8),
    0x26: ("Damper", dec_u8),
    0x29: ("Bss", dec_u8),
    0x31: ("Turbo", dec_bool),
    0x32: ("Night", dec_bool),
    0x42: ("ProgramData", dec_hex),
    0x85: ("AccessControl", dec_u8),
    0x89: ("DeviceType", dec_u16le),
    0x91: ("Status/info", dec_hex),
}


def decode_cmd(cmd, payload):
    name, dec = COMMANDS.get(cmd, (None, None))
    if name is None:
        return f"cmd 0x{cmd:02x} = <unknown> raw={payload.hex()}"
    try:
        val = dec(payload)
    except Exception:
        val = None
    return f"{name:<20} (0x{cmd:02x}) = {val}    raw={payload.hex()}"


def pump(sock, dest, sess, duration, state):
    """Receive+ACK+decode CMD frames for `duration` seconds; fill `state` dict."""
    end = time.time() + duration
    sock.settimeout(0.6)
    while time.time() < end:
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            continue
        parsed = sess.parse_frame(data)
        if not parsed:
            continue
        seq, ftype, inner = parsed
        if ftype != TYPE_CMD or not inner:
            continue
        sock.sendto(sess.build_ack(seq), dest)
        cmd, payload = inner[0], inner[1:]
        if cmd in (0x00, CMD_TIMESYNC):   # handshake echo / timesync ack
            continue
        line = decode_cmd(cmd, payload)
        if cmd not in state:
            print("   " + line)
        state[cmd] = payload


def main():
    ap = argparse.ArgumentParser(description="Encrypted LAN control of a paired ASP-100.")
    ap.add_argument("--mac", help="device MAC (optional if only one on the LAN)")
    ap.add_argument("--token", default=token_path(), help="path to saved token (default: asp100.token next to this script)")
    ap.add_argument("--read-secs", type=float, default=4.0, help="how long to listen for state (default 4s)")
    ap.add_argument("--set-speed", type=int, help="set fan speed 1-7 (CmdSpeed 0x0F)")
    ap.add_argument("--set-mode", type=int, help="program (CmdMode 0x01): 0=Off 1=Manual 2=Auto 3=Night 4=Turbo 5=Fan")
    ap.add_argument("--set-target-temp", type=float, help="set target temperature °C (CmdTargetTemperature 0x02)")
    ap.add_argument("--set-backlight", type=int, choices=(0, 1), help="auto-off indication: 1=enable, 0=disable (CmdBacklight 0x1C)",)
    ap.add_argument("--no-timesync", action="store_true")
    args = ap.parse_args()

    try:
        token = bytes.fromhex(open(args.token).read().strip())
    except FileNotFoundError:
        sys.exit(f"Token file {args.token} not found. Run Stage 1 pairing first.")
    if len(token) != 16:
        sys.exit(f"Token must be 16 bytes, got {len(token)}.")

    print(f"[1] Discovering {args.mac or 'device'} on the LAN …")
    dev = discover(args.mac, timeout=12)
    if not dev:
        sys.exit("    Not found. Same Wi-Fi? Correct --mac?")
    print(f"    mac={dev.get('mac')} ip={dev['ip']} port={dev['port']} protocol={dev['protocol']} fw={dev['firmware']}")
    if dev["protocol"] < 2 or len(dev["pubkey"]) != 64:
        sys.exit("    Expected encrypted protocol-2 device on the LAN.")

    sess = Session(bytes.fromhex(dev["pubkey"]))
    dest = (dev["ip"], dev["port"])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)

    # 2) handshake WITH the saved token (authenticate)
    print("\n[2] Handshake with saved token (authenticating) …")
    hs = sess.build_handshake(token)
    reply = None
    for attempt in range(1, 7):
        sock.sendto(hs, dest)
        try:
            while True:
                data, _ = sock.recvfrom(4096)
                parsed = sess.parse_frame(data)
                if not parsed:
                    continue
                s, ft, inner = parsed
                if ft == TYPE_CMD and inner:
                    sock.sendto(sess.build_ack(s), dest)
                    if inner[0] == 0x00:
                        reply = parse_handshake_reply(inner)
                        break
            if reply:
                break
        except socket.timeout:
            print(f"    … no reply ({attempt}/6)")
    if not reply:
        sys.exit("    No handshake reply.")
    if not any(reply["token"]):
        sys.exit("    Device returned ZERO token = auth REJECTED. Token wrong/stale? Re-pair.")
    print(f"    AUTHENTICATED ✓  protocol={reply['protocol']} fw={reply['firmware']} mode={reply['mode']}")

    seq = 1
    if not args.no_timesync:
        off_min = -(time.timezone // 60) if not time.daylight else -(time.altzone // 60)
        sock.sendto(sess.build_encrypted_cmd(CMD_TIMESYNC, struct.pack("<ih", int(time.time()), off_min), seq), dest)
        seq += 1

    # 3) read current state
    print(f"\n[3] Listening {args.read_secs}s for device state …")
    state = {}
    pump(sock, dest, sess, args.read_secs, state)

    # 4) optional writes
    def send_cmd(cmd, payload, label):
        nonlocal seq
        print(f"\n[4] Sending {label} …")
        sock.sendto(sess.build_encrypted_cmd(cmd, payload, seq), dest)
        seq += 1
        time.sleep(0.3)
        pump(sock, dest, sess, 3.0, {})   # watch the echo/new state

    if args.set_speed is not None:
        send_cmd(0x0F, bytes([args.set_speed & 0xFF]), f"CmdSpeed={args.set_speed}")
    if args.set_mode is not None:
        send_cmd(0x01, bytes([args.set_mode & 0xFF]), f"CmdMode={args.set_mode}")
    if args.set_target_temp is not None:
        t = args.set_target_temp
        b0 = int(abs(t))
        b1 = int(round((abs(t) - b0) * 100)) & 0x7F
        if t < 0:
            b1 |= 0x80
        send_cmd(0x02, bytes([b0, b1]), f"CmdTargetTemperature={t}")
    if args.set_backlight is not None:
        send_cmd(0x1C, bytes([args.set_backlight]), f"CmdBacklight={args.set_backlight}",)
    print("\n[done]")


if __name__ == "__main__":
    main()
