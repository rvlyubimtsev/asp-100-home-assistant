"""ASP-100 command opcodes + value decoders/encoders.

Opcodes from AppCommandParser.decodeUdp(); value formats from the Cmd* classes.
Verified live: temperatures are 2-byte fixed-point; speed/mode are single bytes.
"""

from __future__ import annotations

import struct

# writable + readable opcodes
CMD_MODE = 0x01
CMD_TARGET_TEMPERATURE = 0x02
CMD_TARGET_TIME = 0x03
CMD_ERROR = 0x07
CMD_VOLUME = 0x09
CMD_AMOUNT = 0x0B
CMD_SPEED = 0x0F
CMD_TARGET_HUMIDITY = 0x12
CMD_CURRENT_HUMIDITY = 0x13
CMD_CURRENT_TEMPERATURE = 0x14
CMD_CURRENT_CO2 = 0x16
CMD_IONIZATION = 0x18
CMD_TOTAL_TIME = 0x1A
CMD_BACKLIGHT = 0x1C
CMD_CHILD_LOCK = 0x1E
CMD_CURRENT_PM2 = 0x20
CMD_EXPENDABLES = 0x22  # filter life %
CMD_DAMPER = 0x26
CMD_BSS = 0x29
CMD_NIGHT = 0x32
# turbo is program 4 (CmdMode 0x01), not a standalone opcode on this device


def _u8(p):
    return p[0] if p else None


def _bool(p):
    return bool(p[0]) if p else None


def _u16le(p):
    return struct.unpack("<H", p[:2])[0] if len(p) >= 2 else (p[0] if p else None)


def decode_temp(p) -> float | None:
    """2-byte fixed-point: [int_deg][frac+sign], bit7 of byte1 = negative."""
    if len(p) < 2:
        return None
    deg, b1 = p[0], p[1]
    val = deg + (b1 & 0x7F) / 100.0
    return -val if (b1 & 0x80) else val


def encode_temp(t: float) -> bytes:
    b0 = int(abs(t))
    b1 = int(round((abs(t) - b0) * 100)) & 0x7F
    if t < 0:
        b1 |= 0x80
    return bytes([b0, b1])


# opcode -> (state_key, decoder).  state_key is what coordinator.data is keyed by.
DECODERS: dict[int, tuple[str, callable]] = {
    CMD_MODE: ("mode", _u8),
    CMD_TARGET_TEMPERATURE: ("target_temperature", decode_temp),
    CMD_ERROR: ("error", _u8),
    CMD_SPEED: ("speed", _u8),
    CMD_TARGET_HUMIDITY: ("target_humidity", _u8),
    CMD_CURRENT_HUMIDITY: ("current_humidity", _u8),
    CMD_CURRENT_TEMPERATURE: ("current_temperature", decode_temp),
    CMD_CURRENT_CO2: ("co2", _u16le),
    CMD_IONIZATION: ("ionization", _bool),
    CMD_CHILD_LOCK: ("child_lock", _bool),
    CMD_CURRENT_PM2: ("pm25", _u16le),
    CMD_EXPENDABLES: ("filter", _u8),
    CMD_DAMPER: ("damper", _u8),
    CMD_NIGHT: ("night", _bool),
    CMD_BACKLIGHT: ("backlight", _bool),
}


def decode_state(frames: dict[int, bytes]) -> dict[str, object]:
    """Turn {opcode: payload} into {state_key: value}."""
    out: dict[str, object] = {}
    for cmd, payload in frames.items():
        if cmd in DECODERS:
            key, dec = DECODERS[cmd]
            try:
                out[key] = dec(payload)
            except Exception:
                pass
    return out
