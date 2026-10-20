#!/usr/bin/env python3
"""Regenerates the committed GRIDSHOCK WAV/PNG assets.

Run from the repository root:
    python tools/gridshock_assets.py

The generated files are committed so a Gradle build never needs Python. This helper is
reproducible and offline; it uses only the standard library. The frozen delivery contract
(22050 Hz mono 16-bit PCM, target sizes, sprite dimensions) is checked by
GridshockEffectsTest.
"""
import math
import os
import random
import struct
import wave
import zlib

RATE = 22050
RAW = os.path.join("app", "src", "main", "res", "raw")
SPRITES = os.path.join("app", "src", "main", "res", "drawable-nodpi")


def write_wav(name, samples):
    os.makedirs(RAW, exist_ok=True)
    data = b"".join(
        struct.pack("<h", int(max(-1.0, min(1.0, value)) * 32767)) for value in samples
    )
    with wave.open(os.path.join(RAW, name), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(RATE)
        output.writeframes(data)


def envelope(count, attack=0.005, release=0.05):
    attack_frames = max(1, int(attack * RATE))
    release_frames = max(1, int(release * RATE))
    return [min(1.0, i / attack_frames, (count - i) / release_frames) for i in range(count)]


def tone(freq, ms, amp=0.5):
    count = int(RATE * ms / 1000)
    env = envelope(count)
    return [amp * env[i] * math.sin(2 * math.pi * freq * i / RATE) for i in range(count)]


def sweep(start, end, ms, amp=0.5):
    count = int(RATE * ms / 1000)
    env = envelope(count)
    phase = 0.0
    out = []
    for i in range(count):
        freq = start * (end / start) ** (i / max(1, count - 1))
        phase += 2 * math.pi * freq / RATE
        out.append(amp * env[i] * math.sin(phase))
    return out


def noise(ms, amp=0.3, lowpass=1.0):
    count = int(RATE * ms / 1000)
    env = envelope(count)
    rnd = random.Random(5)
    out = []
    previous = 0.0
    for i in range(count):
        value = rnd.uniform(-1, 1)
        previous += (value - previous) * lowpass
        out.append(amp * env[i] * previous)
    return out


def mix(first, second, gain=1.0):
    count = max(len(first), len(second))
    out = []
    for i in range(count):
        value = (first[i] if i < len(first) else 0.0)
        value += (second[i] if i < len(second) else 0.0) * gain
        out.append(max(-1.0, min(1.0, value)))
    return out


def arpeggio(notes, ms, amp=0.4):
    out = []
    for freq in notes:
        out += tone(freq, ms, amp)
    return out


def write_png(path, width, height, rows):
    raw = b"".join(b"\x00" + row for row in rows)

    def chunk(tag, data):
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    data = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )
    with open(path, "wb") as output:
        output.write(data)


def glow(size):
    rows = []
    centre = (size - 1) / 2
    for y in range(size):
        row = bytearray()
        for x in range(size):
            radius = math.hypot(x - centre, y - centre) / (size / 2)
            alpha = 0 if radius >= 1 else int(255 * ((1 - radius) ** 2.2))
            row += bytes((255, 255, 255, alpha))
        rows.append(bytes(row))
    write_png(os.path.join(SPRITES, "glow_%d.png" % size), size, size, rows)


def main():
    write_wav("place.wav", mix(tone(880, 45, 0.35), noise(10, 0.05)))
    write_wav("clear.wav", mix(noise(200, 0.25, 0.4), tone(440, 200, 0.25), 0.6))
    write_wav("combo.wav", sweep(660, 990, 180, 0.35))
    write_wav(
        "overload.wav",
        mix(
            sweep(1200, 180, 420, 0.35),
            [
                0.3 * (1 if i % max(1, int(RATE / 60)) < int(RATE / 120) else -1) * 0.1
                for i in range(int(RATE * 0.42))
            ],
        ),
    )
    write_wav("perfect.wav", arpeggio([523, 659, 784, 1047], 90, 0.3))
    write_wav("corrupt.wav", noise(160, 0.4, 0.8))
    write_wav("gameover.wav", mix(sweep(440, 220, 900, 0.3), tone(220, 900, 0.12)))
    write_wav("ui_tap.wav", tone(1400, 18, 0.25))

    os.makedirs(SPRITES, exist_ok=True)
    glow(64)
    glow(128)
    glow(256)
    rows = []
    centre = 127.5
    for y in range(256):
        row = bytearray()
        for x in range(256):
            radius = math.hypot(x - centre, y - centre) / 181.0
            alpha = int(min(0xB0, max(0.0, (radius - 0.35) / 0.65) * 0xB0))
            row += bytes((0, 0, 0, alpha))
        rows.append(bytes(row))
    write_png(os.path.join(SPRITES, "vignette_256.png"), 256, 256, rows)
    scanline = [bytes((0, 229, 255, 0x2A)), bytes((0, 0, 0, 0)),
                bytes((0, 0, 0, 0)), bytes((0, 0, 0, 0))]
    write_png(os.path.join(SPRITES, "scanline_4h.png"), 1, 4, scanline)


if __name__ == "__main__":
    main()
