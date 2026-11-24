"""Hardware abstraction layer. PROPOSED interface -- not derived from the user's RTL. Confirm before use.
Frame (7 bytes): A5 | engine | risk | conf_u8 | category | flags | crc8(poly 0x07 over bytes 1..5)
Register map for MMIO backends: see docs/HARDWARE_INTERFACE.md"""
ENGINE = {"url": 1, "sms": 2, "network": 3}; RISK = {"low": 0, "medium": 1, "high": 2}
CATEGORY = {"benign": 0, "phishing": 1, "banking": 2, "kyc": 3, "payment": 4, "delivery": 5, "otp": 6, "prize": 7,
            "investment": 8, "legit": 0, "normal": 0, "anomalous": 9, "port_scan": 10, "flood": 11, "exfiltration": 12}
FLAG_ABSTAIN, ST_READY, ST_VALID, ST_BUSY, ST_ERR_CRC, ST_ERR_SYNC = 1, 1, 2, 4, 8, 16
SOF = 0xA5

def crc8(data: bytes, poly=0x07) -> int:
    c = 0
    for b in data:
        c ^= b
        for _ in range(8): c = ((c << 1) ^ poly) & 0xFF if c & 0x80 else (c << 1) & 0xFF
    return c

def encode(engine, risk, prob, label, flags=0):
    body = bytes([ENGINE[engine], RISK[risk], max(0, min(255, round(prob * 255))), CATEGORY.get(label, 15), flags])
    return bytes([SOF]) + body + bytes([crc8(body)])

def decode(frame: bytes):
    if len(frame) != 7 or frame[0] != SOF: raise ValueError("bad framing")
    if crc8(frame[1:6]) != frame[6]: raise ValueError("crc mismatch")
    e, r, c, k, f = frame[1:6]
    return dict(engine={v: k_ for k_, v in ENGINE.items()}[e], risk={v: k_ for k_, v in RISK.items()}[r], confidence=c / 255, category=k, flags=f)

class HardwareLink:
    name = "abstract"
    def connect(self): raise NotImplementedError
    def send(self, frame: bytes) -> int: raise NotImplementedError   # returns status bits
    def status(self) -> dict: raise NotImplementedError

class LoopbackLink(HardwareLink):
    """Pure-software model of the PROPOSED device. Validates framing/CRC. It is NOT the user's Verilog."""
    name = "loopback-sim"
    def __init__(self): self.connected = False; self.last = None; self.errors = 0; self.count = 0
    def connect(self): self.connected = True; return True
    def send(self, frame):
        if not self.connected: raise ConnectionError("not connected")
        try: self.last = decode(frame); self.count += 1; return ST_READY | ST_VALID
        except ValueError as e: self.errors += 1; return ST_READY | (ST_ERR_SYNC if "framing" in str(e) else ST_ERR_CRC)
    def status(self): return dict(backend=self.name, connected=self.connected, frames_ok=self.count, errors=self.errors, last=self.last,
                                  verified_against_rtl=False)

class UartLink(HardwareLink):
    """UART backend (needs pyserial + device). UNTESTED: no hardware available."""
    name = "uart"
    def __init__(self, port, baud=115200): self.port, self.baud, self.s = port, baud, None
    def connect(self):
        import serial; self.s = serial.Serial(self.port, self.baud, timeout=.5); return True
    def send(self, frame): self.s.write(frame); r = self.s.read(1); return r[0] if r else 0
    def status(self): return dict(backend=self.name, connected=self.s is not None, verified_against_rtl=False)

def make_link(kind="loopback", **kw):
    return {"loopback": LoopbackLink, "uart": UartLink}[kind](**kw)
