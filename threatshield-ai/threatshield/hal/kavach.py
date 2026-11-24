"""Host-side driver for the Kavach-ID lite UART bridge (uart_to_reg_bridge.v, as read from the user's RTL).
Frame (6 bytes): [CMD][ADDR][DATA3][DATA2][DATA1][DATA0], DATA MSB-first.  CMD 0x01=WRITE, 0x02=READ (reply: 4 bytes MSB-first).
Unknown CMD: the bridge drops the frame (after consuming all 6 bytes). The bridge has no sync byte, CRC or inter-byte timeout.
Register addresses are copied from kavach_register_map.v comments. Verified ONLY by simulation of bridge+register map (see run_cosim.py)."""
CMD_WRITE, CMD_READ = 0x01, 0x02
REG = dict(CONTROL=0x00, STATUS=0x04, CHALLENGE=0x08, RESPONSE=0x0C, UNSTABLE=0x10, STAGE_ID=0x14, STAGE_DATA=0x18,
           PROVENANCE=0x1C, OFFLINE=0x20, OFFLINE_USES=0x24, KEY_DATA=0x28, KEY_CONTROL=0x2C, KEY_STATUS=0x30,
           CIPHERTEXT=0x34, TX_COUNTER=0x38, RELIABILITY_MASK=0x40, MASK_STATUS=0x44, HASH_SELECT=0x48, HASH_WORD=0x4C, CHIP_ID=0xFC)
CHIP_ID_EXPECTED = 0x4B415641  # "KAVA" per RTL comment

def _chk(addr, val=0):
    if not 0 <= addr <= 0xFF: raise ValueError("addr must be 8-bit")
    if not 0 <= val <= 0xFFFFFFFF: raise ValueError("data must be 32-bit")

def encode_write(addr: int, data: int) -> bytes:
    _chk(addr, data); return bytes([CMD_WRITE, addr]) + data.to_bytes(4, "big")

def encode_read(addr: int) -> bytes:
    _chk(addr); return bytes([CMD_READ, addr, 0, 0, 0, 0])   # DATA field unused for reads but still 4 bytes

def decode_reply(b: bytes) -> int:
    if len(b) != 4: raise ValueError("read reply must be 4 bytes")
    return int.from_bytes(b, "big")

def decode_status(v: int) -> dict:
    return dict(bist_pass=bool(v & 1), bist_fail=bool(v >> 1 & 1), replay_detected=bool(v >> 2 & 1),
                authentication_grant=bool(v >> 3 & 1), auth_denied_bist=bool(v >> 4 & 1), auth_denied_replay=bool(v >> 5 & 1))

class KavachUart:
    """Wraps any byte transport with write(bytes) / read(n)->bytes (e.g. pyserial). UNTESTED on real hardware."""
    def __init__(self, transport): self.t = transport
    def read_reg(self, addr):
        self.t.write(encode_read(addr)); return decode_reply(self.t.read(4))
    def write_reg(self, addr, data): self.t.write(encode_write(addr, data))
    def chip_present(self): return self.read_reg(REG["CHIP_ID"]) == CHIP_ID_EXPECTED
    def status(self): return decode_status(self.read_reg(REG["STATUS"]))
