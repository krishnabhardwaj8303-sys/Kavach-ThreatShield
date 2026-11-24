> **Note:** for the Kavach-ID lite chip the real protocol is the UART bridge's 6-byte frame, see `KAVACH_INTEGRATION.md`. The 7-byte CRC frame below is a generic proposal.

# Proposed hardware interface (ASSUMPTIONS — confirm against your RTL)
Assumed: single clock `clk`, active-low synchronous `rst_n`, byte-stream link with `byte_valid/byte_ready`. Clock frequency, data width, protocol: **unknown, not assumed beyond this**.
Frame (7 B): `A5 | engine | risk | conf_u8 | category | flags | crc8` (CRC-8 poly 0x07 over bytes 1..5, init 0; check vector "123456789"→0xF4).
* engine: 1 URL, 2 SMS, 3 NET. risk: 0 low, 1 medium, 2 high. conf: round(p·255). flags bit0 = abstain.
* category: 0 benign/legit/normal, 1 phishing, 2 banking, 3 kyc, 4 payment, 5 delivery, 6 otp, 7 prize, 8 investment, 9 anomalous, 10 port_scan, 11 flood, 12 exfiltration, 15 unknown.
* Status bits (Python HAL): 1 READY, 2 VALID, 4 BUSY, 8 ERR_CRC, 16 ERR_SYNC.
Files: `threatshield/hal/link.py` (Python), `hardware/rtl/threat_result_if.v` + `tb_threat_result_if.v`. For SPI/UART/MMIO, only a new `HardwareLink` subclass is needed; detectors never import the HAL.
Verified: iverilog simulation accepts a Python-generated frame and flags a CRC-corrupted one. Not verified: any real device, timing, or your RTL.
