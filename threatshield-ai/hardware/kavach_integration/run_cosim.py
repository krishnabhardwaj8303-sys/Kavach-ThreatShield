"""Python <-> user's RTL co-simulation of uart_to_reg_bridge + kavach_register_map (iverilog).
Usage: KAVACH_RTL_DIR=/path/to/lite_files python hardware/kavach_integration/run_cosim.py
The user's RTL is NOT copied into this repository."""
import os, sys, subprocess, tempfile, shutil
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from threatshield.hal.kavach import encode_read, encode_write, REG

HERE = Path(__file__).resolve().parent
VEC = [  # (frame, expected reply or None, description)
 (encode_read(REG["CHIP_ID"]), "4B415641", "CHIP_ID"),
 (encode_read(REG["STATUS"]), "00000025", "STATUS: bist_pass|replay|auth_denied_replay"),
 (encode_read(REG["PROVENANCE"]), "0000000D", "PROVENANCE: stages=3, seq_violation=1"),
 (encode_read(REG["OFFLINE"]), "0000015A", "OFFLINE: budget=0x5A, sync_required=1"),
 (encode_write(REG["CHALLENGE"], 0xDEADBEEF), None, "WRITE CHALLENGE"),
 (bytes([0x07, 0x10, 0, 0, 0, 0]), None, "unknown CMD -> frame dropped"),
 (encode_read(REG["CHIP_ID"]), "4B415641", "CHIP_ID after dropped frame (resync)"),
 (encode_read(REG["KEY_STATUS"]), "00000000", "KEY_STATUS"),
 (encode_write(REG["CHALLENGE"], 0x12345678), None, "WRITE CHALLENGE final"),
]

def main():
    rtl = Path(os.environ.get("KAVACH_RTL_DIR", ""))
    need = ["uart_to_reg_bridge.v", "kavach_register_map.v", "uart_rx.v"]
    if not rtl.is_dir() or not all((rtl / n).exists() for n in need):
        print("SKIP: set KAVACH_RTL_DIR to the folder containing", need); return 2
    tx_real = (rtl / "uart_tx.v").exists()
    w = Path(tempfile.mkdtemp())
    (w / "tx_frames.txt").write_text("".join(f"{f.hex()} {4 if exp else 0}\n" for f, exp, _ in VEC))
    srcs = [str(rtl / n) for n in need] + [str(rtl / "uart_tx.v") if tx_real else str(HERE / "uart_tx_testmodel.v"), str(HERE / "tb_cosim.v")]
    subprocess.run(["iverilog", "-g2012", "-o", str(w / "sim.vvp")] + srcs, check=True)
    subprocess.run(["vvp", str(w / "sim.vvp")], cwd=w, check=True, capture_output=True)
    got = [x.upper() for x in (w / "rx_resp.txt").read_text().split()]
    exp = [e or "NORESP" for _, e, _ in VEC] + ["CHALLENGE_O=12345678"]
    ok = got == exp
    print("uart_tx used:", "USER'S uart_tx.v" if tx_real else "ThreatShield TEST MODEL (user's uart_tx.v not supplied)")
    for (f, e, d), g in zip(VEC + [(b"", "", "final challenge_o")], got):
        print(f"{'PASS' if g == (e or 'NORESP') or (d == 'final challenge_o' and g == exp[-1]) else 'FAIL'}  {d:45s} frame={f.hex():12s} got={g}")
    print("COSIM", "PASS" if ok else "FAIL"); shutil.rmtree(w, ignore_errors=True); return 0 if ok else 1

if __name__ == "__main__": sys.exit(main())
