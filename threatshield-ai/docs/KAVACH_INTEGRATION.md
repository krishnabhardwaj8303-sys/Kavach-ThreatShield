# Kavach-ID lite <-> ThreatShield integration (based on 5 RTL files supplied by the owner)
Files read: uart_to_reg_bridge.v, kavach_register_map.v, uart_rx.v, kavach_id_top.v, kavach_id_top_uart_tb.v. **Not seen:** uart_tx.v, provenance_chain.v, key_storage.v, sha256_core.v, kavach_auth_gate.v, others. No RTL is copied into this repo; no Kavach file was modified.

## What is verified (simulation only, Icarus Verilog 12, `hardware/kavach_integration/run_cosim.py`)
Python frames from `threatshield/hal/kavach.py` drive the user's `uart_to_reg_bridge` + `kavach_register_map` + `uart_rx` (status inputs tied to constants): CHIP_ID, STATUS, PROVENANCE, OFFLINE, KEY_STATUS reads return the expected values; CHALLENGE writes reach `challenge_o`; an unknown-CMD frame is dropped and the next frame is parsed correctly. Result: COSIM PASS (log: evaluation/results/kavach_bridge_cosim.log).
**Caveats:** (1) `uart_tx.v` was not supplied, so a ThreatShield test model of the same ports was used. (2) The full `kavach_id_top` was not simulated (missing modules). (3) Nothing was run on hardware.
Replaces the earlier 7-byte CRC frame proposal for Kavach: the real protocol is the bridge's 6-byte frame `[CMD][ADDR][DATA x4 MSB-first]`, CMD 0x01 write / 0x02 read (4-byte reply).

## Observations from reading the RTL (please confirm)
- `CLKS_PER_BIT = 4` is hard-coded in the bridge ("simplified for simulation") and `uart_rx` has a 4-bit counter (max 15). A real baud rate at a real clock needs a different parameter/counter width.
- The bridge has no sync byte, CRC or inter-byte timeout: a lost or extra byte shifts every later frame until reset.
- KEY_DATA (0x28) and KEY_CONTROL (0x2C) are writable over UART in the register map; whether anything prevents re-programming after lock lives in modules I have not seen.
- `encrypted_channel` is XOR (your own note), so do not describe it as secure encryption in the report or video.
- The provenance chain records ordered supply-chain stages (stage_id is 2 bits, with sequence-violation tracking). It is not a natural log for per-scan threat verdicts and misuse could trigger `sequence_violation`.

## Integration options (nothing below is implemented unless stated)
A. **Host-side only, no RTL change (implemented in the driver, sim-verified):** ThreatShield reads CHIP_ID / STATUS / PROVENANCE over UART and shows Kavach device identity and trust state on the dashboard.
B. **Needs your approval to change RTL:** add a small register block (e.g. 0x50 THREAT_VERDICT write: engine/risk/confidence/category/counter; readback; optional hashing with your SHA-256 core) so the host can store verdicts on-chip. I will not edit your files without approval; I can provide a patch file for review.
C. Anything using auth_gate, replay_detector or key material: requires reading those modules first.
