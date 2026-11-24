# Kavach-ID lite

Lite variant of the Kavach-ID design, copied from chip-startup/kavach_id/lite_version.
Status: simulation and synthesis only. Nothing has been run on hardware.

## How lite differs from the full version
- No AES core: the full version has aes128_core.v, lite does not.
- The encrypted channel (encrypted_channel.v) combines data with key material by XOR, not AES.
- The synthesis script uses ring_oscillator_stub.v, a stub, in place of a real ring oscillator.

## Contents
PUF array and stabilizer, reliability enrollment, key storage, authorization gate, built-in self-test, provenance chain, replay detector, power-on-reset circuit, register map and UART bridge, with testbenches.
Synthesis scripts: lite_final_synth.ys and lite_synth_v2.ys (the logs are included).

## Note
The verified results of the main project (formal runs, key derivation tests, FPGA place-and-route) belong to the production variant, not to this one.

---

## ThreatShield AI (Arm Bharat AI-SoC Challenge 2026, PS3)

On-device threat, phishing and scam detection prototype, in [`threatshield-ai/`](threatshield-ai/).

- **Detectors:** URL, SMS and network-flow classifiers (scikit-learn), with a validated explainer that cannot change a detector's label.
- **Kavach link:** a Python driver speaks the 6-byte UART bridge frame (CMD, ADDR, 4 data bytes) of `uart_to_reg_bridge.v` and reads Kavach registers. Verified in iverilog simulation only.
- **Status:** all training data is synthetic, so metrics measure fit to the generator, not real-world accuracy. Llama and ExecuTorch are **not implemented yet**. Nothing has run on Arm hardware or on an FPGA.
- **Kavach RTL:** the lite design in this repo's root is unchanged. It has no AES (the encrypted channel is XOR), and it is simulation and synthesis only.

See `threatshield-ai/README.md` and `threatshield-ai/STATUS.md` for details.
