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
