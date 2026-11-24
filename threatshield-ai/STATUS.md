# Implementation status (verified = actually executed in this session)
| Item | Status |
|---|---|
| Synthetic datasets + leakage-safe splits (URL by domain, SMS by template) | ✅ done, tested |
| URL engine: 3 models compared on validation, isotonic calibration, importance | ✅ trained |
| SMS engine: 9-class, 3 models compared, unseen-template test | ✅ trained, **weak generalisation** |
| Network engine: IsolationForest + RandomForest, z-score explanations | ✅ trained |
| Explainer with evidence validator (cannot change label) | ✅ template backend tested |
| Llama / Ollama backend | ⚠️ code only, **never run** |
| Flask API + dashboard (all buttons call real pipeline) | ✅ API tested via test client; **UI not visually tested in a browser** |
| HAL: frame/CRC8 codec, loopback model | ✅ tested |
| HAL: UART backend | ⚠️ untested (no hardware) |
| Verilog proposed interface + testbench | ✅ simulated with iverilog 12 (TB PASS) — proposed design only |
| Kavach UART bridge driver (`hal/kavach.py`) + co-simulation vs user's bridge/register map | ✅ COSIM PASS (simulation only; test model for uart_tx; full top not simulated) |
| Integration on real Kavach hardware / full top level | ❌ not done |
| pytest suite | ✅ 17 passed, 1 skipped without Kavach RTL (18 passed with it) |
| Latency/memory/size (x86_64) | ✅ evaluation/results/deployment_report.json |
| ExecuTorch export + quantization | ❌ **not verified**: `pip install executorch` stalled in dependency resolution; script `arm_deployment/export_executorch.py` is written but unrun |
| ARM / QEMU / device test | ❌ not done |
| Real datasets, licensing docs | ❌ none used (synthetic only) |
| Architecture diagram, competition report, video script | ⚠️ see docs/ (brief) |
