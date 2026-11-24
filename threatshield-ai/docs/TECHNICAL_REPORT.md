# Technical report (prototype)
**Architecture:** URL (17 lexical features; RF selected on validation; isotonic calibration; threshold chosen on validation for recall ≥0.95) · SMS (word+char TF-IDF; ComplementNB selected over two logistic regressions; token explanations from a linear model) · Network (IsolationForest on normal flows + RandomForest; z-score explanations) · Explainer (validator forbids label/risk changes and unsupported evidence) · HAL (framed, CRC-protected).
**Verified results (synthetic data, test split, evaluation/results/*.json):**
| Model | Acc | Prec | Rec | FPR | FNR |
|---|---|---|---|---|---|
| URL RF (thr 0.98) | 0.997 | 1.000 | 0.992 | 0.000 | 0.008 |
| SMS scam-vs-legit (unseen templates) | 0.957 | 0.954 | 1.000 | 0.425 | 0.000 |
| Network RF normal-vs-suspicious | 0.993 | 0.984 | 0.994 | 0.007 | 0.006 |
| Network IsolationForest | 0.788 | 0.587 | 1.000 | 0.303 | 0.000 |
SMS 9-class macro-F1 on unseen templates: 0.519. Desktop latency (x86_64, 1 vCPU, p50): URL 33 ms, SMS 1.3 ms, network 13 ms; load RSS +18 MB; models 6.2 MB / 0.7 MB / 2.9 MB (joblib).
**Novelty (honest):** Nothing here is a new algorithm. Established: lexical URL features, TF-IDF classifiers, IsolationForest, calibration, template explanations. Design choices worth validating: strict separation of detector and explainer with an evidence validator; confidence-aware abstention band; swappable HAL with a CRC-framed result protocol. **Unvalidated:** every real-world performance claim, Llama explanation quality, ARM latency, hardware integration.
**Limitations:** synthetic data; URL latency dominated by 200-tree forest plus calibration wrappers (would need distillation/ExecuTorch export for ARM); SMS generalisation poor.
