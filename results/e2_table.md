# Experiment E2: Baseline Comparisons & Signal Ablations

| Model / Ablation | Precision | Recall | F1 Score | PR-AUC | FPR |
|---|---|---|---|---|---|
| zxcvbn only | 0.857 | 0.357 | 0.504 | 0.884 | 0.417 |
| HIBP only | 1.000 | 0.071 | 0.133 | 0.942 | 0.000 |
| zxcvbn + HIBP | 1.000 | 0.071 | 0.133 | 0.884 | 0.000 |
| personal only | 1.000 | 0.762 | 0.865 | 0.991 | 0.000 |
| history only | 1.000 | 0.071 | 0.133 | 0.942 | 0.000 |
| Full CAV (Fixed) | 1.000 | 0.071 | 0.133 | 0.992 | 0.000 |
| Full CAV (Calibrated) | 0.875 | 1.000 | 0.933 | 0.999 | 1.000 |
| Ablation: -Personal | 1.000 | 0.071 | 0.133 | 0.890 | 0.000 |
| Ablation: -Derivative | 1.000 | 0.071 | 0.133 | 0.992 | 0.000 |
| Ablation: -zxcvbn | 1.000 | 0.071 | 0.133 | 0.996 | 0.000 |
| Ablation: -HIBP | 1.000 | 0.143 | 0.250 | 0.992 | 0.000 |
