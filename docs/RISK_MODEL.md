# Risk model (prototype, `rdf-risk-1.0`)

```
R_t = 0.45·V_t + 0.25·C_t + 0.20·D_t + 0.10·A_t        all components 0..100, higher = more risk
```

The score ranks assets for attention. It is **not** a probability of exploitation or loss and has not
been empirically calibrated. All constants are in `config/risk_model.json`; change `model_version`
whenever you change them.

## Components

| | Definition | Normalisation & aggregation | Missing / stale data |
|---|---|---|---|
| **V** vulnerability | Open findings of the **latest** imported scan for the asset | per finding `s_i` = CVSS base (0–10). `V = 0.7·10·max(s_i) + 0.3·100·min(1, Σ(s_i/10)/10)`. Excludes QoD < 30, status ≠ OPEN (false positives), `s_i < 0.1` (log). Findings are de-duplicated per (NVT, host, port) at import and only one scan is used, so repeated scans never double-count. | Missing CVSS → threat-label fallback (Critical 9.5, High 8.0, Medium 5.5, Low 2.5), else 5.0; counted in `estimated_cvss`. **No scan → V unavailable (NULL), not 0.** Scan older than 30 days → used but `stale`, score PARTIAL. |
| **C** compliance | Latest successful assessment | `C = 100·Σ w_i r_i / Σ w_i`; r = 1 NON_COMPLIANT, 0 COMPLIANT, 0.5 UNKNOWN/ERROR. Check weights: SSH-001 1.0, SSH-002 0.9, FW-001 1.0, SVC-001 0.6, FILE-001 0.9, PWD-001 0.5, LOCK-001 0.5, UPD-001 0.8 | Bounds use r ∈ [0,1] for undetermined checks. > 50 % undetermined → C unavailable. No run → unavailable. |
| **D** configuration drift | Drift events in the last 7 days | Latest event per check (run-level events once per category); ignore BASELINE, CORRECTED, EVIDENCE_RESTORED, ASSESSMENT_INCOMPLETE and events for checks now COMPLIANT. Points: CRITICAL 40, HIGH 25, MEDIUM 10, LOW 5, INFO 0. `D = min(100, Σ points)` | First assessment → D = 0 flagged "baseline". No run → unavailable. |
| **A** criticality | Asset criticality | Low 25, Medium 50, High 75, Critical 100 | Always set (schema constraint). |

Direction: all components increase with risk. Remediation lowers C immediately and removes the
check's drift points (resolved).

## Combination and uncertainty
* All four available, nothing stale/undetermined → **COMPLETE**.
* Available weight < 0.5 → **UNKNOWN**, no number is shown.
* Otherwise → **PARTIAL**: score renormalised over available components; `score_lower` / `score_upper`
  computed with each missing component at 0 / 100 and undetermined checks at r = 0 / 1. Warnings
  explain why.
* Bands: Low < 25 ≤ Medium < 50 ≤ High < 75 ≤ Critical.

## Risk drift
`ΔR = R_t − R_(t−1)` against the most recent **comparable** score (same asset, model version, weights
and available components; both valid). First comparable score → BASELINE; current UNKNOWN →
NOT_COMPARABLE. `|ΔR| ≥ 5` is *significant*. Because the model is linear, ΔR decomposes exactly into
`Σ w_k ΔX_k` (stored as `component_deltas`). Coinciding evidence (new/resolved findings, CVSS changes,
check transitions, drift events, criticality and policy changes) is listed with record references and
described as observed alongside the change — not as its cause.

## Sensitivity
Every score stores the result under alternative weight sets (equal, vulnerability-heavy,
compliance-heavy, drift-heavy). `python cli.py evaluate-baselines` reports Kendall τ between the
default ranking and each alternative.
