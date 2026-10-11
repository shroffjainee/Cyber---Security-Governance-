# Phase-II experiment results (30 simulation runs, 20 assets, 16 weekly scans)

Values are mean ± standard deviation across runs. Rates are fractions (0-1).

| method             | label                           | precision     | recall        | f1            | false_alerts_per_100   | detection_rate   | mean_delay    | critical_detection_rate   | critical_mean_delay   | ndcg5         | p5            | premature_drop_rate   | alerts           |
|:-------------------|:--------------------------------|:--------------|:--------------|:--------------|:-----------------------|:-----------------|:--------------|:--------------------------|:----------------------|:--------------|:--------------|:----------------------|:-----------------|
| B0_compliance_only | Base paper (compliance only)    | 0.574 ± 0.103 | 0.529 ± 0.101 | 0.544 ± 0.084 | 9.944 ± 3.484          | 0.64 ± 0.104     | 0.187 ± 0.148 | 0.711 ± 0.148             | 0.175 ± 0.199         | 0.513 ± 0.168 | 0.529 ± 0.083 | 0.097 ± 0.058         | 69.833 ± 17.687  |
| B1_compliance_cvss | Compliance + CVSS scanner       | 0.669 ± 0.09  | 0.853 ± 0.076 | 0.747 ± 0.074 | 10.656 ± 3.608         | 0.892 ± 0.062    | 0.048 ± 0.064 | 0.918 ± 0.082             | 0.055 ± 0.102         | 0.548 ± 0.151 | 0.618 ± 0.102 | 0.03 ± 0.026          | 96.0 ± 17.867    |
| P_no_context       | Proposed without context        | 0.691 ± 0.081 | 0.997 ± 0.015 | 0.813 ± 0.06  | 11.233 ± 3.617         | 0.998 ± 0.008    | 0.0 ± 0.0     | 0.998 ± 0.01              | 0.0 ± 0.0             | 0.67 ± 0.099  | 0.783 ± 0.079 | 0.0 ± 0.0             | 108.367 ± 17.399 |
| P_no_temporal      | Proposed without temporal logic | 0.975 ± 0.134 | 0.108 ± 0.061 | 0.196 ± 0.095 | 0.144 ± 0.791          | 0.171 ± 0.095    | 0.426 ± 0.487 | 0.287 ± 0.139             | 0.389 ± 0.451         | 0.8 ± 0.115   | 0.715 ± 0.108 | 0.22 ± 0.231          | 8.567 ± 5.171    |
| P_full             | Proposed risk-drift framework   | 0.727 ± 0.088 | 0.902 ± 0.068 | 0.802 ± 0.065 | 8.467 ± 3.068          | 0.925 ± 0.046    | 0.022 ± 0.045 | 1.0 ± 0.0                 | 0.0 ± 0.0             | 0.818 ± 0.097 | 0.758 ± 0.101 | 0.007 ± 0.015         | 92.933 ± 15.157  |


## Paired Wilcoxon signed-rank tests

| comparison                   | metric                  |   proposed_mean |   baseline_mean |   difference |   wilcoxon_p |
|:-----------------------------|:------------------------|----------------:|----------------:|-------------:|-------------:|
| P_full vs B0_compliance_only | precision               |          0.7272 |          0.574  |       0.1532 |       0      |
| P_full vs B0_compliance_only | f1                      |          0.8016 |          0.5443 |       0.2573 |       0      |
| P_full vs B0_compliance_only | false_alerts_per_100    |          8.4667 |          9.9444 |      -1.4778 |       0.0048 |
| P_full vs B0_compliance_only | critical_detection_rate |          1      |          0.7106 |       0.2894 |       0      |
| P_full vs B0_compliance_only | ndcg5                   |          0.8179 |          0.5127 |       0.3053 |       0      |
| P_full vs B0_compliance_only | p5                      |          0.7576 |          0.5292 |       0.2284 |       0      |
| P_full vs B0_compliance_only | premature_drop_rate     |          0.0073 |          0.0969 |      -0.0896 |       0      |
| P_full vs B1_compliance_cvss | precision               |          0.7272 |          0.6686 |       0.0586 |       0      |
| P_full vs B1_compliance_cvss | f1                      |          0.8016 |          0.7466 |       0.055  |       0      |
| P_full vs B1_compliance_cvss | false_alerts_per_100    |          8.4667 |         10.6556 |      -2.1889 |       0.0002 |
| P_full vs B1_compliance_cvss | critical_detection_rate |          1      |          0.9178 |       0.0822 |       0      |
| P_full vs B1_compliance_cvss | ndcg5                   |          0.8179 |          0.5482 |       0.2697 |       0      |
| P_full vs B1_compliance_cvss | p5                      |          0.7576 |          0.6179 |       0.1397 |       0      |
| P_full vs B1_compliance_cvss | premature_drop_rate     |          0.0073 |          0.0296 |      -0.0224 |       0.0003 |


## Sensitivity to drift threshold θ

|   theta |   precision |   recall |    f1 |   critical_detection_rate |   false_alerts_per_100 |
|--------:|------------:|---------:|------:|--------------------------:|-----------------------:|
|     2.5 |       0.656 |    1     | 0.79  |                     1     |                 13     |
|     5   |       0.733 |    0.887 | 0.8   |                     1     |                  7.9   |
|     7.5 |       0.771 |    0.779 | 0.772 |                     0.986 |                  5.667 |
|    10   |       0.875 |    0.631 | 0.724 |                     0.903 |                  2.333 |
|    15   |       0.933 |    0.371 | 0.502 |                     0.673 |                  1.033 |

