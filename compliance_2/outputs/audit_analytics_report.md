# Automated audit analytics report

Generated from live data (CISO Assistant snapshot 2026-11-18T17:49:33+00:00) and the capstone logs.

## Sampling plan

| Confidence | Tolerable deviation | Deviations allowed | Sample size |
|---|---|---|---|
| 95% | 5% | 0 | 59 |
| 95% | 5% | 1 | 93 |
| 95% | 5% | 2 | 124 |
| 90% | 5% | 1 | 77 |
| 95% | 10% | 1 | 46 |

## Evidence analytics

- EHR: 18 of 90 views (20.0%, 95% CI (13.0, 29.4)) were by the billing role: least-privilege exceptions.
- Sign-in failure outliers (z > 2): test.vendor1 (44, z=2.22)
- Control tests: 2026-10-13 8/14 = 57.1% (CI 32.6-78.6); 2026-11-03 12/14 = 85.7% (CI 60.1-96.0)

## Predictions

- Corrective actions: 9/18 closed; at 1.75/week, 90% closure is forecast for 2026-12-20.
- At risk in the next 14 days: CA-08, CA-12, CA-13, CA-17
- US - HRMC flagship (Albany, NY): expected 13.3 findings (90% interval 8-20)
- US - community campuses (2): expected 17.7 findings (90% interval 11-25)
- EU - Dublin + Cork clinics: expected 28.8 findings (90% interval 20-38)
- EU - Munich diagnostics: expected 28.8 findings (90% interval 20-38)
- India - Hyderabad shared services: expected 26.6 findings (90% interval 18-35)
