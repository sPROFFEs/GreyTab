# Scanner Regression Suite

This folder provides a repeatable FP/FN metric workflow per release.

## 1) Prepare vulnerable labs

Run your local test targets (examples):
- DVWA
- OWASP Juice Shop
- WebGoat

Update `regression/baseline.example.json` with the correct local URLs and expected findings.

## 2) Run regression

```bash
python3 scripts/scanner_regression.py \
  --api-base http://127.0.0.1:8443 \
  --baseline regression/baseline.example.json \
  --release v0.1.0 \
  --output regression/reports/v0.1.0.json
```

Run a subset:

```bash
python3 scripts/scanner_regression.py --profiles dvwa,juice_shop
```

## 3) Track release quality

Compare `regression/reports/*.json` across releases:
- `summary.tp`
- `summary.fp`
- `summary.fn`
- `summary.precision`
- `summary.recall`
- `summary.f1`

Use this as a release gate to avoid scanner regressions.
