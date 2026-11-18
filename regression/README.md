# Scanner lab regression

The application's automated tests validate request construction, deterministic detector behavior and browser workflows. This separate harness measures findings against independently running vulnerable labs. Its example baseline is a template, not evidence that those labs were scanned for a release.

## Prepare

Start authorized local DVWA, OWASP Juice Shop and/or WebGoat installations. Copy `baseline.example.json` to your own baseline and update the URLs, authentication headers, enabled families and expected findings to match the lab version/configuration. Install GreyTab using the [Linux one-liner](../docs/INSTALL.md), then start `greytab --backend-only` and create a session via the API or extension.

## Run

```bash
.venv/bin/python scripts/scanner_regression.py \
  --api-base http://127.0.0.1:8443 \
  --baseline regression/baseline.example.json \
  --release v0.3.0 \
  --output regression/reports/v0.3.0.json
```

Select a subset with `--profiles dvwa,juice_shop`. `--timeout` controls the per-profile timeout. OAST profiles require a reachable callback URL. Use fixture data and never commit real authentication tokens in baselines/reports.

Compare `summary.tp`, `fp`, `fn`, `precision`, `recall` and `f1` only across equivalent lab versions and baseline definitions. Review unmatched findings individually: an extra finding may be valid and missing from the baseline. The harness reports metrics; it does not impose an automatic pass threshold. Use the [release validation procedure](../docs/RELEASE.md) to decide which evidence is required for a detector change.
