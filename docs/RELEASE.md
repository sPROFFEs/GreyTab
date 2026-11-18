# Release procedure

A release is a tested source archive plus a pinned runtime manifest. Publish only after the full validation sequence, including real extension workflows and a clean install.

1. Set the same version in `core/__init__.py` and `extension/manifest.json`. Update `runtime-lock.json`, `requirements.lock` and `.python-version` only after validating the selected runtimes. Update the changelog and all versioned installation links.
2. Run the Python and Node suites, Python undefined-name checks, shell syntax and `git diff --check`. Run `tests/browser_smoke.py` with the pinned browser. Inspect narrow/wide screenshots and any changed dialogs/forms; record the exact checks and limits in `docs/QA-VERSION.md`.
3. Build a candidate with `python3 scripts/build_release.py --output /tmp/greytab-candidate`. Verify SHA256SUMS. Extract into a clean path containing spaces, install with isolated command/desktop destinations, check version/browser, exercise backend startup/shutdown and reinstall while retaining fixture state.
4. Review the diff for runtime data, credentials and unsupported feature claims. Commit the complete result, push the reviewed commit, and wait for Linux CI to pass. If it fails, fix and rerun before proceeding.
5. Build the final archive from that exact commit. Run checksum verification and inspect the archive file list. Include `greytab-linux-x86_64.tar.gz` and `SHA256SUMS` as release assets. The checksum file contains the application archive only so the bootstrap can verify its download. Optional QA screenshot bundles use separate assets.
6. Create tag `vVERSION` on that tested commit and publish the release with concrete behavior changes, validation evidence, runtime versions and remaining limits. Publication and pushing require an explicit release request.
7. Validate the published versioned one-liner in an isolated destination and check `--version` and `--check`. Verify the release page and download links. If publication or remote validation fails, report that state accurately.

Example packaging and publication after all checks:

```bash
python3 scripts/build_release.py --output dist
(cd dist && sha256sum -c SHA256SUMS)
gh release create v0.3.1 dist/greytab-linux-x86_64.tar.gz dist/SHA256SUMS \
  --target TESTED_COMMIT --title 'GreyTab 0.3.1' --notes-file /tmp/greytab-release-notes.md
```

Keep real audit databases, profiles, secrets and certificates out of release assets. Preserve only sanitized local-fixture screenshots and reports as QA evidence. Do not present safe mock/lab coverage as measured parity with Burp Suite or universal scanner accuracy.
