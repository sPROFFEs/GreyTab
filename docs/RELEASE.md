# Release procedure

A release is a tested source archive plus a pinned runtime manifest. Publish only after the full validation sequence, including real extension workflows and a clean install.

1. Set the same version in `core/__init__.py` and `extension/manifest.json`. Update `runtime-lock.json`, `requirements.lock` and `.python-version` only after validating the selected runtimes. Update the changelog and all versioned installation links.
2. Run the Python and Node suites, Python undefined-name checks, shell syntax and `git diff --check`. Run `tests/browser_smoke.py` with the pinned browser. Inspect narrow and wide screenshots and any changed dialogs or forms. Record checks and limits in `docs/QA-VERSION.md`.
3. Build a candidate with `python3 scripts/build_release.py --output /tmp/greytab-candidate`. Verify both checksum files. Extract the matching archive into a clean path containing spaces and use `tests/install_smoke.py` to check the installed versions, backend lifecycle, and preservation of a saved session after reinstalling.
4. Review the diff for runtime data, credentials and unsupported feature claims. Commit and push the reviewed version. Both native Linux CI jobs (`x86_64` and `aarch64`) must pass against that commit, including the packaged install and full Chromium workflows. Fix and rerun failures before proceeding.
5. Build the final archives from that exact commit. Verify both checksum files and inspect the archive file lists. Publish `greytab-linux-x86_64.tar.gz` with `SHA256SUMS` and `greytab-linux-aarch64.tar.gz` with `SHA256SUMS.aarch64`. Keep one archive entry per checksum file so existing x86_64 bootstraps can verify new releases.
6. Create tag `vVERSION` on that tested commit and publish the release with concrete behavior changes, validation evidence, runtime versions and remaining limits. Publication and pushing require an explicit release request.
7. Verify the release page and download links. The release event runs both native jobs against the versioned public one-liner. Wait for that verification and report any failures.

Example packaging and publication after all checks:

```bash
VERSION=0.7.0
TESTED_COMMIT=$(git rev-parse HEAD)
python3 scripts/build_release.py --output dist
(cd dist && sha256sum -c SHA256SUMS && sha256sum -c SHA256SUMS.aarch64)
gh release create "v$VERSION" dist/greytab-linux-x86_64.tar.gz dist/SHA256SUMS \
  dist/greytab-linux-aarch64.tar.gz dist/SHA256SUMS.aarch64 \
  --target "$TESTED_COMMIT" --title "GreyTab $VERSION" --notes-file /tmp/greytab-release-notes.md
```

Keep real audit databases, profiles, secrets and certificates out of release assets. Preserve only sanitized local-fixture screenshots and reports as QA evidence. Do not present safe mock/lab coverage as measured parity with Burp Suite or universal scanner accuracy.
