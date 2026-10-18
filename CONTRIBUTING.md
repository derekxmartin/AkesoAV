# Contributing to AkesoAV

Start with a focused issue or pull request that explains the observed problem, expected behavior, and a reproducible example. Keep changes small enough to review. Retain upstream attribution and license notices.

## Local checks

Run from the repository root, using a clean dependency installation:

```sh
python -m pip install pytest cryptography
./scripts/ci.ps1
```

See [the CI workflow](.github/workflows/ci.yml) for operating system and runtime versions. Use Visual Studio 2022 C++ build tools and Python 3.12. CI runs the script's build/test stages and the MSVC analysis build as separate required jobs. The script's existing test exclusions and skips remain visible in its output; a green run does not imply those cases passed. Kernel-driver testing additionally requires a separate authorized Windows lab and the WDK.

## Pull request evidence

Describe what changed, why, and which commands passed. State skipped checks and environment limitations explicitly. A passing unit test or frontend build does not establish production readiness, live connector behavior, or kernel-driver coverage. Include regression coverage for changed behavior when practical.

Use synthetic fixtures and redact logs. For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of posting exploit details publicly. Attribute AI-assisted work and third-party code accurately; review and validate generated changes before submitting them.
