# Security Audit — graphify (Wibx-LABS fork)

- **Date:** 2026-07-04
- **Target:** `github.com/Wibx-LABS/graphify` (fork of `Graphify-Labs/graphify`, MIT;
  PyPI `graphifyy`)
- **Audited commit:** `983da3c15f3eb31862bca4c9977ff5329a6b12d4`
- **Threat model:** host-attacking code (exfiltration, arbitrary shell, persistence,
  backdoor). Not code quality. Note: as a code-graph tool it *legitimately* reads source
  trees and may call an LLM API — expected behavior distinguished from exfiltration below.
- **Nature:** pip-installed Python CLI (`graphify query`, `graphify clone <url>`) + git
  hooks that call `graphify.watch._rebuild_code`.

## Scanners

| Scan | Tool | Result |
|------|------|--------|
| Malware signature | ClamAV 1.5.3 (DB current) | **0 infected** |
| SAST | semgrep 1.168.0 (`--config auto`) | 0 runtime-code findings; all hits are CI `github-actions-mutable-action-tag` |
| Dependencies | osv-scanner 2.4.0 (uv.lock) | 1 finding — `pip 26.1.1` (CVSS 5.5, fix 26.1.2), dev tooling; low impact |
| Manual review | build backend, clone path, egress, subprocess, obfuscation | **SAFE** |

## Manual review — verdict: SAFE TO RUN

- **No install-time code execution:** standard `setuptools.build_meta`, no
  `setup.py`/custom build hooks; entry points only.
- **`graphify clone`** runs `git clone --depth 1 -- <url> <dest>` as an **argument list**
  (no shell); URL validated by a `github.com` regex; `--` blocks option injection; writes
  only under `~/.graphify/repos/…` or `--out`. No command injection.
- **Network egress** goes only to official LLM providers (Anthropic/OpenAI/Gemini/
  Moonshot/DeepSeek/Azure/Bedrock/local Ollama); keys from standard env vars, sent only to
  the matching client. Sending source/corpus to the configured LLM is the tool's stated
  purpose. Custom `base_url` is explicitly validated as "an exfiltration channel".
- **SSRF guard** on the arbitrary-URL ingest path (`security.py`): http/https only,
  DNS-pinned against rebinding, private IPs blocked, redirects re-validated, size-capped.
- **Secret-skipping:** files under `.ssh/.aws/.gnupg/secrets/credentials` and
  `*.pem/*.key/id_rsa/.env/.netrc` are silently excluded from ingestion (anti-harvest).
- **`cpp` preprocessing** hardened (`-nostdinc -I /dev/null`) to stop a malicious corpus
  file `#include`-ing `/etc/passwd`.
- **Git-hook rebuild** spawns a detached background python running graphify's own
  extraction into `graphify-out/` (no network); installed only on explicit `graphify hook
  install`. Interpreter path passes a strict character allowlist.
- **No** obfuscation (base64 is image→data-URI only; no eval/exec/marshal/pickle of untrusted data).

## Provenance note

`pyproject.toml` homepage points at `github.com/safishamsi/graphify` (the original author)
rather than `Graphify-Labs`. `Graphify-Labs/graphify` is the source we forked; confirm the
upstream identity chain out-of-band if strict provenance matters. Not a code risk.

## Verdict

**CLEAR as source-of-trust.** Pin `983da3c…`. Re-audit on upstream pulls; consider bumping
the `pip` dev pin.
