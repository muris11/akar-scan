# Contributing to akar-scan

Thanks for wanting to make akar-scan better! 🙏 This document explains how to set
up a dev environment, add features, and get your change merged.

> 🇮🇩 [Baca dalam Bahasa Indonesia](#kontribusi-ke-akar-scan-bahasa-indonesia)

---

## 1. Development setup

### Windows (PowerShell)

```powershell
git clone https://github.com/muris11/akar-scan.git
cd akar-scan
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
python -m akar --version     # sanity check → akar 1.1.0
```

### macOS / Linux (zsh/bash)

```bash
git clone https://github.com/muris11/akar-scan.git
cd akar-scan
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python -m akar --version     # sanity check → akar 1.1.0
```

Requirements: Python ≥ 3.10. No other dev dependencies — the project is
stdlib + `httpx` only.

## 2. Project layout

```
akar/
├── cli.py            # argparse CLI, output dispatch, exit codes
├── engine.py         # scan pipeline + shared Context (findings, pages, tech…)
├── crawl.py          # async crawler
├── fingerprint.py    # tech detection
├── http.py           # shared async httpx client
├── models.py         # Finding / Page / Severity
├── checks/           # one file per vulnerability check
├── recon/            # subdomains, ports
└── reporting/        # console / json / html renderers
entry.py              # PyInstaller entry (build only, not used at runtime)
```

## 3. Adding a new check module

1. Create `akar/checks/mycheck.py` subclassing `Check`:

```python
from __future__ import annotations
from .base import Check
from ..models import Finding, Severity


class MyCheck(Check):
    id = "mycheck"            # unique, used in --only/--skip
    name = "My check"         # shown by --list-modules

    async def on_page(self, ctx, page) -> None:
        # called for each sampled crawled page (up to --max-test-pages)
        if "something-bad" in (page.body or ""):
            ctx.add(Finding(
                check=self.id, severity=Severity.MEDIUM,
                title="Something bad on page", url=page.url,
                info="…", fix="…",
            ))

    async def run(self, ctx) -> None:
        # called once per scan, for host-wide checks (optional)
        return None
```

2. Register it in `akar/checks/__init__.py` (append to `ALL_CHECKS`).
3. Verify: `python -m akar --list-modules` must show it, then run a real scan
   against a local test server and confirm behavior.

**Rules for checks**

- **Passive** checks only inspect data already collected (`ctx.pages`, headers) —
  no extra requests. **Active** checks may make requests, but stay inside the
  `--max-tests` budget mindset: probe smart, don't brute force.
- Use the shared client (`ctx.client`) for every HTTP request — never create a
  new one.
- Findings must be deduped via `ctx.add(...)` (it handles dedup by key).
- No exploitation payloads, no DoS, no brute forcing. Detection only.
- Every `Finding` needs `title`, `url`, `info` (what/why) and `fix` (remediation).

## 4. Code style

- Python ≥ 3.10, PEP 8, **type hints** on new functions.
- Prefer stdlib; new third-party deps need justification in the PR.
- Keep modules self-contained: one file per check, no cross-imports between checks.
- Comments explain *why*, not *what*.

## 5. Testing your change

There's no formal test suite yet — verify manually:

```bash
# 1. build a local demo target
mkdir demo && cd demo
echo "<html><body><a href='x.html'>x</a></body></html>" > index.html
python -m http.server 8000 --bind 127.0.0.1   # in another terminal

# 2. scan it
python -m akar http://127.0.0.1:8000 --format console,json -o out --timeout 5
```

Your change must:

- [ ] `python -m akar --version` and `--list-modules` still work
- [ ] a full scan of the demo target completes with no traceback
- [ ] no false positives introduced on the clean demo target
- [ ] README(s) updated if you added/changed a flag or module

## 6. Pull request flow

1. Fork → create a branch: `git checkout -b feature/my-thing`
2. Make the change (one logical change per PR, please)
3. Update docs: `README.md` **and** `README.id.md` (they must stay in sync —
   if you add a flag, document it in both languages)
4. Commit with a clear message: `feat: …` / `fix: …` / `docs: …` / `refactor: …`
5. Open a PR using the template; describe *what* and *why*, and how you tested
6. CI must pass (runs `--version`, `--list-modules`, and a local demo scan on
   Linux + Windows)

## 7. Version bumps & releases

Maintainers handle releases, but remember: **every release bumps the version in
four places** — `akar/__init__.py`, `pyproject.toml`, `README.md`,
`README.id.md` (grep for the old version). Releases are tagged `vX.Y.Z` and the
`.exe` is built automatically by GitHub Actions.

## 8. Reporting security issues

Please **do not** open a public issue for vulnerabilities in akar-scan itself.
Email/report privately to the maintainer first so it can be fixed before
disclosure.

---

# Kontribusi ke akar-scan (Bahasa Indonesia)

Terima kasih mau bikin akar-scan lebih baik! 🙏

## 1. Setup development

```bash
git clone https://github.com/muris11/akar-scan.git
cd akar-scan
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1 | macOS/Linux: source .venv/bin/activate
pip install -e .
python -m akar --version
```

Syarat: Python ≥ 3.10. Tidak ada dependency dev lain — proyek ini cuma stdlib +
`httpx`.

## 2. Menambah modul check baru

1. Bikin `akar/checks/mycheck.py` yang subclass `Check` (lihat contoh lengkap di
   [bagian 3 Bahasa Inggris](#3-adding-a-new-check-module)):
   - `id` unik (dipakai di `--only`/`--skip`)
   - `on_page(ctx, page)` dipanggil per halaman yang di-sample
   - `run(ctx)` dipanggil sekali per scan (opsional, untuk check host-wide)
2. Daftarkan di `akar/checks/__init__.py` (tambahkan ke `ALL_CHECKS`).
3. Verifikasi: `python -m akar --list-modules` harus menampilkannya, lalu scan
   server lokal.

**Aturan check**

- Check **passive** hanya membaca data yang sudah ada (header, `ctx.pages`) — tanpa
  request tambahan. Check **active** boleh bikin request, tapi tetap sopan (pikirkan
  budget `--max-tests`, jangan brute force).
- Selalu pakai client bersama `ctx.client` — jangan bikin client baru.
- Temuan wajib lewat `ctx.add(...)` (sudah ada dedup).
- Tanpa payload eksploitasi, tanpa DoS, tanpa brute force. Deteksi saja.
- Setiap `Finding` wajib punya `title`, `url`, `info` (apa & kenapa), dan `fix`.

## 3. Gaya kode & testing

- Python ≥ 3.10, PEP 8, **type hints** untuk fungsi baru.
- Prioritaskan stdlib; dependency pihak ketiga baru harus ada justifikasi di PR.
- Test manual: scan target demo lokal (lihat [bagian 5](#5-testing-your-change)),
  pastikan `--version`, `--list-modules`, dan scan penuh tanpa traceback.

## 4. Alur Pull Request

1. Fork → branch: `git checkout -b feature/my-thing`
2. Satu perubahan logis per PR
3. Update dokumen: `README.md` **dan** `README.id.md` harus sinkron (tambah flag =
   dokumentasi di dua bahasa)
4. Commit jelas: `feat: …` / `fix: …` / `docs: …` / `refactor: …`
5. Buka PR pakai template; jelaskan *apa*, *kenapa*, dan cara test
6. CI harus hijau (test di Linux + Windows)

## 5. Versi & rilis

**Setiap rilis bump versi di 4 tempat** — `akar/__init__.py`, `pyproject.toml`,
`README.md`, `README.id.md`. Rilis di-tag `vX.Y.Z` dan `.exe` dibangun otomatis
oleh GitHub Actions.

## 6. Laporkan masalah keamanan

Jangan buka issue publik untuk kerentanan di akar-scan itu sendiri — laporkan
privat ke maintainer dulu.
