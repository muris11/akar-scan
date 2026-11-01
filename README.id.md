# akar-scan

> [🇬🇧 English](README.md) | 🇮🇩 Bahasa Indonesia

**Scanner kerentanan web mendalam** — reconnaissance, crawling, fingerprinting, dan
pemeriksaan kerentanan aktif, dengan laporan console / JSON / HTML.

`akar` (akar = akar dari pohon) menggali dari akar-akarnya: enumerasi subdomain dan
port, crawl situs, fingerprint stack, lalu aktif mem probe kerentanan umum — file
terekspos, misconfiguration, titik injeksi, dan lainnya.

> ⚠️ **Hanya untuk target yang sah/berizin.** Memindai sistem yang tidak kamu miliki
> atau tidak punya izin tertulis untuk diuji bisa ilegal di yurisdiisimu. Kamu
> bertanggung jawab atas penggunaan alat ini.

---

## Daftar isi

- [Fitur](#fitur)
- [Persyaratan](#persyaratan)
- [Instalasi](#instalasi)
  - [Windows](#windows)
  - [macOS](#macos)
  - [Linux](#linux)
  - [Verifikasi instalasi](#verifikasi-instalasi)
- [Mulai cepat](#mulai-cepat)
- [Panduan penggunaan](#panduan-penggunaan)
- [Referensi CLI (semua flag)](#referensi-cli-semua-flag)
- [Modul](#modul)
- [Laporan & output](#laporan--output)
- [Exit code & integrasi CI](#exit-code--integrasi-ci)
- [Cara kerja](#cara-kerja)
- [Troubleshooting / FAQ](#troubleshooting--faq)
- [Struktur proyek](#struktur-proyek)
- [Uninstall](#uninstall)
- [Penggunaan yang bertanggung jawab](#penggunaan-yang-bertanggung-jawab)

---

## Fitur

- **Recon**: enumerasi subdomain (certificate transparency crt.sh + DNS brute-force,
  wordlist 170 kata, resolusi live) dan pemindaian port TCP async dengan banner grab.
- **Crawler**: async, dibatasi depth & jumlah halaman, single-host secara default,
  dedup URL kanonisasi, ekstrak link dari `<a>` / `<link>` / `srcset` / meta-refresh /
  JS inline, dan membaca `robots.txt` + `sitemap.xml`.
- **Fingerprinting**: server, bahasa, framework, CMS, library JS (dari header, cookie,
  path, dan signature body).
- **15 modul pemeriksaan** di lapisan passive dan active (lihat [Modul](#modul)):
  security headers, clickjacking, cookies, CORS, TLS, file terekspos, path rentan
  (CVE), open redirect, XSS, SQLi, LFI, CSRF, info leak, metode HTTP, kebijakan HTTP.
- **Sadara false-positive**: baseline 404 acak diminta duluan, jadi halaman fallback
  SPA tidak menghasilkan temuan "file terekspos" palsu.
- **Terbatas & sopan**: test aktif dibatasi `--max-tests` (default 500 request) dan
  di-sample `--max-test-pages` (default 25 halaman); `--rate` bisa membatasi kecepatan.
- **Laporan**: output console berwarna, JSON yang bisa dibaca mesin, dan laporan HTML
  self-contained.
- **Core tanpa dependensi berat**: hanya `httpx` (dengan HTTP/2) — sisanya Python
  standard library (ssl, socket, asyncio, html.parser).

---

## Persyaratan

- **Python 3.10 atau lebih baru** (3.10 – 3.13 semuanya jalan; kode memakai typing
  modern dan fitur `asyncio` yang butuh 3.10+).
- `pip` (bawaan installer python.org; di Windows itu pip dari launcher `py`).
- Akses internet kalau pakai `--subdomains` (query crt.sh). Sisanya jalan langsung ke
  target.
- Tidak butuh hak akses admin/root.

Cek versi kamu:

```bash
python --version      # atau: python3 --version  (macOS/Linux)
# Windows mungkin perlu: py --version
```

Kalau keluar `Python 3.10.x` atau lebih tinggi, beres. Kalau tidak, lihat
[Troubleshooting](#troubleshooting--faq).

---

## Instalasi

### Windows

> Dites dengan PowerShell dan CMD. Langkah di bawah mengasumsikan installer resmi
> python.org.

**1. Install Python (lewati kalau sudah ≥ 3.10)**

- Download installer dari <https://www.python.org/downloads/windows/>.
- Jalankan dan — ini penting — **centang "Add python.exe to PATH"** di layar pertama
  sebelum klik *Install Now*.
- Kalau pakai **Python bawaan Laragon/XAMPP** (misal
  `C:\laragon\bin\python\python-3.10\`), itu juga bisa — pastikan saja direktori itu
  (dan subfolder `Scripts\`-nya) ada di `PATH` kamu.

**2. Buka terminal**

- Tekan `Win + X` → **Windows Terminal** / **PowerShell**, atau tekan
  `Win + R`, ketik `powershell`, Enter.

**3. Pastikan Python bisa diakses**

```powershell
python --version
# Kalau gagal, coba launcher py:
py --version
```

**4. (Disarankan) Buat virtual environment**

Di PowerShell, dari folder proyek:

```powershell
cd C:\path\to\akar-scan
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

- Script aktivasi diblokir kebijakan? Jalankan sekali ini, lalu coba aktivasi lagi:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  ```
- Lebih suka CMD? Aktifkan dengan `.\.venv\Scripts\activate.bat`.
- Di CMD/PowerShell env yang aktif ditampilkan sebagai `(.venv)` di awal baris prompt.

**5. Install scannernya**

```powershell
# dari dalam folder proyek, dengan venv aktif:
pip install -e .
```

Ini menginstall `httpx` + `httpx[http2]` dan membuat perintah `akar`.

Alternatifnya, tanpa install (tanpa perintah `akar`, jalan via module):

```powershell
pip install -r requirements.txt
python -m akar --version
```

**6. Jalankan**

```powershell
akar --version
# atau, kalau tidak `pip install -e .`:
python -m akar --version
```

> Catatan: di Windows perintah `akar` ada di `.venv\Scripts\` (install editable menaruh
> console script di samping interpreter). Kalau `akar` "not recognized", pakai saja
> `python -m akar ...` — ekuivalen.

---

### macOS

> Jalan di Apple Silicon (M1/M2/M3…) maupun Intel. macOS membawa stub `python3` yang
> membuka App Store — install Python asli dulu.

**Opsi A — Homebrew (disarankan kalau sudah punya Homebrew)**

```bash
# install Homebrew dulu kalau perlu: https://brew.sh
brew install python@3.12
```

**Opsi B — installer python.org**

- Download dari <https://www.python.org/downloads/macos/> dan jalankan paketnya.
- Ini menginstall `python3` dan `pip3` ke `/Library/Frameworks/Python.framework`.

**Lalu, di Terminal (zsh secara default):**

```bash
cd ~/path/to/akar-scan

# 1. virtual environment (disarankan — menjaga Python sistem tetap bersih)
python3 -m venv .venv
source .venv/bin/activate

# 2. install
pip install -e .
# atau, jalur tanpa install:
#   pip install -r requirements.txt
#   python -m akar --version

# 3. verifikasi
akar --version
# atau: python -m akar --version
```

Nonaktifkan venv kapan saja dengan `deactivate`.

---

### Linux

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install -y python3 python3-venv python3-pip

cd ~/path/to/akar-scan
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
akar --version
```

Fedora/RHEL: `sudo dnf install python3 python3-pip`; Arch: `sudo pacman -S python python-pip`.

---

### Verifikasi instalasi

Semua platform — ini seharusnya semua berhasil:

```bash
akar --version          # cetak: akar 1.0.0
akar --list-modules     # cetak tabel modul
akar --help             # usage lengkap
```

Kalau `--version` jalan tapi scan langsung gagal, langsung ke
[Troubleshooting](#troubleshooting--faq).

---

## Mulai cepat

```bash
# Scan penuh satu situs (crawl + semua check), laporan console:
akar https://example.com

# Tulis laporan JSON + HTML juga:
akar https://example.com --format console,json,html -o report

# Recon: subdomain + port scan di atas scan normal:
akar https://example.com --subdomains --ports 80,443,8000-8100

# Arahkan traffic lewat Burp / ZAP:
akar https://example.com --proxy http://127.0.0.1:8080

# Scan terotentikasi (cookie sesi / basic auth / header kustom):
akar https://example.com --cookie "session=abc123" --header "X-Env: staging"
akar https://example.com --auth admin:password

# Jalankan hanya modul tertentu / lewati beberapa:
akar https://example.com --only cors,tls,exposed-files
akar https://example.com --skip xss,sqli          # jalur passive-only
```

Tanpa `pip install -e .`, ganti `akar` dengan `python -m akar` (atau `python3 -m akar`).

---

## Panduan penggunaan

### Pindai target

```bash
akar example.com                # scheme opsional; https dicoba dulu, lalu http
akar https://example.com:8443   # port non-standar dihormati
akar http://localhost:8000      # target lokal/dev juga jalan
akar https://example.com/app    # path diikuti sebagai dasar crawl
```

Kalau URL tanpa scheme, scanner mencoba `https://` dulu lalu otomatis jatuh ke
`http://`. Kalau scheme pertama gagal, scheme lain dicoba ulang sebelum menyerah
(exit code 2).

### Atur crawl

```bash
akar example.com --depth 5 --max-pages 500      # situs lebih besar
akar example.com --depth 1 --max-pages 20       # lewat cepat
akar example.com --no-js                        # lewati ekstraksi link dari JS inline
akar example.com --robots                       # crawl juga path yang dilarang robots.txt
```

### Atur request

```bash
akar example.com --threads 50 --timeout 20      # server lambat, sabar ya
akar example.com --rate 5                       # maks 5 req/s per host (mode sopan)
akar example.com --insecure                     # lewati verifikasi sertifikat TLS (self-signed)
akar example.com --no-http2                     # paksa HTTP/1.1
akar example.com --user-agent "MyScanner/1.0"
```

### Recon

```bash
# subdomain: crt.sh + DNS brute force (butuh internet untuk crt.sh)
akar example.com --subdomains
akar example.com --subdomains --no-crt          # DNS brute saja (hampir offline)

# port scan: flag kosong = daftar umum; atau isi daftar/range eksplisit
akar example.com --ports
akar example.com --ports 80,443,3306,8000-8100
akar example.com --ports 1-1024 --port-timeout 3
```

### Kendalikan test aktif

```bash
akar example.com --max-tests 1000               # budget probe lebih besar (default 500)
akar example.com --max-test-pages 50            # sample lebih banyak halaman (default 25)
akar example.com --sqli-aggressive              # aktifkan probe SQLi time-based (lambat)
akar example.com --test-forms                   # sertakan form HTML di test injeksi
akar example.com --only cors,tls
akar example.com --skip xss,sqli,lfi            # jalur passive-only / lebih ringan
akar --list-modules                             # lihat semua id modul
```

### Scan terotentikasi

```bash
# cookie sesi (salin dari dev tools browser kamu):
akar example.com --cookie "PHPSESSID=...; token=..."

# HTTP basic auth:
akar example.com --auth user:password

# header bebas (bisa diulang):
akar example.com --header "Authorization: Bearer eyJ..." --header "X-Env: staging"
```

### Lewat proxy (Burp Suite / OWASP ZAP)

```bash
# listener default Burp:
akar example.com --proxy http://127.0.0.1:8080

# listener default ZAP:
akar example.com --proxy http://127.0.0.1:8081
```

Untuk memproxy HTTPS lewat Burp, install sertifikat CA Burp ke trust store sistem
(atau pakai `--insecure` untuk melewati verifikasi).

---

## Referensi CLI (semua flag)

Jalankan `akar --help` untuk referensi live. Flag dikelompokkan per area:

### Posisional

| Flag | Keterangan |
|---|---|
| `url` | URL target. Scheme opsional (`example.com` jalan). Hilangkan saat pakai `--list-modules`. |
| `--version` | Cetak versi lalu keluar. |

### Crawling

| Flag | Default | Keterangan |
|---|---|---|
| `--depth N` | `3` | Kedalaman crawl maksimal dari URL awal. |
| `--max-pages N` | `120` | Jumlah halaman crawl maksimal. |
| `--no-js` | mati | Jangan ekstrak link dari JavaScript inline. |
| `--robots` | mati | Juga crawl path yang dilarang di robots.txt. |
| `--max-test-pages N` | `25` | Halaman yang di-sample untuk test aktif. |

### Request

| Flag | Default | Keterangan |
|---|---|---|
| `--threads N` | `20` | Request bersamaan. |
| `--timeout S` | `10.0` | Timeout per request dalam detik (boleh float). |
| `--rate R` | `0.0` | Request/detik per host; `0` = tanpa batas. |
| `--proxy URL` | — | Proxy, mis. `http://127.0.0.1:8080`. |
| `--header K:V` | — | Header kustom; bisa diulang. |
| `--cookie VALUE` | — | Nilai header `Cookie`. |
| `--auth USER:PASS` | — | HTTP basic auth. |
| `--user-agent UA` | `AkarScan/1.0.0 (+security-scanner)` | User-Agent kustom. |
| `--insecure` | mati | Lewati verifikasi sertifikat TLS. |
| `--no-http2` | mati | Nonaktifkan HTTP/2. |

### Recon

| Flag | Default | Keterangan |
|---|---|---|
| `--subdomains` | mati | Enumerasi subdomain (crt.sh + DNS brute). |
| `--no-crt` | mati | Lewati crt.sh saat enumerasi subdomain. |
| `--ports [DAFTAR]` | mati | Pindai port. `--ports` kosong = daftar umum; atau `80,443,8000-8100`. |
| `--port-timeout S` | `1.2` | Timeout probe per port. |

### Test aktif

| Flag | Default | Keterangan |
|---|---|---|
| `--max-tests N` | `500` | Budget request test aktif. |
| `--sqli-aggressive` | mati | Aktifkan probe SQLi time-based (lambat). |
| `--test-forms` | mati | Sertakan form HTML di test injeksi. |
| `--only IDS` | — | Id modul yang dijalankan, dipisah koma. |
| `--skip IDS` | — | Id modul yang dilewati, dipisah koma. |
| `--list-modules` | — | Daftar modul yang tersedia lalu keluar. |

### Output

| Flag | Default | Keterangan |
|---|---|---|
| `--format FMT` | `console` | Dipisah koma: `console`, `json`, `html`. |
| `-o, --output PREFIX` | `akar-<host>-<timestamp>` | Prefix file output untuk laporan json/html. |
| `--fail-on SEV` | — | `low` / `medium` / `high` / `critical` — exit non-zero kalau ada temuan ≥ severity ini. |
| `-v, --verbose` | mati | Log debug di stderr. |

---

## Modul

Total 17 modul: 15 check + 2 recon. Aktifkan/matikan dengan `--only` / `--skip`.
Modul recon hanya jalan kalau flag-nya (`--subdomains` / `--ports`) dipasang.

| id | lapisan | apa yang diperiksa |
|---|---|---|
| `security-headers` | passive | header hilang/lemah, HSTS, direktif CSP (unsafe-inline/eval, wildcard, default-src/base-uri/form-action hilang) |
| `clickjacking` | passive | X-Frame-Options / frame-ancestors |
| `cookies` | passive | flag Secure / HttpOnly / SameSite |
| `cors` | active | refleksi origin, wildcard + credentials, preflight terlalu permisif |
| `tls` | active | kedaluwarsa sertifikat, self-signed, SAN tidak cocok, TLS 1.0/1.1, cipher lemah (RC4/3DES/NULL/EXPORT) |
| `exposed-files` | active | `.env`, `.git`, kunci SSH, dump DB, backup, backup `wp-config`, actuator, phpinfo, config IDE/SFTP, log |
| `cve` | active | PHPUnit eval-stdin (CVE-2017-9841), Ignition, actuator/env+heapdump, konsol Werkzeug, Solr, Elasticsearch tanpa auth, Swagger, WP xmlrpc/user enum, advisori versi jQuery/AngularJS, stack trace mode debug |
| `open-redirect` | active | 40+ parameter redirect, 6 payload bypass (absolut, `//`, `///`, encoded, double-encoded, backslash) |
| `xss` | active | refleksi canary di query param dan form GET (raw vs encoded) |
| `sqli` | active | signature error (6 engine) + boolean blind diferensial; time-based di balik `--sqli-aggressive` |
| `lfi` | active | payload traversal unix/windows + konfirmasi baca sumber `php://filter` base64 |
| `csrf` | passive | form yang mengubah state tanpa token, kredensial lewat GET |
| `info-leak` | passive | banner server, stack trace, daftar direktori, komentar HTML sensitif, IP internal, robots.txt/sitemap, source map `.js.map` |
| `http-methods` | active | enumerasi OPTIONS/TRACE, verb tidak aman, WebDAV, XST |
| `http-policy` | active | downgrade HTTPS→HTTP, injeksi Host header (sinyal cache/pw-reset poisoning) |
| `subdomains` | recon | certificate transparency crt.sh + DNS brute force 170 kata, resolusi live (aktifkan dengan `--subdomains`) |
| `ports` | recon | pemindaian port TCP async dengan banner grab (aktifkan dengan `--ports`) |

Legenda severity: **critical** > **high** > **medium** > **low** > **info**.

---

## Laporan & output

```bash
# console saja (default)
akar example.com

# ketiganya sekaligus
akar example.com --format console,json,html -o report
#   → report.json + report.html  (plus laporan console)

# nama file defaultnya akar-<host>-<timestamp>.json/.html kalau -o dihilangkan
akar example.com --format json,html
```

- **console** — berwarna, dikelompokkan per severity, dengan evidence dan saran remediasi.
- **json** — bisa dibaca mesin; berisi temuan, fingerprint tech, statistik crawl,
  info TLS, subdomain, dan port terbuka. Enak dipipe ke alat lain.
- **html** — laporan satu file self-contained yang bisa dibuka di browser atau
  dilampirkan ke deliverable klien.

---

## Exit code & integrasi CI

| Code | Arti |
|---|---|
| `0` | Scan selesai; tidak ada temuan di/atas threshold `--fail-on` (atau tanpa threshold). |
| `1` | Ada temuan di/atas severity `--fail-on`. |
| `2` | Target tidak terjangkau (atau error runtime fatal). |
| `130` | Dibatalkan (Ctrl+C). |

Gerbang pipeline CI berdasarkan severity:

```bash
akar https://staging.example.com --format json -o scan --fail-on high
# exit code != 0 → pipeline gagal
```

Contoh step GitHub Actions:

```yaml
- name: Security scan
  run: |
    pip install -e .
    akar https://staging.example.com --format console,json --fail-on high -o akar-report
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: akar-report
    path: akar-report.*
```

---

## Cara kerja

Pipeline (diimplementasikan di `akar/engine.py`):

1. **Jangkau target** — normalisasi URL, coba https lalu http (dan sebaliknya kalau
   gagal). Tidak terjangkau → exit 2.
2. **Fingerprint** — kumpulkan sinyal tech dari header, cookie, dan body.
3. **Crawl** — BFS dengan batas depth/halaman; membaca robots.txt + sitemap.xml;
   dedup URL kanonisasi.
4. **Baseline 404** — fetch path acak yang tidak ada supaya respons fallback SPA
   (soft-404) tidak menghasilkan false positive di `exposed-files` dan kawan-kawan.
5. **Check passive + active** — setiap modul terpilih menjalankan `on_page()` di
   sampai `--max-test-pages` halaman ter-sample, lalu `run()` site-wide. Probe aktif
   berbagi budget request (`--max-tests`) supaya situs besar tetap cepat.
6. **Recon (opsional)** — enumerasi subdomain dan/atau port scan saat diaktifkan.
7. **Laporan** — temuan diurutkan per severity; renderer console/JSON/HTML memakai
   objek context yang sama.

Batasan desain:

- Probe injeksi memakai **canary acak** atau **perbandingan diferensial** — tanpa
  payload eksploitasi, tanpa brute force, tanpa DoS.
- Semua HTTP probing lewat satu klien `httpx` async bersama (reuse koneksi, dukungan
  proxy, HTTP/2).

---

## Troubleshooting / FAQ

**`python` is not recognized (Windows)**
Python tidak ada di PATH. Pakai launcher `py` saja (`py -m akar ...`,
`py -m venv .venv`), atau install ulang dari python.org dengan centang
*"Add python.exe to PATH"*.

**`akar` is not recognized setelah `pip install -e .` (Windows)**
Install editable menaruh shim `akar.exe` di folder `Scripts\` venv yang aktif. Pastikan
venv-nya aktif, atau pakai bentuk universal saja: `python -m akar ...`.

**`pip : File ...\pip.ps1 cannot be loaded ... security restriction` (PowerShell)**
Kebijakan execution memblokir shim pip. Jalankan sekali per sesi:
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, lalu coba lagi.

**`ModuleNotFoundError: httpx`**
Dependensi belum terinstall di interpreter yang kamu pakai. Aktifkan venv lalu jalankan
`pip install -e .` (atau `pip install -r requirements.txt`). Kalau pakai `python -m
akar`, `python` itu harus yang sudah punya httpx.

**`ssl.SSLError` / certificate verify failed**
Sertifikat target self-signed atau kedaluwarsa → tambah `--insecure`. Di belakang
Burp/ZAP, import sertifikat CA proxy ke trust store (disarankan) atau pakai `--insecure`.

**`error: target unreachable: ...` (exit code 2)**
Scanner tidak dapat respons HTTP sama sekali. Cek URL, coba scheme lain (`http://` vs
`https://`), cek jaringan/proxy, atau tambah `--insecure`.

**Scan terlalu lambat di situs besar**
Turunkan budget crawl: `--depth 2 --max-pages 40 --max-test-pages 10 --max-tests 200`.
Atau jalankan passive-only:
`--skip xss,sqli,lfi,open-redirect,cors,http-methods,http-policy,exposed-files,cve,tls`.

**Saya mau semua link, termasuk yang dilarang robots**
Tambah `--robots` (dan pertimbangkan naikkan `--max-pages`).

**Check SQLi time-based tidak pernah jalan**
Itu opt-in karena lambat: pasang `--sqli-aggressive`.

**macOS bilang "command not found: python3"**
Kamu belum install Python asli (stub OS hanya membuka App Store). Install via
`brew install python@3.12` atau paket python.org, lalu restart Terminal.

**Apple Silicon / "pip install" minta build dari source**
Pakai `python@3.12` Homebrew atau build universal2 python.org — keduanya menyediakan
wheel untuk `httpx` dan `h2`.

**Windows Defender / antivirus menandai scan**
Check aktif mengirim string probe (traversal, error SQL). Sebagian AV secara heuristik
menandai scanner. Tambahkan exclusion untuk folder proyek kalau kamu percaya sumbernya
(repo ini) — itu heuristik lokal, bukan malware.

**Port scan tidak menemukan apa-apa**
Hanya jalan dengan `--ports`; yang dipindai adalah host target (bukan path URL). Naikkan
`--port-timeout` untuk jaringan lambat.

**Enumerasi subdomain tidak menghasilkan apa-apa**
crt.sh bisa lambat atau kena rate-limit; coba lagi, atau pakai `--no-crt` untuk DNS brute
saja. Subdomain ditemukan secara pasif lewat certificate transparency — situs tanpa log
CT bisa hasilnya nol.

**Bagaimana scan localhost / server dev?**
`akar http://localhost:8000` jalan. Untuk HTTPS dengan sertifikat dev self-signed
tambah `--insecure`.

---

## Struktur proyek

```
akar-scan/
├── akar/
│   ├── __init__.py          # versi
│   ├── __main__.py          # entry python -m akar
│   ├── cli.py               # CLI argparse, dispatch output, exit code
│   ├── engine.py            # pipeline scan & Context bersama
│   ├── crawl.py             # crawler async (robots/sitemap, ekstraksi link)
│   ├── fingerprint.py       # deteksi tech
│   ├── http.py              # klien httpx async bersama
│   ├── models.py            # Finding / Page / Severity
│   ├── utils.py             # helper URL
│   ├── checks/              # 15 modul check + registry
│   ├── recon/               # subdomains + ports
│   └── reporting/           # renderer console / json / html
├── pyproject.toml           # packaging, console script `akar`
├── requirements.txt         # httpx[http2]>=0.27
└── README.md
```

Development tanpa install:

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m akar example.com --format console
```

---

## Uninstall

```bash
pip uninstall akar-scan
```

Kalau menjalankan dari venv, kamu bisa menghapus seluruh folder `.venv` saja.

---

## Penggunaan yang bertanggung jawab

- Hanya pindai target yang **kamu miliki** atau punya **izin tertulis eksplisit** untuk diuji.
- Hormati `--rate` dan ketentuan situs; jalankan mode agresif ke production tanpa izin
  pemilik.
- Temuan bisa berisi data sensitif (file terekspos, token). Tangani laporan dengan
  sewajarnya dan jangan dibagikan sembarangan.

---

*akar-scan v1.0.0 — dibangun dengan Python + httpx.*
