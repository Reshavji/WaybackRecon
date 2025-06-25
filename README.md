
# 🕵️‍♂️ WaybackRecon

**WaybackRecon** is an advanced reconnaissance tool that leverages the **Wayback Machine** (archive.org) to fetch, filter, and analyze historical URLs for a given domain. It helps security researchers, bug‑bounty hunters, DFIR analysts, and OSINT professionals uncover **sensitive files**, legacy endpoints, and forgotten attack surfaces that still linger in archived snapshots or remain live in production.

---

## ✨ Key Features
- **Targeted Wayback scraping** – pull all snapshots for `*.example.com/*` across any custom date range  
- **Noise‑free filtering** – ignore images, fonts, scripts, and other static assets automatically  
- **Sensitive‑file detection** – flag secrets such as `.env`, `.sql`, `.bak`, `.log`, etc., or any custom extension list  
- **Keyword hunting** – search URLs for tokens like `password`, `api`, `backup`, etc. (regex‑powered)  
- **Live vs. Archived check** – verify if a URL is still reachable (`HEAD 200`) and capture its closest archive snapshot  
- **Highly concurrent** – thread‑pool architecture (user‑tunable, default 32 workers) for fast scans  
- **Flexible outputs** – export findings to **TXT**, **CSV**, or **JSON** for downstream tooling  
- **Progress & logging** – optional tqdm progress bar plus granular `INFO`/`DEBUG` verbosity flags  

---

## 🛠 Installation
> Python **3.9+** is required.

```bash
# clone the repo
git clone https://github.com/yourusername/WaybackRecon.git && cd WaybackRecon

# install core dependencies
pip install -r requirements.txt      # requests, tqdm (optional)
```

If you only need the bare minimum:

```bash
pip install requests tqdm            # tqdm is optional but recommended
```

---

## 🚀 Quick Start

```bash
# Pull every snapshot for the domain since 2019, save raw list
python wayback_recon.py -u example.com -p 20190101-20250625 -o all_urls.txt

# Find .env, .sql, .bak, or anything containing "password" or "token"
python wayback_recon.py -u example.com -p 2010-2025 \
    -k password,token \
    --sensitive-ext env,sql,bak \
    --format csv -o sensitive_hits.csv
```

---

## ⚙️ Command‑Line Options

| Flag | Purpose |
|------|---------|
| `-u, --url` | Target root domain (e.g. `example.com`) |
| `-p, --period` | Date range `FROM-TO` (YYYYMMDD), e.g. `20190101-20250625` |
| `-k, --keywords` | Comma‑separated keyword list (`password,config,backup`) |
| `-o, --output` | Output filename _(default `wayback_results.txt`)_ |
| `--format` | Output style: `txt`, `csv`, `json` _(default `txt`)_ |
| `-w, --workers` | Thread count _(default 32)_ |
| `--ignore-ext` | Extra extensions to skip (comma‑list) |
| `--sensitive-ext` | Extra sensitive extensions to flag |
| `--no-progress` | Disable tqdm bar |
| `--no-ssl-verify` | Skip TLS certificate validation |
| `-v / -vv` | Increase log verbosity |

Run `python wayback_recon.py -h` anytime to see the full help text.

---

## 🔎 Interpreting Results

| Tag | Meaning |
|-----|---------|
| `[LIVE]` | URL responded with HTTP status <400 during scan |
| `[ARCHIVE]` | Closest archived snapshot URL returned by the Wayback API |
| `[MISS]` | Neither live nor archived match available (snapshot may exist outside range) |

Example TXT output:

```
[LIVE] https://example.com/.env
[ARCHIVE] https://web.archive.org/web/20210612075830/https://example.com/backup.sql
[MISS] https://example.com/robots.txt
```

---

## 🎯 Practical Use Cases
- Map forgotten sub‑directories before running active scans  
- Identify leaked secrets or configuration files left in prior deploys  
- Correlate API endpoints between historical and current versions  
- Feed discovered URLs into vulnerability scanners (Burp, Nuclei, etc.)  
- Support **DFIR** workflows by reconstructing an application's past attack surface  

---

## 🗺 Roadmap
- [ ] Asynchronous `httpx` backend for even faster scans  
- [ ] Passive DNS enrichment & subdomain expansion  
- [ ] Burp/ZAP extension export  
- [ ] Slack / Discord webhook reporting  
- [ ] Docker image & GitHub Action for CI/CD pipelines  

Have an idea? [Open an issue](https://github.com/yourusername/WaybackRecon/issues) or submit a PR!

---

## 🤝 Contributing
1. Fork the project & create your feature branch (`git checkout -b feature/AmazingFeature`)  
2. Commit your changes with clear messages  
3. Push to the branch (`git push origin feature/AmazingFeature`)  
4. Open a Pull Request  

Please run `pre-commit run --all-files` (if configured) and ensure unit tests pass.

---

## 📜 License
WaybackRecon is released under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

## ⚠️ Disclaimer
WaybackRecon is provided **for educational and authorized security‑testing purposes only**. Scanning domains without explicit permission may violate the law. The author assumes **no liability** for misuse.

---

## 👤 Author
**Reshav ji**  
- Email: <reshavkumar9837@gmail.com>  
- LinkedIn / GitHub: [@ReshavKumar](https://github.com/Reshavji)

---

## ⭐ Support & Feedback
If you find WaybackRecon useful, **star the repo** and spread the word!  
Issues, bugs, or feature requests? Please open an issue or contact me on email.

Happy recon 🕵️‍♂️🚀
