
# 🕵️‍♂️ WaybackRecon

WaybackRecon is an advanced reconnaissance tool that leverages the Wayback Machine to extract, filter, and analyze historical URLs of a target domain. It helps security researchers, bug bounty hunters, and OSINT professionals discover sensitive files, exposed endpoints, and archived snapshots efficiently. It supports keyword filtering, file extension filters, archived/live checks, and outputs results in TXT, CSV, or JSON formats. Built for speed with multi-threaded scanning.

## Usage Example

```bash
python wayback_recon.py -u example.com -p 20190101-20250625 -o output.txt
python wayback_recon.py -u target.com -p 20180101-20241231 -k token,apikey,config -w 64 --format json -o sensitive.json
```

## Installation

Python 3.9+ required  
Install dependencies:

```bash
pip install requests tqdm
```

## Options

- `-u, --url` → Target domain (e.g., example.com)  
- `-p, --period` → Date range (e.g., 20190101-20240101)  
- `-k, --keywords` → Comma-separated keywords (e.g., password,config)  
- `-o, --output` → Output filename (default: wayback_results.txt)  
- `--format` → Output format: txt, csv, json  
- `-w, --workers` → Number of threads (default: 32)  
- `--ignore-ext` → Extra static file extensions to ignore  
- `--sensitive-ext` → Extra sensitive file extensions to detect  
- `--no-progress` → Disable progress bar  
- `--no-ssl-verify` → Disable SSL verification  
- `-v, --verbose` → Increase logging verbosity  

## Example Output

```
[LIVE] https://example.com/.env  
[ARCHIVE] https://web.archive.org/web/20210612075830/https://example.com/backup.sql  
[MISS] https://example.com/robots.txt
```

## Use Cases

- Bug bounty reconnaissance  
- Sensitive file exposure hunting  
- Hidden endpoint discovery  
- OSINT and historical web app analysis

## Disclaimer

This tool is for **educational and authorized testing purposes only**. Do not scan targets without proper permission.

## Author

**Reshav Kumar**  
GitHub: [@ReshavKumar](https://github.com/)  
Email: reshav@example.com

⭐ If you like this tool, give it a star!
