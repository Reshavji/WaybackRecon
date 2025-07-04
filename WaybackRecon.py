#!/usr/bin/env python3
"""
WaybackRecon – Concurrent Wayback Machine enumerator
Author  : Reshav Ji
Updated : 2025-06-25

Requires Python ≥3.9
Third-party: requests, tqdm (optional for progress bar)
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, Field
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Set
from urllib.parse import quote

import requests

# ────────────────────────────── Configuration models ──────────────────────────────


@dataclass(slots=True)
class ScanConfig:
    domain: str
    from_date: str
    to_date: str
    keywords: Set[str] = field(default_factory=set)
    ignore_ext: Set[str] = field(
        default_factory=lambda: {
            "png", "jpg", "jpeg", "gif", "bmp", "svg", "webp", "ico",
            "tiff", "woff", "woff2", "eot", "ttf", "otf", "js", "css",
        }
    )
    sensitive_ext: Set[str] = field(
        default_factory=lambda: {
            "bak", "old", "zip", "tar", "gz", "7z", "sql", "env", "git",
            "conf", "log", "inc", "swp", "save", "tmp", "cache", "backup",
            "ini", "db",
        }
    )
    ignore_keywords: Set[str] = field(default_factory=lambda: {"robots.txt"})
    workers: int = 32
    timeout: int = 10
    verify_ssl: bool = True
    progress: bool = True


@dataclass
class ScanResult:
    url: str
    found_live: bool | None = None
    found_archive: str | None = None
    notes: str = ""


# ────────────────────────────── Core implementation ──────────────────────────────


class WaybackScanner:
    """High-level façade for Wayback enumeration and verification."""

    WAYBACK_CDX = (
        "https://web.archive.org/cdx/search/cdx?"
        "url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
        "&from={from_date}&to={to_date}"
    )
    WAYBACK_AVAILABLE = "https://archive.org/wayback/available?url={url}"

    def __init__(self, cfg: ScanConfig) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        self.session.verify = cfg.verify_ssl
        self._stop = False
        signal.signal(signal.SIGINT, self._sigint)

        # Pre-compile regexes
        self._ignore_ext_re = re.compile(
            r"\.(" + "|".join(re.escape(x) for x in cfg.ignore_ext) + r")(\?.*)?$",
            re.IGNORECASE,
        )
        self._sensitive_ext_re = re.compile(
            r"\.(" + "|".join(re.escape(x) for x in cfg.sensitive_ext) + r")$",
            re.IGNORECASE,
        )
        self._keyword_re = (
            re.compile("|".join(re.escape(k) for k in cfg.keywords), re.IGNORECASE)
            if cfg.keywords
            else None
        )

    # ─────────────────── Public entrypoint ───────────────────

    def run(self) -> List[ScanResult]:
        urls = self._fetch_wayback_urls()
        logging.info("Retrieved %d raw URLs", len(urls))

        candidates = self._apply_filters(urls)
        logging.info("Scanning %d candidate URLs", len(candidates))

        return self._verify(candidates)

    # ─────────────────── Internals ───────────────────

    def _fetch_wayback_urls(self) -> List[str]:
        url = self.WAYBACK_CDX.format(
            domain=quote(self.cfg.domain),
            from_date=self.cfg.from_date,
            to_date=self.cfg.to_date,
        )
        logging.debug("GET %s", url)
        try:
            resp = self.session.get(url, timeout=self.cfg.timeout)
            resp.raise_for_status()
        except Exception as exc:
            logging.error("Wayback CDX request failed: %s", exc)
            return []
        return list(dict.fromkeys(resp.text.splitlines()))  # dedupe, preserve order

    def _apply_filters(self, urls: Iterable[str]) -> List[str]:
        keep: List[str] = []
        for u in urls:
            if any(k in u.lower() for k in self.cfg.ignore_keywords):
                continue
            if self._ignore_ext_re.search(u.split("?")[0]):
                continue
            if self._sensitive_ext_re.search(u):
                keep.append(u)
            elif self._keyword_re and self._keyword_re.search(u):
                keep.append(u)
        return keep

    def _verify(self, urls: List[str]) -> List[ScanResult]:
        results: List[ScanResult] = []
        bar = _maybe_tqdm(urls, disable=not self.cfg.progress)
        with ThreadPoolExecutor(max_workers=self.cfg.workers) as tp:
            futs = {tp.submit(self._check_url, url): url for url in urls}
            for fut in as_completed(futs):
                if self._stop:
                    break
                results.append(fut.result())
                bar.update()
        bar.close()
        return results

    def _check_url(self, url: str) -> ScanResult:
        res = ScanResult(url=url)

        # Archived snapshot
        try:
            r = self.session.get(
                self.WAYBACK_AVAILABLE.format(url=quote(url)),
                timeout=self.cfg.timeout,
            )
            res.found_archive = (
                r.json().get("archived_snapshots", {}).get("closest", {}).get("url")
            )
        except Exception as exc:
            res.notes += f"archive_err:{exc}; "

        # Live check
        try:
            lr = self.session.head(url, allow_redirects=True, timeout=self.cfg.timeout)
            res.found_live = lr.status_code < 400
        except Exception as exc:
            res.notes += f"live_err:{exc}; "

        return res

    # ─────────────────── SIGINT handler ───────────────────

    def _sigint(self, *_):
        logging.warning("Interrupted by user, shutting down…")
        self._stop = True


# ────────────────────────────── Output helpers ──────────────────────────────


def save_results(results: List[ScanResult], path: Path, fmt: str) -> None:
    """Write results to TXT | CSV | JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().isoformat(sep=" ", timespec="seconds")
    header = f"# Wayback scan • {len(results)} URLs • {timestamp}\n"

    if fmt == "txt":
        with path.open("w", encoding="utf-8") as fp:
            fp.write(header)
            for r in results:
                line = f"[LIVE] {r.url}\n" if r.found_live else ""
                line += f"[ARCHIVE] {r.found_archive}\n" if r.found_archive else ""
                line = line or f"[MISS] {r.url}\n"
                fp.write(line)

    elif fmt == "csv":
        with path.open("w", newline="", encoding="utf-8") as fp:
            writer = csv.writer(fp)
            writer.writerow(["url", "live", "archive"])
            for r in results:
                writer.writerow([r.url, r.found_live, r.found_archive or ""])

    elif fmt == "json":
        with path.open("w", encoding="utf-8") as fp:
            json.dump([r.__dict__ for r in results], fp, indent=2)

    else:
        raise ValueError(f"Unknown format: {fmt}")

    logging.info("Results written to %s (%s)", path, fmt.upper())


# ────────────────────────────── CLI parsing ──────────────────────────────


def parse_cli(argv: List[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="WaybackRecon",
        description="Concurrent Wayback Machine sensitive-file enumerator",
    )
    p.add_argument("-u", "--url", required=True, help="Target domain (example.com)")
    p.add_argument(
        "-p", "--period", required=True, metavar="FROM-TO",
        help="Date range (e.g. 20100101-20250625)"
    )
    p.add_argument("-k", "--keywords", help="Comma-separated keyword list")
    p.add_argument("--ignore-ext", help="Extra ignore extensions (comma list)")
    p.add_argument("--sensitive-ext", help="Extra sensitive extensions (comma list)")
    p.add_argument("-w", "--workers", type=int, default=32,
                   help="Concurrent worker threads (default 32)")
    p.add_argument("-o", "--output", default="wayback_results.txt",
                   help="Output file name")
    p.add_argument("--format", choices=("txt", "csv", "json"), default="txt",
                   help="Output format")
    p.add_argument("--no-ssl-verify", action="store_true",
                   help="Disable TLS certificate validation")
    p.add_argument("--no-progress", action="store_true", help="Hide progress bar")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity")
    return p.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    args = parse_cli(argv)

    if "-" not in args.period:
        sys.exit("Period must be FROM-TO (e.g. 20100101-20250625)")

    from_date, to_date = args.period.split("-", 1)

    # Logging setup
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    cfg = ScanConfig(
        domain=args.url,
        from_date=from_date,
        to_date=to_date,
        keywords={k.strip() for k in args.keywords.split(",")} if args.keywords else set(),
        ignore_ext=_merge_lists(ScanConfig.ignore_ext, args.ignore_ext),
        sensitive_ext=_merge_lists(ScanConfig.sensitive_ext, args.sensitive_ext),
        workers=args.workers,
        verify_ssl=not args.no_ssl_verify,
        progress=not args.no_progress,
    )

    scanner = WaybackScanner(cfg)
    results = scanner.run()
    save_results(results, Path(args.output), args.format)


# ─────────────────── helper: merge default+CLI lists safely ───────────────────


def _merge_lists(default_obj, extra: str | None) -> Set[str]:
    """
    Merge default extensions (set or Field) with comma-list overrides.
    """
    if isinstance(default_obj, set):
        merged = set(default_obj)
    elif isinstance(default_obj, Field) and callable(default_obj.default_factory):
        merged = set(default_obj.default_factory())
    else:
        merged = set()

    if extra:
        merged.update(x.strip().lower() for x in extra.split(",") if x.strip())

    return merged


# ────────────────────────────── tqdm helper ──────────────────────────────


def _maybe_tqdm(iterable, **kwargs):
    """Return tqdm(iterable) if tqdm installed, else the iterable itself."""
    try:
        from tqdm import tqdm

        return tqdm(iterable, **kwargs)
    except ModuleNotFoundError:
        return iterable


if __name__ == "__main__":
    main()
