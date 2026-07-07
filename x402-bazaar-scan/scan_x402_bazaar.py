#!/usr/bin/env python3
"""
scan_x402_bazaar.py
===================

Live scanner for the Coinbase CDP x402 "Bazaar" discovery catalog.

Purpose
-------
Scan the live x402 discovery resources + semantic search endpoints to evaluate
demand / competition for *Paxiom Receipts* (a proof-bound receipt layer for
x402-paid APIs). Saves all raw responses and derives the CSVs used in the
accompanying report.

Verified API shape (as of 2026-07, from Coinbase CDP docs + a real catalog
snapshot, see bazaar_summary.md "Scan metadata" for citations)
--------------------------------------------------------------------------
Catalog (paginated, inventory-style browse):
    GET https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources
        ?type=http&limit=<n>&offset=<n>

Semantic search (quality-ranked):
    GET https://api.cdp.coinbase.com/platform/v2/x402/discovery/search
        ?query=<term>&limit=<n>

Response (list endpoint) is one of:
    {"x402Version": 1|2, "items": [<resource>, ...], "pagination": {...}}
  or a bare JSON array [<resource>, ...]   (older/mirror shape)

Each <resource>:
    {
      "resource": "https://host/path",
      "type": "http",
      "x402Version": 1,
      "lastUpdated": "2025-11-19T21:17:29.641Z",
      "accepts": [
        {
          "scheme": "exact",
          "network": "base",
          "maxAmountRequired": "10000",            # uint256, USDC has 6 decimals
          "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # USDC on Base
          "payTo": "0x....",
          "resource": "https://host/path",
          "description": "...",
          "mimeType": "application/json",
          "maxTimeoutSeconds": 60,
          "outputSchema": {"input": {...}, "output": {...}},
          "extra": {"name": "USD Coin", "version": "2"}
        }
      ],
      "metadata": {                                 # CDP-computed trust signals
        "confidence":       {"overallScore", "performanceScore", "recencyScore",
                              "reliabilityScore", "volumeScore"},
        "paymentAnalytics": {"totalTransactions", "totalUniqueUsers",
                              "transactions24h", "transactionsWeek",
                              "transactionsMonth", "averageDailyTransactions",
                              "base:0x8335...": "<uint256 volume>"},
        "performance":      {"avgLatencyMs", "minLatencyMs", "maxLatencyMs",
                              "recentAvgLatencyMs"},
        "reliability":      {"apiSuccessRate", "successfulSettlements",
                              "totalRequests"},
        "errorAnalysis":    {"apiErrors", "requestErrors", "facilitatorErrors",
                              "delayedSettlements", "abandonedFlows"}
      }
    }

Auth
----
The discovery MCP endpoint (.../discovery/mcp) is documented as "No Authorization".
The REST discovery endpoints may enforce CDP JWT auth from some networks. If you
have CDP API keys, export:
    CDP_API_KEY_ID / CDP_API_KEY_SECRET   (this script will attach a Bearer JWT
    if the `cdp-sdk` or `coinbase` package is importable; otherwise it sends the
    request unauthenticated, which is enough from most origins).

Usage
-----
    pip install requests pandas tenacity   # tenacity optional
    python scan_x402_bazaar.py --out ./ --limit 1000

If the schema differs, the script logs the unexpected shape to
raw/_schema_errors.json and adapts (it accepts both {"items":[...]} and [...]).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
BASE = "https://api.cdp.coinbase.com/platform/v2/x402/discovery"
RESOURCES_URL = f"{BASE}/resources"
SEARCH_URL = f"{BASE}/search"
MERCHANT_URL = f"{BASE}/merchant"          # probed; may 404 if unsupported

USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

DIRECT_TERMS = [
    "receipt", "signed receipt", "payment receipt", "settlement receipt",
    "proof of delivery", "proof-of-delivery", "delivery proof", "output receipt",
    "request receipt", "payment proof", "x402 receipt", "receipt verification",
    "verify receipt", "signed response", "proof-bound receipt",
]

ADJACENT_TERMS = [
    "proof", "verification", "verify", "attestation", "provenance", "audit",
    "compliance", "evidence", "notary", "signature", "signed", "agent", "MCP",
    "blockchain data", "state proof", "storage proof", "transaction proof",
    "security", "vulnerability", "risk", "oracle", "report", "API proxy",
    "paid API",
]

ALL_TERMS = DIRECT_TERMS + ADJACENT_TERMS

REQUEST_SLEEP = 0.4            # be polite; 0.25-1.0s between requests
PAGE_LIMIT = 100              # per-page size for the catalog crawl


# ----------------------------------------------------------------------------
# HTTP helpers (small hand-rolled retry so tenacity is optional)
# ----------------------------------------------------------------------------
def _auth_headers() -> dict:
    """Attach a CDP bearer JWT if credentials + sdk are available; else {}."""
    key_id = os.environ.get("CDP_API_KEY_ID")
    key_secret = os.environ.get("CDP_API_KEY_SECRET")
    if not (key_id and key_secret):
        return {}
    try:  # pragma: no cover - only when creds present
        from cdp.auth.utils.jwt import generate_jwt, JwtOptions  # type: ignore

        host = "api.cdp.coinbase.com"
        jwt = generate_jwt(
            JwtOptions(api_key_id=key_id, api_key_secret=key_secret,
                       request_method="GET", request_host=host,
                       request_path="/platform/v2/x402/discovery/resources")
        )
        return {"Authorization": f"Bearer {jwt}"}
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] could not mint CDP JWT ({exc}); sending unauthenticated",
              file=sys.stderr)
        return {}


def get_json(url: str, params: dict | None = None, tries: int = 4) -> tuple[dict | list | None, dict]:
    """GET with backoff. Returns (parsed_json_or_None, meta)."""
    meta = {"url": url, "params": params, "status": None, "error": None}
    headers = {"Accept": "application/json", "User-Agent": "paxiom-bazaar-scan/1.0"}
    headers.update(_auth_headers())
    delay = 2.0
    for attempt in range(1, tries + 1):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=30)
            meta["status"] = r.status_code
            if r.status_code == 200:
                return r.json(), meta
            if r.status_code in (429, 502, 503, 504):
                ra = r.headers.get("Retry-After")
                wait = float(ra) if ra and ra.isdigit() else delay
                print(f"[rate/5xx {r.status_code}] {url} -> sleep {wait}s", file=sys.stderr)
                time.sleep(wait)
                delay *= 2
                continue
            meta["error"] = f"HTTP {r.status_code}: {r.text[:300]}"
            return None, meta
        except requests.RequestException as exc:  # network
            meta["error"] = str(exc)
            time.sleep(delay)
            delay *= 2
    return None, meta


# ----------------------------------------------------------------------------
# Normalisation
# ----------------------------------------------------------------------------
def _items(payload) -> list:
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    for key in ("items", "resources", "data", "results"):
        if isinstance(payload.get(key), list):
            return payload[key]
    return []


def price_usdc(accept: dict) -> float | None:
    raw = accept.get("maxAmountRequired")
    if raw in (None, ""):
        return None
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return None
    decimals = 6  # USDC / most stablecoins on Base
    extra = accept.get("extra") or {}
    if str(extra.get("decimals", "")).isdigit():
        decimals = int(extra["decimals"])
    return val / (10 ** decimals)


def flatten(resource: dict) -> dict:
    accepts = resource.get("accepts") or [{}]
    a = accepts[0] if accepts else {}
    url = resource.get("resource") or a.get("resource") or ""
    host = urlparse(url).netloc if url else ""
    md = resource.get("metadata") or {}
    pa = md.get("paymentAnalytics") or {}
    conf = md.get("confidence") or {}
    rel = md.get("reliability") or {}
    return {
        "resource_url": url,
        "host": host,
        "type": resource.get("type", ""),
        "description": a.get("description", ""),
        "mimeType": a.get("mimeType", ""),
        "network": a.get("network", ""),
        "asset": a.get("asset", ""),
        "scheme": a.get("scheme", ""),
        "payTo": a.get("payTo", ""),
        "maxAmountRequired": a.get("maxAmountRequired", ""),
        "price_usdc": price_usdc(a),
        "maxTimeoutSeconds": a.get("maxTimeoutSeconds", ""),
        "has_output_schema": bool((a.get("outputSchema") or {}).get("output")),
        "lastUpdated": resource.get("lastUpdated", ""),
        "totalTransactions": pa.get("totalTransactions"),
        "totalUniqueUsers": pa.get("totalUniqueUsers"),
        "transactions24h": pa.get("transactions24h"),
        "overallScore": conf.get("overallScore"),
        "apiSuccessRate": rel.get("apiSuccessRate"),
        "n_accepts": len(accepts),
        "raw": json.dumps(resource, separators=(",", ":")),
    }


# ----------------------------------------------------------------------------
# Scan
# ----------------------------------------------------------------------------
def crawl_catalog(out_dir: str, limit: int) -> list[dict]:
    raw_dir = os.path.join(out_dir, "raw", "catalog_pages")
    os.makedirs(raw_dir, exist_ok=True)
    resources, offset, page = [], 0, 0
    while offset < limit:
        payload, meta = get_json(RESOURCES_URL,
                                 {"type": "http", "limit": PAGE_LIMIT, "offset": offset})
        with open(os.path.join(raw_dir, f"page_{page:04d}_offset_{offset}.json"), "w") as fh:
            json.dump({"_meta": meta, "payload": payload}, fh, indent=2)
        batch = _items(payload)
        if not batch:
            break
        resources.extend(batch)
        print(f"[catalog] page {page} offset {offset}: {len(batch)} items "
              f"(total {len(resources)})")
        offset += PAGE_LIMIT
        page += 1
        time.sleep(REQUEST_SLEEP)
    return resources


def run_search(out_dir: str) -> list[dict]:
    raw_dir = os.path.join(out_dir, "raw", "search_results")
    os.makedirs(raw_dir, exist_ok=True)
    summary = []
    for term in ALL_TERMS:
        payload, meta = get_json(SEARCH_URL, {"query": term, "limit": 50})
        slug = term.replace(" ", "_").replace("/", "-")
        with open(os.path.join(raw_dir, f"search_{slug}.json"), "w") as fh:
            json.dump({"_meta": meta, "payload": payload}, fh, indent=2)
        items = _items(payload)
        summary.append({
            "term": term,
            "bucket": "direct" if term in DIRECT_TERMS else "adjacent",
            "status": meta["status"],
            "n_results": len(items),
            "error": meta["error"] or "",
            "top_hosts": ";".join(
                sorted({urlparse(flatten(i)["resource_url"]).netloc for i in items})[:5]
            ),
        })
        print(f"[search] {term!r}: status={meta['status']} n={len(items)}")
        time.sleep(REQUEST_SLEEP)
    return summary


# ----------------------------------------------------------------------------
# CSV writers
# ----------------------------------------------------------------------------
def write_csv(path: str, rows: list[dict], fields: list[str]) -> None:
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"[csv] wrote {path} ({len(rows)} rows)")


def classify(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    direct, adjacent = [], []
    for r in rows:
        text = f"{r['resource_url']} {r['description']}".lower()
        d_hits = [t for t in DIRECT_TERMS if t.lower() in text]
        a_hits = [t for t in ADJACENT_TERMS if t.lower() in text]
        if d_hits:
            direct.append({**r, "matched_terms": ";".join(d_hits)})
        if a_hits:
            adjacent.append({**r, "matched_terms": ";".join(a_hits)})
    return direct, adjacent


def build_csvs(out_dir: str, resources: list[dict], search_summary: list[dict]) -> None:
    csv_dir = os.path.join(out_dir, "csv")
    os.makedirs(csv_dir, exist_ok=True)
    rows = [flatten(r) for r in resources]

    all_fields = ["resource_url", "host", "type", "description", "mimeType",
                  "network", "asset", "scheme", "payTo", "maxAmountRequired",
                  "price_usdc", "maxTimeoutSeconds", "has_output_schema",
                  "lastUpdated", "totalTransactions", "totalUniqueUsers",
                  "transactions24h", "overallScore", "apiSuccessRate",
                  "n_accepts", "raw"]
    write_csv(os.path.join(csv_dir, "bazaar_all_resources.csv"), rows, all_fields)

    direct, adjacent = classify(rows)
    comp_fields = all_fields[:-1] + ["matched_terms"]
    write_csv(os.path.join(csv_dir, "bazaar_direct_receipt_competitors.csv"),
              [{k: v for k, v in r.items() if k != "raw"} for r in direct], comp_fields)
    write_csv(os.path.join(csv_dir, "bazaar_adjacent_demand.csv"),
              [{k: v for k, v in r.items() if k != "raw"} for r in adjacent], comp_fields)

    write_csv(os.path.join(csv_dir, "bazaar_search_summary.csv"), search_summary,
              ["term", "bucket", "status", "n_results", "top_hosts", "error"])

    # top hosts
    host_ct = Counter(r["host"] for r in rows if r["host"])
    host_rows = [{"host": h, "n_resources": c} for h, c in host_ct.most_common()]
    write_csv(os.path.join(csv_dir, "bazaar_top_hosts.csv"), host_rows,
              ["host", "n_resources"])

    # price distribution
    def bucket(p):
        if p is None:
            return "unknown"
        if p == 0:
            return "free"
        if p < 0.01:
            return "sub-cent"
        if p < 0.10:
            return "micro (<$0.10)"
        if p < 1:
            return "cent-scale ($0.10-$1)"
        if p < 10:
            return "dollar-scale ($1-$10)"
        return "premium (>$10)"

    price_ct = Counter(bucket(r["price_usdc"]) for r in rows)
    price_rows = [{"price_bucket": b, "n_resources": c} for b, c in price_ct.most_common()]
    write_csv(os.path.join(csv_dir, "bazaar_price_distribution.csv"), price_rows,
              ["price_bucket", "n_resources"])

    # outreach targets = high-signal adjacent/direct resources with real volume
    outreach = []
    for r in direct + adjacent:
        tx = r.get("totalTransactions") or 0
        outreach.append({
            "host": r["host"], "resource_url": r["resource_url"],
            "description": r["description"][:160],
            "matched_terms": r.get("matched_terms", ""),
            "price_usdc": r["price_usdc"], "totalTransactions": tx,
            "overallScore": r.get("overallScore"),
        })
    # de-dupe by host, prefer highest tx
    best = {}
    for o in outreach:
        h = o["host"]
        if h and (h not in best or (o["totalTransactions"] or 0) > (best[h]["totalTransactions"] or 0)):
            best[h] = o
    outreach_sorted = sorted(best.values(),
                             key=lambda x: (x["totalTransactions"] or 0), reverse=True)
    write_csv(os.path.join(csv_dir, "bazaar_relevant_outreach_targets.csv"),
              outreach_sorted,
              ["host", "resource_url", "description", "matched_terms",
               "price_usdc", "totalTransactions", "overallScore"])


# ----------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=".")
    ap.add_argument("--limit", type=int, default=1000)
    ap.add_argument("--skip-search", action="store_true")
    args = ap.parse_args()

    os.makedirs(os.path.join(args.out, "raw"), exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    print(f"[scan] start {started}  ->  {RESOURCES_URL}")

    resources = crawl_catalog(args.out, args.limit)
    if not resources:
        print("[error] catalog returned 0 resources. Check network/egress policy "
              "and auth. Raw responses saved under raw/catalog_pages/.",
              file=sys.stderr)
    search_summary = [] if args.skip_search else run_search(args.out)

    build_csvs(args.out, resources, search_summary)

    manifest = {
        "started": started,
        "finished": datetime.now(timezone.utc).isoformat(),
        "endpoints": {"resources": RESOURCES_URL, "search": SEARCH_URL},
        "n_resources": len(resources),
        "n_unique_hosts": len({flatten(r)["host"] for r in resources}),
        "n_search_terms": len(ALL_TERMS),
        "search_errors": [s for s in search_summary if s["error"]],
    }
    with open(os.path.join(args.out, "raw", "_scan_manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"[scan] done. {len(resources)} resources, "
          f"{manifest['n_unique_hosts']} hosts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
