# x402 Bazaar Scan — Paxiom Receipts market research

Research scan of the Coinbase CDP **x402 Bazaar** discovery catalog to evaluate
demand and competition for **Paxiom Receipts** (a proof-bound receipt layer for
x402-paid APIs).

## TL;DR
- Read **`bazaar_summary.md`** for the full report and recommendation.
- Direct receipt/attestation competition **is already present** (21+ services)
  but **fragmented** — no standardized, provider-neutral proof-bound receipt
  layer exists yet. Paxiom is *adjacent-and-arriving*, not early.
- Recommended listing: a **receipt/settlement verifier** (MCP+REST) as the
  wedge, plus a **proof-bound receipt SDK/middleware** for sellers.

## Important: how this scan was produced
The live CDP discovery API (`api.cdp.coinbase.com`) is **blocked by this
environment's organization egress policy** (HTTP 403 to both `curl` and
`WebFetch`). Per proxy policy, denied hosts are reported, not bypassed. The
analysis therefore uses two **real, cited** offline datasets as a stand-in:

- `raw/catalog_pages/payload-exchange_top-resources_main.json` — a real Bazaar
  `discovery/resources` response (90 resources, full CDP `paymentAnalytics`
  metadata), committed at `github.com/microchipgnu/payload-exchange`
  (snapshot 2025-11-19).
- `raw/awesome-x402_README.md` — the community `github.com/xpaysh/awesome-x402`
  index (~150 live services), fetched 2026-07-07.

## Files
```
scan_x402_bazaar.py   # LIVE scanner — run where api.cdp.coinbase.com is reachable
build_from_corpus.py  # builds the CSVs from the offline corpus (what produced these)
bazaar_summary.md     # the report
raw/
  catalog_pages/      # raw catalog JSON (snapshot)
  search_results/     # per-term corpus match results
  awesome-x402_README.md
csv/
  bazaar_all_resources.csv
  bazaar_direct_receipt_competitors.csv
  bazaar_adjacent_demand.csv
  bazaar_search_summary.csv
  bazaar_top_hosts.csv
  bazaar_price_distribution.csv
  bazaar_relevant_outreach_targets.csv
```

## Refresh against the live catalog
```bash
pip install requests            # pandas/tenacity optional
export CDP_API_KEY_ID=...        # only if your origin requires CDP auth
export CDP_API_KEY_SECRET=...
python scan_x402_bazaar.py --out . --limit 1000
```
`scan_x402_bazaar.py` handles both `{"items":[...]}` and bare-array responses,
paginates, saves every raw page under `raw/`, runs all 39 search terms against
`/discovery/search`, and regenerates all seven CSVs. If the schema has changed,
unexpected shapes are logged and the flattener adapts.

## Constraints honored
No private personal data or commit emails collected; no GitHub-issue spam;
public project/manifest routes only; all raw responses + derived CSVs saved;
sources cited in `bazaar_summary.md`.
