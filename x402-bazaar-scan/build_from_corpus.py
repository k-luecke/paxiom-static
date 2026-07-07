#!/usr/bin/env python3
"""
build_from_corpus.py
====================

Builds the Paxiom x402-Bazaar analysis CSVs from the *offline corpus* that could
be collected in this egress-restricted environment (the live CDP discovery API
host `api.cdp.coinbase.com` is blocked by the session's org egress policy, and
returns HTTP 403 to both curl and WebFetch — see bazaar_summary.md).

Two real, cited datasets are used as a stand-in for the live catalog:

  A. CATALOG SNAPSHOT (real Bazaar `discovery/resources` response, 90 resources
     with full CDP `metadata.paymentAnalytics` trust signals), committed at
     github.com/microchipgnu/payload-exchange
       server/core/resources/top-resources.json  (snapshot dated 2025-11-19)
     -> raw/catalog_pages/payload-exchange_top-resources_main.json

  B. ECOSYSTEM LIST (curated, current) from the community `awesome-x402` index,
     github.com/xpaysh/awesome-x402  -> raw/awesome-x402_README.md
     The receipt/proof/attestation/audit/security entries are transcribed below
     with README line numbers for citation. This captures services that market
     signed-receipt / proof-of-delivery / attestation behaviour explicitly,
     which the sparse catalog `description` fields do not surface.

When run against the LIVE API instead, use scan_x402_bazaar.py.
"""
from __future__ import annotations

import csv
import json
import os
from collections import Counter
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")
CSV = os.path.join(HERE, "csv")
os.makedirs(CSV, exist_ok=True)
os.makedirs(os.path.join(RAW, "search_results"), exist_ok=True)

USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

DIRECT_TERMS = [
    "receipt", "signed receipt", "payment receipt", "settlement receipt",
    "proof of delivery", "proof-of-delivery", "delivery proof", "output receipt",
    "request receipt", "payment proof", "x402 receipt", "receipt verification",
    "verify receipt", "signed response", "proof-bound receipt",
]
ADJACENT_TERMS = [
    "proof", "verification", "verify", "attestation", "provenance", "audit",
    "compliance", "evidence", "notary", "signature", "signed", "agent", "mcp",
    "blockchain data", "state proof", "storage proof", "transaction proof",
    "security", "vulnerability", "risk", "oracle", "report", "api proxy",
    "paid api",
]

# ---------------------------------------------------------------------------
# A. Load the real catalog snapshot
# ---------------------------------------------------------------------------
def price_usdc(accept):
    raw = accept.get("maxAmountRequired")
    if raw in (None, ""):
        return None
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return None
    dec = 6
    extra = accept.get("extra") or {}
    if str(extra.get("decimals", "")).isdigit():
        dec = int(extra["decimals"])
    return round(val / (10 ** dec), 6)


def flatten(resource):
    accepts = resource.get("accepts") or [{}]
    a = accepts[0] if accepts else {}
    url = resource.get("resource") or a.get("resource") or ""
    md = resource.get("metadata") or {}
    pa = md.get("paymentAnalytics") or {}
    conf = md.get("confidence") or {}
    rel = md.get("reliability") or {}
    return {
        "resource_url": url,
        "host": urlparse(url).netloc if url else "",
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
        "overallScore": (conf or {}).get("overallScore"),
        "apiSuccessRate": (rel or {}).get("apiSuccessRate"),
        "n_accepts": len(accepts),
        "raw": json.dumps(resource, separators=(",", ":")),
    }


def load_catalog():
    path = os.path.join(RAW, "catalog_pages",
                        "payload-exchange_top-resources_main.json")
    with open(path) as fh:
        data = json.load(fh)
    return [flatten(r) for r in data]


# ---------------------------------------------------------------------------
# B. Curated ecosystem list (from awesome-x402 README; line = citation)
#    signal: DIRECT (receipt/proof-of-delivery/output-binding) or the adjacent
#    category the service demonstrates demand for.
# ---------------------------------------------------------------------------
# fields: name, url, category, price, signal, receipt_mechanism, readme_line, desc
ECO = [
    # ---- DIRECT: signed / proof-bound receipts, output-binding, verification ----
    ("swornly", "https://swornly.luci.ws", "receipt/verification", "$0.005-$0.02",
     "DIRECT", "HMAC-signed re-verifiable receipt per answer + free /receipts/verify endpoint", 455,
     "Deterministic signed-receipt tools; every answer returns an HMAC-signed, re-verifiable receipt. Closest product analogue to Paxiom (testnet)."),
    ("Mycelium Trails", "https://github.com/giskard09/giskard-stack", "receipt/audit", "21 sats/trail",
     "DIRECT", "signed trail: payment_hash + action_ref (SHA-256 commitment) + dual-chain anchor (Arbitrum+Base)", 691,
     "Post-execution accountability receipts for x402 payments; binds payment to action, verifiable by anyone, for audits/disputes/insurance. Closest conceptual analogue to Paxiom."),
    ("PayPerByte", "https://x402.payperbyte.io/feeds", "receipt/attestation", "$0.05",
     "DIRECT", "EIP-712 PayloadAttestation binds output bytes to signer; buyer re-derives keccak256, fails closed on tamper", 622,
     "Every paid response emits an EIP-712 PayloadAttestation binding output to signer; payment-to-output binding primitive."),
    ("@larkinsh/x402", "https://www.npmjs.com/package/@larkinsh/x402", "receipt/middleware", "n/a (npm)",
     "DIRECT", "Ed25519-signed receipts verifiable with only the public key", 300,
     "Authorization middleware returning Ed25519-signed receipts; closest to Paxiom's SDK/middleware distribution model."),
    ("@tensorfeed/x402-base-mcp", "https://www.npmjs.com/package/@tensorfeed/x402-base-mcp", "receipt-verification", "n/a (npm)",
     "DIRECT", "verify on-chain that a USDC settlement matches a claimed x402 receipt (recipient+amount)", 564,
     "Read-only Base reader purpose-built to verify that a settlement matches a claimed x402 receipt. Direct competitor on the *verification* side."),
    ("anchor-x402", "https://anchor-x402.com", "attestation/anchoring", "$0.001-$7.77",
     "DIRECT", "signed attestations + dual-chain hash anchoring; signed markdown report + anchor proof", 216,
     "16 services incl. signed attestations, dual-chain hash anchoring, verifiable signed RNG, on-chain anchored verdicts."),
    ("SYNTHORA md-extract", "https://pay.hergertsynthora.com/service", "attestation/output-binding", "$0.005",
     "DIRECT", "Ed25519 attestation receipt: buyer verifies offline that output came from this mesh untampered", 243,
     "Ships an Ed25519 attestation receipt per response - cryptographic chain-of-custody for scraped output. Output-binding analogue."),
    ("TWZRD Agent Intel", "https://intel.twzrd.xyz", "attestation/trust", "$0.05",
     "DIRECT", "signed twzrd.receipt.v5 trust receipts verifiable offline", 594,
     "Signed offline-verifiable trust receipts (versioned receipt schema) - same 'signed receipt as a product' shape as Paxiom."),
    ("TrustBoost PII Sanitizer", "https://api.trustboost.dev", "attestation/proof-of-execution", "$0.0149",
     "DIRECT", "every paid sanitization anchored on Solana via Helius; verify at /verify/{anchor_tx}", 235,
     "On-chain proof-of-execution per call, buyer-verifiable at a /verify endpoint. Proof-of-delivery analogue."),
    ("Kraken Crypto Signals", "https://signals.nsgoods.org", "signed-output/hash-chain", "$0.01-$0.10",
     "DIRECT", "ECDSA-signed responses + tamper-evident hash-chain track-record", 241,
     "Every response ECDSA-signed with a tamper-evident hash-chain; signed-response + integrity-chain analogue."),
    ("LION", "https://lionx402.com", "attestation/output-binding", "$ per call",
     "DIRECT", "every response Ed25519-attested, verify offline", 364,
     "20 compliance tools, every response Ed25519-attested and offline-verifiable."),
    ("Stratalize", "https://www.stratalize.com", "signed-output", "$0.02-$1.00",
     "DIRECT", "Ed25519-signed outputs on every synthesis", 146,
     "100+ intelligence tools with Ed25519-signed outputs on every synthesis."),
    ("AI Growth (verification)", "https://kjtirbnxxymeumycrhqv.supabase.co", "proof-of-execution", "$0.02",
     "DIRECT", "timestamped proof-of-execution receipts (HTTP status, latency, phantom/simulation detection)", 182,
     "Sells timestamped proof-of-execution receipts so agents can confirm an A2A service is real before paying. Verification-as-a-service."),
    ("Agent Passport System (APS)", "https://github.com/aeoess/agent-passport-system", "receipt/attestation/governance", "OSS",
     "DIRECT", "signed receipts with per-condition attestation; scoped delegation", 544,
     "Governance/delegation layer with signed receipts + per-condition attestation."),
    ("SafeAgent Execution Guard", "https://safeagent-production.up.railway.app", "receipt/audit", "$0.001",
     "DIRECT", "crash-safe receipts + audit endpoint + audit trail by agent wallet (two-phase PENDING->COMMITTED)", 543,
     "Exactly-once execution guard with crash-safe receipts and an audit trail keyed by agent wallet."),
    ("Boundary Guard", "https://boundary-guard.vercel.app", "receipt/pre-action", "n/a",
     "DIRECT", "deterministic receipt before downstream writes/sends (allow/retry/block)", 542,
     "Pre-action checkpoint returning a deterministic receipt before an agent acts."),
    ("Voidly Pay", "https://api.voidly.ai/v1/pay", "signed-envelope/facilitator", "rail",
     "DIRECT", "Ed25519-signed envelopes + facilitator-signed quotes + public proof of reserves at /v1/pay/proof", 342,
     "Payment rail with Ed25519-signed envelopes, facilitator-signed quotes (anti-MitM) and public proof of reserves."),
    ("Hive Civilization", "https://thehiveryiq.com", "attestation/receipt", "free+paid",
     "DIRECT", "verifiable Spectral receipts + ZK attestations across a 52-service fleet", 830,
     "52-service fleet emitting verifiable 'Spectral receipts' plus ZK attestations."),
    ("LogicNodes", "https://logicnodes.io", "trust-hash/integrity", "$ per call",
     "DIRECT", "SHA-256 trust hashes on 619 deterministic microservices, 8 chains", 0,
     "619 microservices each returning a SHA-256 trust hash for output integrity."),
    ("n0brains (/proof)", "https://n0brains.com", "audit/proof", "$0.005",
     "DIRECT", "live auditable per-signal-type win-rate proof at /proof (forward returns, 95% CI)", 232,
     "Publishes an auditable per-signal win-rate proof endpoint - provenance/track-record proof."),
    ("presidio-hardened-x402", "https://pypi.org/project/presidio-hardened-x402/", "verification/hardening", "OSS",
     "DIRECT", "pre-signing hardening: PII redaction + spending-policy + replay detection before payment is signed", 547,
     "Pre-signing middleware (fail-closed) over payment metadata; adjacent to receipt-integrity."),

    # ---- ADJACENT: security / risk / audit ----
    ("melis.ai x402 Tools", "https://agents.melis.ai", "security/audit", "$0.0005-$0.01",
     "security", "xAudit response auditing + prompt-injection screening (23 audit-verified endpoints)", 222,
     "23 audit-verified utility endpoints incl. xAudit response auditing and PromptGuard injection screening."),
    ("t54.ai secure-api", "https://x402-secure-api.t54.ai", "security", "$0.01",
     "security", "server security assessment with risk scoring", 0,
     "Server security assessment / overall risk score (present in live catalog snapshot)."),
    ("skill-audit / tokenguard / contract-guard", "https://eltociear-skill-audit.hf.space", "security/audit", "$ per scan",
     "security", "MCP server security scanner + ERC-20 rug scanner + contract risk check", 0,
     "Security scanners: MCP skill audit, token rug/safety, contract risk."),
    ("ShieldAPI MCP", "https://www.npmjs.com/package/shieldapi-mcp", "security", "$ per call",
     "security", "breach/domain/URL/skill scanning (9 tools)", 0,
     "9-tool security MCP (breach check, domain rep, skill audit)."),
    ("Daizyx402 Security Research", "https://daizyx402.com:5402", "security", "$ per call",
     "security", "AI-powered smart-contract security analysis", 0,
     "Smart contract security analysis API."),
    ("GPT55 x402", "https://gpt55.558686.xyz", "security/risk", "$ per call",
     "security", "wallet safety, EIP-712 risk decoding, approval auditing", 0,
     "Signing/approval risk decoding and approval auditing."),
    ("SolProbe / RugGuard / SolSignal", "https://api.solprobe.xyz", "security/risk", "$ per call",
     "risk", "token risk scanners (A-F grades, wash-trade detection, rug heuristics)", 0,
     "Token/contract risk scanners."),

    # ---- ADJACENT: compliance / provenance ----
    ("OSF - Open Source Filings", "https://osf-master-server.com", "provenance/compliance", "$0.05-$0.50",
     "provenance", "every record ships a provenance URL back to its authoritative primary source", 180,
     "Provenance-stamped government/scientific data with source-traceable records."),
    ("GlobalAPI", "https://globalapi.dev", "compliance", "$ per call",
     "compliance", "OFAC/FCDO/UN screening, 43 compliance/macro endpoints", 0,
     "Compliance screening (sanctions) endpoints."),
    ("CYBERA Compliance API", "https://compliance-api-ruddy.vercel.app", "compliance", "$ per call",
     "compliance", "VASP identification, crypto compliance risk scoring", 0,
     "Crypto compliance suite."),
    ("Sanctions Screening API", "https://sanctions.hugen.tokyo", "compliance", "$ per call",
     "compliance", "OFAC/EU/UN screening, 26,800+ entities, fuzzy matching", 0,
     "Sanctions screening compliance endpoint."),
    ("Melvea", "https://api.melvea.com", "provenance", "$0.02-$0.10",
     "provenance", "every datum resolvable to a real published source (DOI/PMID)", 231,
     "Citation-backed data with resolvable research provenance."),
    ("romefeller.app", "https://romefeller.app", "compliance/provenance", "$0.005-$0.15",
     "compliance", "PII scrub + document completeness verify + receipt extraction", 217,
     "Document intelligence: PII scrub, completeness verification, invoice/receipt extraction."),

    # ---- ADJACENT: blockchain data / state / oracle ----
    ("PayPerByte oracles", "https://x402.payperbyte.io/feeds", "oracle/blockchain-data", "$0.05",
     "oracle", "address-reputation + sanctions decision oracles; per-byte feeds", 622,
     "Decision oracles (address reputation, sanctions) with attested payloads."),
    ("Crest x402 Data", "https://data.crestsystems.ai", "blockchain-data", "$ per call",
     "blockchain data", "wallet profiling, whale scoring, risk assessment", 0,
     "On-chain wallet profiling and market data."),
    ("Deepnets / OpenPulsechain / Rug Munch", "https://api.deepnets.ai", "blockchain-data", "$ per call",
     "blockchain data", "token intelligence, analytics, 117+ tools", 0,
     "On-chain token intelligence / analytics fleets."),
    ("Seneschal", "https://seneschal.space", "blockchain-data/proof", "$0.001-$0.02",
     "state proof", "HMAC-signed payment webhooks; on-chain proof via Solana anchors", 227,
     "Monero/Zcash view-key payment watching with HMAC-signed webhook events."),
    ("bitquery x402 Data API", "https://docs.bitquery.io/docs/examples/x402/", "blockchain-data", "$ per call",
     "transaction proof", "query x402 payment transactions & server analytics on-chain", 0,
     "On-chain analytics over x402 payment transactions themselves (demand signal for settlement data)."),

    # ---- ADJACENT: agent / MCP tooling & marketplaces ----
    ("Agent402", "https://agent402.tools", "agent/mcp/marketplace", "free+paid",
     "agent", "~1,100 tools + open x402 index + leaderboard of sellers by settled USDC volume", 152,
     "Large agent-tool hub + the first public on-chain ranking of x402 sellers; a listing & discovery surface."),
    ("PayAPI Market", "https://payapi.market", "marketplace/proxy", "$ per call",
     "api proxy", "first x402 API marketplace (10 APIs, 65 endpoints)", 0,
     "x402 API marketplace - a distribution/listing surface."),
    ("Aigregator", "https://x402.aigregator.com", "marketplace/discovery", "$ per call",
     "agent", "structured data on 5,336+ AI tools, searchable + MCP", 0,
     "Meta-catalog of AI tools; discovery surface."),
    ("Pyrimid", "https://pyrimid.ai", "marketplace/registry", "$ per call",
     "agent", "on-chain vendor/product registry + payment router + live catalog", 186,
     "Agent commerce protocol with on-chain vendor/product registry."),
    ("Ontario Protocol", "https://ontarioprotocol.com", "verification/facilitator", "n/a",
     "verification", "trust scans & readiness verification, pre-payment checks, manifests", 0,
     "Trust scans / readiness verification and manifests (pre-payment)."),
    ("Sentinel", "https://sentinel-awms.onrender.com", "verification/security", "$ per call",
     "verification", "trust verification for AI agents, OFAC screening, preflight checks", 0,
     "Pre-payment trust verification and preflight checks for agents."),
    ("ZKProofport MCP", "https://github.com/zkproofport/proofport-ai", "attestation/zk", "$ per proof",
     "attestation", "ZK identity proofs (KYC/Country/OIDC) via TEE, ERC-8004 registered", 615,
     "Zero-knowledge identity proof MCP - proof-generation demand signal."),
    ("ALTER MCP", "https://mcp.truealter.com", "attestation/identity", "free-$0.50",
     "attestation", "Ed25519-signed identity vectors, tiered per-query", 572,
     "Identity attestation with Ed25519-signed vectors."),
    ("Agent Commerce Desk", "https://x402-wallet-readiness-service.vercel.app", "receipt/agent", "$0.01-$2.00",
     "agent", "agent-commerce receipt + wallet readiness endpoints", 703,
     "Ships an 'agent-commerce receipt' endpoint alongside wallet readiness."),
    ("Fast PDF Parser", "https://x402-parser-edge-mainnet.epicblubber.workers.dev", "proof/agent", "$0.002",
     "proof", "SHA-256-bound payment proofs with replay protection", 457,
     "Pay-per-parse with SHA-256-bound payment proofs and replay protection."),
]


def eco_rows():
    rows = []
    for (name, url, cat, price, signal, mech, line, desc) in ECO:
        rows.append({
            "name": name, "resource_url": url,
            "host": urlparse(url).netloc, "category": cat, "price": price,
            "signal": signal, "receipt_mechanism": mech,
            "awesome_readme_line": line, "description": desc,
        })
    return rows


# ---------------------------------------------------------------------------
# writers
# ---------------------------------------------------------------------------
def write_csv(path, rows, fields):
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"[csv] {os.path.basename(path)}: {len(rows)} rows")


def term_scan(catalog, eco):
    """Offline emulation of discovery/search: count corpus matches per term."""
    summary = []
    for term in DIRECT_TERMS + ADJACENT_TERMS:
        t = term.lower()
        cat_hits = [r for r in catalog
                    if t in f"{r['resource_url']} {r['description']}".lower()]
        eco_hits = [e for e in eco
                    if t in f"{e['name']} {e['resource_url']} {e['receipt_mechanism']} "
                            f"{e['description']} {e['category']}".lower()]
        hosts = sorted({r["host"] for r in cat_hits} |
                       {e["host"] for e in eco_hits})
        summary.append({
            "term": term,
            "bucket": "direct" if term in DIRECT_TERMS else "adjacent",
            "catalog_matches": len(cat_hits),
            "ecosystem_matches": len(eco_hits),
            "total_matches": len(cat_hits) + len(eco_hits),
            "example_hosts": ";".join(hosts[:6]),
        })
        # persist per-term "search result" json (offline corpus)
        slug = term.replace(" ", "_").replace("/", "-")
        with open(os.path.join(RAW, "search_results", f"search_{slug}.json"), "w") as fh:
            json.dump({
                "term": term, "source": "offline-corpus (catalog snapshot + awesome-x402)",
                "catalog_matches": [r["resource_url"] for r in cat_hits],
                "ecosystem_matches": [e["name"] for e in eco_hits],
            }, fh, indent=2)
    return summary


def main():
    catalog = load_catalog()
    eco = eco_rows()

    # 1. all resources (real catalog)
    all_fields = ["resource_url", "host", "type", "description", "mimeType",
                  "network", "asset", "scheme", "payTo", "maxAmountRequired",
                  "price_usdc", "maxTimeoutSeconds", "has_output_schema",
                  "lastUpdated", "totalTransactions", "totalUniqueUsers",
                  "transactions24h", "overallScore", "apiSuccessRate",
                  "n_accepts", "raw"]
    write_csv(os.path.join(CSV, "bazaar_all_resources.csv"), catalog, all_fields)

    # 2. direct competitors (ecosystem signal DIRECT + any catalog term hits)
    direct = [e for e in eco if e["signal"] == "DIRECT"]
    cat_direct = []
    for r in catalog:
        text = f"{r['resource_url']} {r['description']}".lower()
        hits = [t for t in DIRECT_TERMS if t in text]
        if hits:
            cat_direct.append({
                "name": r["host"], "resource_url": r["resource_url"],
                "host": r["host"], "category": "catalog-hit", "price": r["price_usdc"],
                "signal": "DIRECT(catalog-term)", "receipt_mechanism": ";".join(hits),
                "awesome_readme_line": "", "description": r["description"],
            })
    comp_fields = ["name", "resource_url", "host", "category", "price", "signal",
                   "receipt_mechanism", "awesome_readme_line", "description"]
    write_csv(os.path.join(CSV, "bazaar_direct_receipt_competitors.csv"),
              direct + cat_direct, comp_fields)

    # 3. adjacent demand (ecosystem non-DIRECT + catalog adjacent hits)
    adjacent = [e for e in eco if e["signal"] != "DIRECT"]
    for r in catalog:
        text = f"{r['resource_url']} {r['description']}".lower()
        hits = [t for t in ADJACENT_TERMS if t in text]
        if hits:
            adjacent.append({
                "name": r["host"], "resource_url": r["resource_url"],
                "host": r["host"], "category": "catalog-hit", "price": r["price_usdc"],
                "signal": hits[0], "receipt_mechanism": ";".join(hits),
                "awesome_readme_line": "", "description": r["description"],
            })
    write_csv(os.path.join(CSV, "bazaar_adjacent_demand.csv"), adjacent, comp_fields)

    # 4. search summary (offline term scan)
    summary = term_scan(catalog, eco)
    write_csv(os.path.join(CSV, "bazaar_search_summary.csv"), summary,
              ["term", "bucket", "catalog_matches", "ecosystem_matches",
               "total_matches", "example_hosts"])

    # 5. top hosts (real catalog)
    host_ct = Counter(r["host"] for r in catalog if r["host"])
    write_csv(os.path.join(CSV, "bazaar_top_hosts.csv"),
              [{"host": h, "n_resources": c, "total_transactions":
                sum((r["totalTransactions"] or 0) for r in catalog if r["host"] == h)}
               for h, c in host_ct.most_common()],
              ["host", "n_resources", "total_transactions"])

    # 6. price distribution (real catalog)
    def bucket(p):
        if p is None:
            return "unknown"
        if p == 0:
            return "free"
        if p < 0.01:
            return "sub-cent (<$0.01)"
        if p < 0.10:
            return "micro ($0.01-$0.10)"
        if p < 1:
            return "cent-scale ($0.10-$1)"
        if p < 10:
            return "dollar-scale ($1-$10)"
        return "premium (>$10)"
    order = ["free", "sub-cent (<$0.01)", "micro ($0.01-$0.10)",
             "cent-scale ($0.10-$1)", "dollar-scale ($1-$10)",
             "premium (>$10)", "unknown"]
    pc = Counter(bucket(r["price_usdc"]) for r in catalog)
    write_csv(os.path.join(CSV, "bazaar_price_distribution.csv"),
              [{"price_bucket": b, "n_resources": pc.get(b, 0)} for b in order if pc.get(b)],
              ["price_bucket", "n_resources"])

    # 7. outreach targets: direct+adjacent ecosystem, ranked by relevance tier
    tier = {"DIRECT": 0}
    outreach = []
    for e in direct + adjacent:
        outreach.append({
            "host": e["host"], "name": e["name"], "resource_url": e["resource_url"],
            "category": e["category"], "signal": e["signal"],
            "relevance": "highest" if e["signal"] == "DIRECT" else "adjacent",
            "why": e["receipt_mechanism"],
            "contact_route": f"https://{e['host']}/.well-known/x402 (public manifest / project site)",
        })
    write_csv(os.path.join(CSV, "bazaar_relevant_outreach_targets.csv"), outreach,
              ["host", "name", "resource_url", "category", "signal", "relevance",
               "why", "contact_route"])

    # console summary
    print("\n=== SUMMARY ===")
    print(f"catalog resources : {len(catalog)}")
    print(f"unique hosts      : {len(host_ct)}")
    print(f"DIRECT competitors: {len(direct)} (ecosystem) + {len(cat_direct)} (catalog-term)")
    print(f"adjacent entries  : {len(adjacent)}")
    tx_total = sum((r['totalTransactions'] or 0) for r in catalog)
    print(f"catalog total tx  : {tx_total:,}")
    print("prices:", dict(pc))


if __name__ == "__main__":
    main()
