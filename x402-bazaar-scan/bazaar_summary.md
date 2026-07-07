# x402 Bazaar Scan Report

**Prepared for:** Paxiom Receipts — *"x402 proves a payment. Paxiom proves what the payment bought."*
**Analyst run date:** 2026-07-07

---

## Scan metadata

| Field | Value |
|---|---|
| Date/time | 2026-07-07 (UTC) |
| Primary endpoints targeted | `GET https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources?type=http&limit=1000&offset=0` · `GET .../discovery/search?query=<term>` · `.../discovery/merchant` |
| **Live-API status** | **BLOCKED from this environment.** `api.cdp.coinbase.com` and `docs.cdp.coinbase.com` are denied by the session's organization egress policy (HTTP 403 to both `curl` and `WebFetch`). Per policy, denied hosts are reported, not routed around. |
| Data actually used | (A) a **real Bazaar `discovery/resources` snapshot** — 90 resources with full CDP `metadata.paymentAnalytics` — committed at `github.com/microchipgnu/payload-exchange` → `server/core/resources/top-resources.json` (snapshot dated **2025-11-19**); (B) the community **`awesome-x402`** index `github.com/xpaysh/awesome-x402` (fetched 2026-07-07, ~150 live services). Both saved under `raw/`. |
| Catalog resources analysed | **90** (snapshot) + ~150 ecosystem entries cross-referenced |
| Unique hosts/domains (snapshot) | **37** |
| Total settled transactions in snapshot | **26,109** (Bazaar exposes per-service `totalTransactions` — demand *is* measurable) |
| Search terms used | 15 direct + 24 adjacent (see `bazaar_search_summary.csv`); executed as an offline term-scan over the corpus, and wired into `scan_x402_bazaar.py` for the live `/discovery/search` endpoint |
| API errors / rate limits | Live endpoint: **403 policy denial** (not a rate limit). No hammering performed. |

### Verified API shape (from CDP docs + the real snapshot)

- **Catalog:** `GET /platform/v2/x402/discovery/resources?type=http&limit=&offset=` → `{"x402Version", "items":[...], "pagination"}` **or** a bare array `[...]`.
- **Search:** `GET /platform/v2/x402/discovery/search?query=` → same item shape, quality-ranked.
- **Auth:** the discovery **MCP** endpoint (`.../discovery/mcp`) is documented "No Authorization"; the REST endpoints may require a CDP JWT from some origins. `scan_x402_bazaar.py` mints a Bearer JWT if `CDP_API_KEY_ID`/`CDP_API_KEY_SECRET` + the `cdp` SDK are present, otherwise sends unauthenticated.
- **Resource object:** `resource`, `type`, `x402Version`, `lastUpdated`, `accepts[]` (`scheme`, `network`, `maxAmountRequired`, `asset`, `payTo`, `resource`, `description`, `mimeType`, `maxTimeoutSeconds`, `outputSchema{input,output}`, `extra`), and a rich **`metadata`** block: `confidence{overall/performance/recency/reliability/volumeScore}`, `paymentAnalytics{totalTransactions, totalUniqueUsers, transactions24h/Week/Month, averageDailyTransactions}`, `performance{avg/min/max/recentAvgLatencyMs}`, `reliability{apiSuccessRate, successfulSettlements, totalRequests}`, `errorAnalysis{...}`.
  → **This contradicts the assumed caveat that Bazaar hides transaction counts.** It does not — `totalTransactions` per resource is exposed, so activity is directly rankable.

**Sources:** [CDP x402 Bazaar docs](https://docs.cdp.coinbase.com/x402/bazaar) · [x402 GitBook — Bazaar Discovery Layer](https://x402.gitbook.io/x402/core-concepts/bazaar-discovery-layer) · [coinbase/x402 `bazaar` Go pkg](https://pkg.go.dev/github.com/coinbase/x402/go/extensions/bazaar) · snapshot: [microchipgnu/payload-exchange](https://github.com/microchipgnu/payload-exchange) · ecosystem: [xpaysh/awesome-x402](https://github.com/xpaysh/awesome-x402).

---

## Executive findings

- **Is direct receipt competition present?** **Yes — and it is arriving fast.** At least **21 live services** already ship signed receipts, attestation receipts, proof-of-execution receipts, or payment-to-output binding (full list below). The space went from empty to crowded-but-fragmented in ~2 quarters.
- **Is adjacent proof/verification demand present?** **Strongly yes.** Adjacent terms dominate the corpus: `agent` (39 matches), `signed` (14), `risk` (14), `attestation` (10), `security` (10), `proof` (8), `verification`/`audit`/`mcp` (7 each), `compliance` (6). And crucially the **second-highest-volume host in the real snapshot is a security/verification API** (`x402-secure-api.t54.ai`, 2,921 settled tx) — verification is already a *paid, high-traffic* category, not a hypothetical.
- **Is Paxiom early, late, or adjacent?** **Adjacent-and-arriving, not early.** Paxiom is *late* to the "sign your own output" primitive (dozens do it) but *on time* for the **unsolved problem: there is no standardized, cross-service, provider-neutral proof-bound receipt layer.** Every incumbent signs only *its own* output in *its own* ad-hoc format (Ed25519 here, HMAC there, EIP-712 elsewhere, SHA-256 trust-hash somewhere else). No one binds **payment + request + output + settlement + proof** into a single interoperable receipt that any x402 API can emit and any agent can verify uniformly. That standard/SDK slot is open.
- **Listing strategy.** List **twice and narrowly**: (1) a **verifier** ("x402 receipt & settlement verifier", MCP + REST — this is the highest-intent, lowest-friction wedge and directly parallels the already-popular `@tensorfeed/x402-base-mcp`), and (2) the **proof-bound receipt SDK/middleware** for sellers (parallel to `@larkinsh/x402`). Seed both into the CDP Bazaar (auto-catalogued on first settled payment), the Agent402 index/leaderboard, PayAPI Market, the MCP Registry, and `awesome-x402`.

---

## Direct competition

Full data in `csv/bazaar_direct_receipt_competitors.csv`. The market splits into four shapes; **none is a general receipt standard**, which is Paxiom's opening.

### 1) Closest conceptual analogues (payment ↔ action/output binding)

| Service | URL/host | Why it competes | Receipt vs. full proof-bound | Paxiom differentiation |
|---|---|---|---|---|
| **Mycelium Trails** | `github.com/giskard09/giskard-stack` | Post-execution accountability receipts for x402: each settled payment → signed trail `payment_hash + action_ref (SHA-256) + dual-chain anchor`, for audits/disputes/insurance | **Full-ish** — binds payment→action, but `action_ref` is a hash *commitment*, not the verifiable output+request+settlement bundle | Bind the actual request+output+settlement, not just a commitment; provider-neutral schema; agent-verifiable offline without chasing two chains |
| **swornly** | `swornly.luci.ws` | Sells "deterministic, signed-receipt tools; every answer returns an HMAC-signed, re-verifiable receipt" + free `/receipts/verify` | **Payment-adjacent** — signs the *tool answer*, not the x402 payment↔output link; Base **Sepolia testnet** | Mainnet; bind to the actual x402 settlement tx; public-key (not shared-secret HMAC) verification |
| **PayPerByte** | `x402.payperbyte.io` | Every paid response emits an **EIP-712 PayloadAttestation**; buyer re-derives keccak256 over bytes, recovers signer, fails closed on tamper | **Output-binding primitive** — the strongest technical prior art; but per-feed, single-vendor, no request/settlement binding | Standardize the primitive across sellers; add payment+request+settlement legs; ship the verifier agents already want |

### 2) Signed-receipt-as-middleware (Paxiom's distribution twin)

- **`@larkinsh/x402`** (npm) — authorization middleware returning **Ed25519-signed receipts** verifiable with only the public key; Hono/Express/Next adapters. *This is exactly Paxiom's go-to-market motion (one-line middleware) but scoped to auth gating, not proof-of-delivery.* Differentiate on binding the delivered output + settlement, and on the verifier side.
- **Agent Passport System (APS)** — signed receipts with **per-condition attestation** (governance/delegation angle).
- **presidio-hardened-x402** (PyPI, arXiv-backed) — pre-signing hardening; receipt-integrity adjacent.

### 3) Receipt *verification* tools (Paxiom's wedge product)

- **`@tensorfeed/x402-base-mcp`** — read-only Base reader that **verifies a USDC settlement matches a claimed x402 receipt** (recipient+amount). *The single closest competitor to a "receipt verifier" listing.* It verifies payment↔settlement; it does **not** verify payment↔output. Paxiom's verifier should verify the full chain.
- **AI Growth** — sells **timestamped proof-of-execution receipts** ($0.02) so agents "confirm an A2A service is real before paying." Demand proof that agents will *pay for verification.*
- **n0brains `/proof`** — auditable per-signal win-rate proof (track-record provenance).

### 4) Per-service signed output / attestation (widespread, shallow)

`anchor-x402` (signed attestations + dual-chain anchoring), **SYNTHORA md-extract** (Ed25519 attestation receipt, offline chain-of-custody), **LION** (every response Ed25519-attested), **Stratalize** (Ed25519-signed outputs), **Kraken Crypto Signals** (ECDSA-signed + tamper-evident hash-chain), **TrustBoost** (Solana-anchored proof at `/verify/{tx}`), **TWZRD** (`twzrd.receipt.v5` signed trust receipts), **LogicNodes** (SHA-256 trust hashes ×619), **Hive Civilization** (Spectral receipts + ZK attestations), **SafeAgent** (crash-safe receipts + audit trail), **Boundary Guard** (pre-action deterministic receipt), **Voidly Pay** (Ed25519 envelopes + proof-of-reserves).

**Takeaway:** the primitive is commoditized; the *interoperability layer and the verifier* are not. Twelve vendors each invented a different signature format — that fragmentation **is** the wedge. Paxiom wins by being the neutral schema + verifier everyone can point at, not the 22nd vendor signing its own JSON.

---

## Adjacent demand

Grouped from `csv/bazaar_adjacent_demand.csv` (64 entries) and the term-scan (`bazaar_search_summary.csv`).

| Category | Relevant resources | Representative examples | Why it matters for Paxiom | Buyer demand? |
|---|---|---|---|---|
| **proof / verification** | ~10 | Ontario Protocol (readiness verification), Sentinel (preflight trust), AI Growth (proof-of-execution), Fast PDF Parser (SHA-256-bound payment proofs) | These are Paxiom's category-adjacent buyers *and* channel partners; verification is a named product line | **Yes** — paid preflight/verification is a live pattern |
| **attestation / provenance** | ~9 | ZKProofport (ZK identity proofs), ALTER (Ed25519 identity vectors), OSF (provenance-stamped records), Melvea (DOI/PMID-resolvable provenance) | Provenance buyers already pay to *prove where data came from*; Paxiom proves *what a payment bought* — same trust budget | **Yes** |
| **audit / compliance** | ~8 | melis.ai `xAudit`, GlobalAPI (OFAC/UN), CYBERA (VASP), Sanctions Screening, romefeller (PII + receipt extraction) | Compliance buyers need immutable evidence trails — a native Paxiom use case (disputes, chargebacks, audits) | **Yes** — compliance is a paying vertical |
| **blockchain data / state** | ~7 | Crest, Deepnets, Seneschal (signed webhooks), bitquery **x402 payment-transaction analytics**, Rug Munch | bitquery selling *analytics over x402 settlements themselves* proves appetite for settlement-level truth | **Yes** |
| **agent / MCP tools** | dominant (39 `agent`, 7 `mcp`) | Agent402 (~1,100 tools + seller leaderboard), Aigregator, Pyrimid registry, Agent Commerce Desk ("agent-commerce receipt") | The buyer is the agent; MCP is the delivery format. Paxiom must ship an MCP verifier to be discoverable | **Yes — this is the mainstream** |
| **security / risk** | ~14 `risk`, 10 `security` | **t54.ai secure-api (2,921 tx — #2 by volume)**, melis PromptGuard, ShieldAPI, SolProbe/RugGuard, GPT55 approval-risk | Security is proven *paid, high-traffic* demand; "prove this output wasn't tampered" is a security sale | **Yes — strongest volume signal** |
| **API marketplaces / proxies** | ~5 | Agent402 index, PayAPI Market, Aigregator, swerver/monapi gateways | These are Paxiom's **listing surfaces**, not competitors | n/a (channel) |

---

## Pricing observations

From the real 90-resource snapshot (`bazaar_price_distribution.csv`; USDC on Base, 6-decimals):

| Bucket | Resources |
|---|---|
| sub-cent (<$0.01) | 2 |
| **micro ($0.01–$0.10)** | **30** |
| cent-scale ($0.10–$1) | 18 |
| **dollar-scale ($1–$10)** | **31** |
| premium (>$10) | 9 |

- **Free / near-free:** rare in the *top* snapshot; most freebies are preview endpoints not catalogued as paid.
- **Microtransaction ($0.01–$0.10):** the modal data/tool call. This is where a **per-receipt verify** should sit — think **$0.001–$0.01 per receipt verification**, i.e. a rounding error on the underlying call.
- **Premium (>$10):** token-mint / NFT / heavy-report endpoints (e.g. `x402song.com` $42, `arvos/touch` $10). Not Paxiom's lane.
- **Implication for Paxiom pricing:** issuing a receipt should be **free/bundled** for sellers (adoption driver — mirror how `@larkinsh/x402` and SYNTHORA give the receipt away), and monetize the **verifier** and **premium proof anchoring / audit exports** ($0.005–$0.05 per deep verify; subscription for compliance dashboards). Signing must be cheaper than the value it de-risks, or sellers won't bundle it.

---

## Merchant / domain clustering

From `bazaar_top_hosts.csv` (snapshot, ranked by settled `totalTransactions`):

**Likely serious operators (real volume):**
- `api.questflow.ai` — **5,734 tx**, 14 resources (agent/news/search fleet)
- `x402-secure-api.t54.ai` — **2,921 tx**, 4 resources (**security scoring — direct adjacency**)
- `mesh.heurist.xyz` — **2,264 tx**, 12 resources (GPU/agent mesh)
- `api.ping.observer` — **2,124 tx**, 7 resources
- `pay.codenut.ai` / `nut402.codenut.xyz` — ~2,443 tx combined
- Ecosystem heavyweights not in the snapshot but high-signal: **Agent402** (seller leaderboard, ~1,100 tools), **melis.ai** (23 audit-verified endpoints), **anchor-x402**, **LogicNodes** (619 services), **Stratalize** (100+ tools).

**Likely toy / demo projects:** meme-mint endpoints (`x420.dev`, `boofy.fun`, `payx402.fun`, `nut402`, `x402song.com`), `x402-demo-discovery-endpoint.vercel.app` — high count, low strategic value.

**Likely outreach targets:** the security/verification/attestation cluster (t54, melis, anchor-x402, LION, SYNTHORA, Kraken Signals, TrustBoost, n0brains) + the infra/middleware authors (larkinsh, tensorfeed, APS, Voidly) who could **adopt Paxiom's schema** rather than compete.

---

## Paxiom positioning recommendation

**Do not list as "another signed-output API."** That box has 20+ occupants. List as the **two roles no one owns cleanly:**

1. **Primary wedge — MCP/REST receipt & settlement *verifier*.** Highest intent, lowest adoption friction, directly parallels the already-adopted `@tensorfeed/x402-base-mcp` but verifies the **full** payment→request→output→settlement chain, not just payment→settlement. Agents already pay AI Growth $0.02 to verify a service is real — Paxiom verifies the *transaction they just did*.
2. **Secondary — proof-bound receipt SDK / middleware** for sellers (parallels `@larkinsh/x402`'s one-line motion), emitting a **provider-neutral receipt schema** any x402 API can adopt.

Deprioritize framing as: pure "state/proof verification service" (crowded, and not Paxiom's edge), or a generic "audit/security tool" (crowded). Lead with **receipt verifier + receipt SDK**; let audit/compliance be *outcomes*, not the headline.

**Best initial listing**

- **Name:** `Paxiom Receipts`
- **Description:** *Proof-bound receipts for x402-paid APIs. Bind payment, request, output, settlement, and proof evidence into one signed receipt that agents and developers can verify later — provider-neutral, offline-verifiable.*
- **Tags:** `x402, receipts, proof-of-delivery, agent-payments, audit, verification, signed-receipts, api-security, mcp, attestation`
- **Category:** Agent trust / verification & attestation (list under both "security" and "agent tooling" facets).

---

## Suggested Paxiom listing copy

> **Name:** Paxiom Receipts
>
> **Description:** Proof-bound receipts for x402-paid APIs. Bind payment, request, output, settlement, and proof evidence into a signed receipt that agents and developers can verify later.
>
> **Tags:** x402, receipts, proof-of-delivery, agent payments, audit, verification, signed receipts, API security
>
> **Endpoints (suggested):** `POST /receipt/issue` (seller-side, bundled free) · `GET /receipt/verify` (free, drives adoption) · `POST /receipt/anchor` (paid, on-chain proof) · MCP tools `issue_receipt`, `verify_receipt`, `explain_receipt`.

---

## Outreach targets

Public routes only — project sites / `/.well-known/x402` manifests / GitHub project READMEs. **No commit-email harvesting, no issue spam.** Full machine list: `csv/bazaar_relevant_outreach_targets.csv`.

| # | Project / domain | Why relevant | Message angle | Contact route (research manually) |
|---|---|---|---|---|
| 1 | **t54.ai** (`x402-secure-api.t54.ai`) | #2 by settled volume; security-scoring buyer base overlaps Paxiom | "Ship verifiable receipts alongside your risk scores" | project site / manifest |
| 2 | **melis.ai** (`agents.melis.ai`) | 23 audit-verified endpoints; `xAudit` already sells response auditing | "Standardize your audit output as a Paxiom receipt" | melis.ai |
| 3 | **larkin-dev** (`@larkinsh/x402`) | Ships Ed25519-signed receipts as middleware — natural schema adopter/partner | "Adopt Paxiom's neutral receipt schema, don't reinvent it" | GitHub project page |
| 4 | **tensorfeed** (`@tensorfeed/x402-base-mcp`) | Already a receipt *verifier*; partner or interop | "Verify output-binding, not just settlement" | GitHub / MCP registry |
| 5 | **giskard09 / Mycelium Trails** | Closest conceptual peer (accountability receipts) | "Interop on a common receipt/anchor format" | GitHub |
| 6 | **anchor-x402** | Signed attestations + dual-chain anchoring | "Use Paxiom receipts as your attestation envelope" | anchor-x402.com/trust |
| 7 | **SYNTHORA** (`pay.hergertsynthora.com`) | Ed25519 attestation receipts on scraped output | "Portable chain-of-custody across meshes" | project site |
| 8 | **LION** (`lionx402.com`) | Every response Ed25519-attested; compliance tools | "Compliance-grade receipts + audit export" | lionx402.com |
| 9 | **Kraken Crypto Signals** (`signals.nsgoods.org`) | ECDSA-signed + hash-chain track record | "Standard verifier so buyers trust your chain" | OpenAPI/GitHub |
| 10 | **TrustBoost** (`api.trustboost.dev`) | On-chain proof-of-execution at `/verify/{tx}` | "Unify your /verify under a portable receipt" | trustboost.dev |
| 11 | **n0brains** (`/proof`) | Auditable track-record proofs | "Make /proof a verifiable Paxiom receipt" | n0brains.com |
| 12 | **AI Growth** | Sells proof-of-execution receipts — validated demand | "Upgrade to full payment↔output receipts" | discovery manifest |
| 13 | **Voidly Pay** | Ed25519 envelopes + proof-of-reserves (rail) | "Bundle Paxiom receipts into the pay rail" | api.voidly.ai |
| 14 | **Agent402** | ~1,100 tools + seller leaderboard = prime listing surface | "List Paxiom in your index; offer receipts to sellers" | agent402.tools |
| 15 | **PayAPI Market** | First x402 API marketplace = distribution | "Feature verifiable receipts as a marketplace trust layer" | payapi.market |
| 16 | **OSF — Open Source Filings** | Provenance-stamped gov/scientific data | "Provenance + receipt = end-to-end proof" | osf-master-server.com |
| 17 | **ZKProofport** | ZK identity proofs, ERC-8004 | "ZK-friendly receipt anchoring" | GitHub |
| 18 | **Ontario Protocol** | Readiness verification + manifests | "Receipts as the post-payment half of your trust scan" | ontarioprotocol.com |
| 19 | **APS (agent-passport-system)** | Signed receipts + per-condition attestation | "Converge on one receipt schema" | GitHub |
| 20 | **LogicNodes** | 619 services w/ SHA-256 trust hashes | "Swap ad-hoc hashes for verifiable receipts at scale" | logicnodes.io |
| 21 | **Hive Civilization** | 52-service fleet, Spectral receipts + ZK | "Interop Spectral↔Paxiom receipts" | GitHub (srotzin) |
| 22 | **swornly** | Signed-receipt tools (testnet) | "Mainnet + payment-binding partnership" | swornly.luci.ws |
| 23 | **bitquery** (x402 data API) | Sells analytics over x402 settlements | "Feed verified receipts into settlement analytics" | bitquery.io |

---

## Caveats

- **Live catalog was not reachable from this run.** `api.cdp.coinbase.com` is blocked by the org egress policy (403). Findings rest on a **real but ~8-month-old catalog snapshot (2025-11-19, 90 resources)** plus a **current curated ecosystem index**. Re-run `scan_x402_bazaar.py` from a network that allows the CDP host (with a CDP key if required) to refresh against the full live catalog (`limit=1000`).
- Bazaar **does** expose per-service `totalTransactions` (unlike the assumed caveat) — but the snapshot is "top resources," so it over-represents high-volume services and under-counts the long tail and new entrants.
- **Search ranking ≠ demand.** `/discovery/search` is quality-ranked; high rank implies reliability/recency, not proven buyer pull for *your* category.
- **Some endpoints are demos/toys** (meme mints, `*.vercel.app` demos). Volume counts include them.
- **Direct receipt demand may still be early even though adjacent demand is proven.** Adjacent categories (security, agent tooling, compliance) clearly pay; whether agents will pay *specifically* for a standalone receipt/verify call — versus expecting it bundled free — is the key open question. The data leans toward **"free receipt, paid verifier + paid audit,"** which is the recommended model.
- Ecosystem descriptions are self-reported by operators; capabilities (e.g. "audit-verified") were not independently tested.
```
