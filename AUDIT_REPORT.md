# Paxiom Static Site — Audit Report

**Audited path:** `/home/user/paxiom-static`
**Audit date:** 2026-05-05
**Scope:** 16 HTML files (`index`, `404`, `docs`, `services`, `status`, `contact`, plus 10 `paxiom-*` blueprint pages), `site-config.js`, `fonts.css`, `.github/workflows/pages.yml`, `CNAME`, `.nojekyll`, `README.md`, `fonts/README.md`.

---

## Executive Summary

The site is a static GitHub Pages deployment for `paxiom.org`. It is implemented as hand-written HTML with all CSS inlined per page, no JavaScript on any rendered page, no `<script>` / `<iframe>` / `<embed>` / `<img>` tags anywhere, and exactly one same-origin JS file (`site-config.js`) that is **not referenced by any page in the repo**. Because there is no client-side rendering, no fetch logic, no third-party widgets, and no user input handling, the practical XSS / SRI / CSP attack surface is essentially nil.

The genuine risk profile is **disclosure and content correctness**, not script injection:

1. **Personal disclosure** — the founder's full name, age, current employer (Google Fiber), region (Greater Nashville), weekly hours, hardware inventory (Yoga i9 laptop, HP ProDesk, RunPod), OS (WSL2 Ubuntu / Windows 11), and a rolling third-person audit-trail of past architectural mistakes, all on a single sheet (`paxiom-project-narrative.html`).
2. **Internal-path / branch leakage** — `paxiom-phase-0-status.html` links to a Claude Code work branch (`claude/build-hyperbeam-network-uIaMZ`) on `github.com/k-luecke/paxiom` and `github.com/k-luecke/bls-verifier`, and references local working-tree paths (`paxiom-ops-wt/...`). The same files are referenced on `main`/`master` from `paxiom-operations-runbook.html`, producing a contradictory link set and indicating the wrong branch was likely shipped.
3. **Date / consistency drift** — every "Updated" stamp on the four nav pages is `2026.04.30` (six days stale relative to today, 2026-05-05). The Phase 0 page's header date (`2026.05.03`) and footer date (`2026.05.02`) disagree with each other inside the same file. The home page describes S.01 / S.02 as gates that *will close* when the operator runs commands — but the Phase 0 page already shows them closed with operator evidence captured.
4. **Stale README** — `README.md` documents pages (`about.html`, `where-paxiom-fits.html`, `pricing.html`, `api.html`) and a "live feed console" / "sample records" feature that **do not exist** in the repo. This will mislead any new contributor and any LLM ingesting the README. `site-config.js` is similarly orphaned.
5. **CSS / SVG duplication** — the same ~200-line CSS block, the same paxiom-bar SVG icon (30 copies), the same Google Fonts `<link>` (32 preconnects), and the same softened-corners block are copy-pasted across files. Total HTML weight is ~870 KB; the project narrative is **160 KB** of single-file HTML, the operations runbook **104 KB**, phase-2 **103 KB**. None of that weight is content that requires it; large files are ~30–40 % CSS by line count.

No credentials, no private API keys, no hot-tier wallet addresses, and no internal IPs/hostnames were found. References to `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GOOGLE_API_KEY` are documentation of expected env vars, not embedded secrets.

---

## Findings by Severity

### Critical
*(none)*

### High

| ID | Severity | Title | File:Line |
|----|----------|-------|-----------|
| H-1 | High | Founder personal data shipped publicly: full name, age, current employer (Google Fiber Greater Nashville), weekly hours, dev hardware (Yoga i9, HP ProDesk), OS (WSL2 Ubuntu / Windows 11), cloud GPU vendor (RunPod). Combined with `kyle@paxiom.org` and the GitHub handle, this is a full doxx package. | `paxiom-project-narrative.html:3762`, `:3765`, `:3791`, `:3885-3887`; `contact.html:278` |
| H-2 | High | Repository links point to an unmerged Claude Code work-branch `claude/build-hyperbeam-network-uIaMZ` instead of `main`. Branch name leaks the use of an automated agent and the internal feature-branch convention. Also creates dead links if/when the branch is renamed or deleted. | `paxiom-phase-0-status.html:175-176`, `:207-208`, `:213-214` |
| H-3 | High | Internal working-tree path leaked: `paxiom-ops-wt/hyperbeam/bringup/logs/smoke-test-20260502T220748Z.log`. The `-wt` suffix is a `git worktree` artifact and discloses the operator's local layout. | `paxiom-phase-0-status.html:169` |
| H-4 | High | Public claim contradicts the Phase 0 status sheet. `index.html` says S.01/S.02 *"close when the operator runs the documented commands"*; the Phase 0 sheet shows both gates **already closed** with operator evidence on 2026-05-02 / 2026-05-03. Reads as out-of-date marketing on the home page. | `index.html:367` vs `paxiom-phase-0-status.html:165`, `:196` |
| H-5 | High | Cross-page link inconsistency on the same files. `paxiom-phase-0-status.html` links the runbook on the work-branch; `paxiom-operations-runbook.html` links the same docs on `main`/`master`. One of them is wrong. | `paxiom-phase-0-status.html:176`, `:208` vs `paxiom-operations-runbook.html:2702`, `:2705`, `:2707` |

### Medium

| ID | Severity | Title | File:Line |
|----|----------|-------|-----------|
| M-1 | Medium | `README.md` advertises pages that do not exist in the repo: `about.html`, `where-paxiom-fits.html`, `pricing.html`, `api.html`. | `README.md:30-34` |
| M-2 | Medium | `README.md` advertises a "live feed console" with `feedApiBase: https://api.paxiom.org`, "Save API" button, sample records, subscriber-gated production access. None of that UI exists in `index.html` or any other page. The README is from a deleted prior design. | `README.md:17-27` |
| M-3 | Medium | `site-config.js` is shipped but not referenced by any HTML file. Dead asset that still gets indexed and crawled. | `site-config.js:1-3`; no `<script src="site-config.js">` anywhere |
| M-4 | Medium | Date drift: every navigation page shows `Updated 2026.04.30`, six days stale relative to today (2026-05-05), even though Phase 0 and other pages have updates dated 2026.05.01–2026.05.03. Suggests the global date stamps are manually maintained and have fallen behind. | `index.html:309`, `:326`, `:380`; `docs.html:275`, `:432`; `services.html:287`, `:423`; `status.html:307`; `contact.html:264`, `:321` |
| M-5 | Medium | Self-contradictory dates inside a single page: header says `Date: 2026.05.03`, footer says `Rev. A · 2026.05.02`. | `paxiom-phase-0-status.html:150` vs `:301` |
| M-6 | Medium | `paxiom-build-map.html` is `Rev. B`; the `docs.html` card for the same document still labels it `Public · Rev. A`. | `paxiom-build-map.html:438`, `:776` vs `docs.html:387` |
| M-7 | Medium | Testnet-only contract addresses are published as a public table without explicit "do not interact" guidance. The page header says "Testnet · Rev. A" elsewhere, but the addresses themselves are presented as a "Live" table — readers may transact against them. | `paxiom-compliance-architecture.html:420`, `:426`, `:432` |
| M-8 | Medium | `paxiom-project-narrative.html` is missing both `<meta name="description">` and `<link rel="icon">`, hurting SEO and breaking the favicon on what is described as the most important sheet ("Read this first"). | `paxiom-project-narrative.html:1-15` |
| M-9 | Medium | Other large blueprint pages also missing `<meta name="description">`: `paxiom-audit-relay-blueprint.html`, `paxiom-key-identity-blueprint.html`, `paxiom-operations-runbook.html`, `paxiom-phase-1-blueprint.html`. | (see file headers, lines 1-15 of each) |
| M-10 | Medium | Same five large blueprint files are also missing `<link rel="icon">` and so don't render the favicon. | (file headers) |
| M-11 | Medium | Heading-level skips break screen-reader semantic outline. `paxiom-audit-relay-blueprint.html` and `paxiom-key-identity-blueprint.html` use `<h2>`, `<h3>`, then `<h5>` (no `<h4>`). Phase 1 / Phase 2 / operations runbook also use `<h5>` heavily for what are effectively `<h4>` items. | `paxiom-audit-relay-blueprint.html` (13 × `<h5>`, 0 × `<h4>`); `paxiom-key-identity-blueprint.html` (14 × `<h5>`, 0 × `<h4>`) |

### Low

| ID | Severity | Title | File:Line |
|----|----------|-------|-----------|
| L-1 | Low | No `<meta name="description">` on `404.html`; mild SEO hit. | `404.html:1-7` |
| L-2 | Low | No Open Graph (`og:*`) or Twitter Card meta tags anywhere in the site. Sharing on social platforms produces no preview. | (all `*.html`) |
| L-3 | Low | No `robots.txt` and no `sitemap.xml`. Crawlers will discover by link-walking only; some sheets buried behind `docs.html` may rank poorly. | repo root |
| L-4 | Low | Google Fonts CDN is loaded without SRI (Google Fonts changes its CSS dynamically, so SRI is impractical, but this should be acknowledged given the privacy concerns the project's own `fonts/README.md` raises). | every page header (`<link href="https://fonts.googleapis.com/css2?...">`) |
| L-5 | Low | Privacy regression vs. project's own stated values: `fonts/README.md` explicitly notes "Google Fonts CDN sees a request from every page-view" as a privacy concern, then ships every page using exactly that CDN. Self-hosting was deferred. | `fonts/README.md:38-39` vs every page header |
| L-6 | Low | `target="_blank"` links use only `rel="noopener"` (no `noreferrer`). External GitHub/Etherscan navigations leak `paxiom.org` as referrer. | `paxiom-compliance-architecture.html:420`, `:426`, `:432`, `:596`, `:704`, `:705`, `:706`; `contact.html:284` |
| L-7 | Low | The same ~80-line "softened corners" CSS block, the same `.paxiom-bar` rules, and the entire colour palette are duplicated across 11 files. A change to the brand requires editing every page. The `fonts.css` file exists but is empty (just a comment). Move shared CSS into `fonts.css` (or `site.css`). | All `*.html`; `fonts.css:1-18` |
| L-8 | Low | The header-bar SVG mark and the title-block SVG mark are inlined into every page (30 copies of the same `<svg viewBox="0 0 100 100">`). Either reference a single `<symbol>` via `<use>` from `favicon.svg`, or factor into shared markup. | All nav-bearing `*.html` (search `viewBox="0 0 100 100"` to find each) |
| L-9 | Low | File sizes are unjustified by content. `paxiom-project-narrative.html` is 160 KB (4,465 lines) with ~672 lines of style block; `paxiom-operations-runbook.html` 104 KB; `paxiom-phase-2-vision.html` 103 KB. Extracting shared CSS to one file would shave ~30 % off total transferred bytes. | `paxiom-project-narrative.html` (160 KB), `paxiom-operations-runbook.html` (104 KB), `paxiom-phase-2-vision.html` (103 KB), `paxiom-phase-1-blueprint.html` (84 KB), `paxiom-key-identity-blueprint.html` (83 KB) |
| L-10 | Low | "Internal Sales Playbook" mentioned by name in a public document. Not a leak (no content), but advertises that an internal document exists and may invite social-engineering pretexts. | `paxiom-phase-2-vision.html:894` |
| L-11 | Low | Forward-looking date claims that may go stale fast: "Glamsterdam, currently targeted Q2/Q3 2026" — Q2 is now (May 2026); the line was probably true when written and is nearly false today. | `paxiom-operations-runbook.html:2657` |
| L-12 | Low | Pages-deploy workflow uploads the entire repo (`path: .`), including `README.md`, `AUDIT_REPORT.md` (this file), and `.git`-adjacent dotfiles other than `.nojekyll`. `actions/upload-pages-artifact@v3` does not include `.git`, but it does include any markdown / unintended files at repo root. Consider an explicit allowlist or a `dist/` folder. | `.github/workflows/pages.yml:28-31` |

### Info

| ID | Severity | Title | File:Line |
|----|----------|-------|-----------|
| I-1 | Info | The Pages workflow is otherwise correct: `permissions:` is minimum-scoped, `concurrency.group: pages` with `cancel-in-progress: false` is the recommended pattern, action versions are pinned to majors (`@v4`/`@v5`/`@v3`). | `.github/workflows/pages.yml` |
| I-2 | Info | `CNAME` correctly contains `paxiom.org` only; `.nojekyll` correctly disables Jekyll on a non-Jekyll site. | `CNAME`, `.nojekyll` |
| I-3 | Info | No `<script>`, `<iframe>`, `<embed>`, `<object>`, `<img>`, `innerHTML`, `document.write`, `eval(`, or `on*=` event handlers were found in any HTML file. Practical XSS surface is zero on the rendered site. | grep across all `*.html` |
| I-4 | Info | `localhost:8080` reference is inside a `<pre>` code block as a documentation example for an operator-only command, not a live endpoint. | `paxiom-phase-0-status.html:230` |
| I-5 | Info | `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GOOGLE_API_KEY` are documented as required environment variables for an internal audit-relay tool, not embedded values. | `paxiom-audit-relay-blueprint.html:1030`, `:1046`, `:1064` |
| I-6 | Info | Etherscan/Basescan-linked addresses are all `*-sepolia.*` testnets. No mainnet addresses are exposed. | `paxiom-compliance-architecture.html:420-432` |

---

## Sensitive Disclosures Found

The following items, while not strictly secrets, are surface area an adversary or recruiter or competitor would value. Review whether each is intentional public surface.

| # | Disclosure | Where | Risk |
|---|------------|-------|------|
| 1 | Founder full name **Kyle Luecke**, age **29**, day-job employer **Google Fiber Greater Nashville**, weekly load **~58 hours** | `paxiom-project-narrative.html:3762-3791` | Doxx-grade personal data; combined with public email enables targeted social engineering |
| 2 | Founder hardware: **Yoga i9 laptop**, **HP ProDesk** "always-on infrastructure", **RunPod** GPU | `paxiom-project-narrative.html:3885-3887` | Narrows attack surface; "always-on" workstation is signing infrastructure |
| 3 | Dev OS / shell: **WSL2 Ubuntu on Windows 11** with **WSLg** + `notify-send` + `tmux` | `paxiom-audit-relay-blueprint.html:827`, `:1088-1096`, `:1652-1671` | Identifies host OS and notification surface for an attacker writing exploit shellcode for the operator's box |
| 4 | Internal git work-tree path **`paxiom-ops-wt/`** | `paxiom-phase-0-status.html:169` | Reveals the operator uses `git worktree`, narrows pivots if the box is reached |
| 5 | Claude Code feature-branch name **`claude/build-hyperbeam-network-uIaMZ`** | `paxiom-phase-0-status.html:175`, `:176`, `:207`, `:208`, `:213`, `:214` | Reveals automated-agent usage and naming convention |
| 6 | Founder direct email **kyle@paxiom.org** | `contact.html:278` | Intentional, but combined with the above raises spam/phishing surface |
| 7 | Self-funded status, "Day job pays the rent" | `status.html:333` | Intentional, but signals to an acquirer / pressure-tactic adversary that there is no runway buffer |
| 8 | Three-tier key custody architecture **K-001 / K-002 / K-006** with explicit "K-001 signs identity but no value transfer" / "K-002 holds operational settlement balances", **mlock**, **encrypted swap**, hot keys on production server, passphrase manual at boot | `paxiom-key-identity-blueprint.html:1493-1530` | The architecture sheet says it's intentionally public; still worth confirming the level of detail (passphrase ceremony, swap configuration, ulimits) is the intended surface |
| 9 | Testnet contract addresses with Etherscan links published as a "Live" table, no "do-not-interact" notice | `paxiom-compliance-architecture.html:420-432` | Could mislead a careless agent into transacting against testnet contracts |
| 10 | "Mainnet beacon access (operator laptop, RunPod, or…)" — confirms operator can reach beacon nodes from personal laptop | `paxiom-operations-runbook.html:2630` | Personal laptop is part of the production trust boundary |

---

## Operational / Build Notes

- The `pages.yml` workflow is correct and minimal; the only concern is `path: .` ships every file in the repo root including this `AUDIT_REPORT.md` (don't merge this file to `main` if you don't want it served at `/AUDIT_REPORT.md`).
- The `404.html` is well-formed and short; no improvement needed beyond adding a `<meta name="description">`.
- `CNAME` and `.nojekyll` are correct. No `robots.txt` / `sitemap.xml`.
- README's "Deploy" steps say *"Set source to `Deploy from a branch`"* (the legacy mode), but the workflow uses **GitHub Actions Pages** (`actions/deploy-pages@v4`). README is wrong; the workflow is right. Do not follow the README.

---

## Summary by Severity

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 5 |
| Medium | 11 |
| Low | 12 |
| Info | 6 |
| **Total** | **34** |

---

## Suggested Remediation Order (not part of the audit, just sequencing)

1. Fix the link contradiction (H-2, H-5, H-3) — repoint Phase 0 status links to `main`, scrub `paxiom-ops-wt`, retire the Claude work-branch URLs.
2. Re-decide the personal-disclosure scope (H-1, sensitive #1–3, #6–7) — the founder's identity is intentionally public; the day-job, weekly hours, and hardware inventory probably are not.
3. Sync the home page's Phase 0 substrate paragraph with the Phase 0 sheet (H-4).
4. Update the README to match reality or delete the orphan parts (M-1, M-2, M-3).
5. Fix dates: bump global "Updated" stamps; reconcile Phase 0 header/footer (M-4, M-5, M-6).
6. Add `<meta name="description">` and favicon to the five large pages (M-8, M-9, M-10).
7. Extract shared CSS to `fonts.css` / `site.css`; collapse SVG marks (L-7, L-8, L-9).
