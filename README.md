# Paxiom Static Site

Public static website for `paxiom.org`.

This repository is intentionally separate from the private Paxiom core repo. It contains only public website and documentation assets suitable for GitHub Pages.

## Deploy

1. Create a public GitHub repository, for example `k-luecke/paxiom-static`.
2. Push this repo to GitHub.
3. In GitHub, open `Settings -> Pages`.
4. Set source to `Deploy from a branch`, branch `main`, folder `/`.
5. Confirm the custom domain is `paxiom.org`.

The `CNAME` file is already included.

## Feed Console

The homepage includes a live feed console. By default it calls:

```text
https://api.paxiom.org
```

Change `site-config.js` if the public feed API uses a different origin. For local testing, enter a different API base URL in the page and click "Save API".

Live production access is subscriber-gated. The public page shows sample records unless a subscriber API endpoint and token are configured.

## Product Pages

- `index.html` — homepage, demo console, latency benchmark, and pilot funnel.
- `about.html` — consumer workflow and verification levels.
- `where-paxiom-fits.html` — oracle/indexer positioning.
- `pricing.html` — public tiers for schema, developer, pilot, and production access.
- `api.html` — feed API surface and predicate documentation.

## Drawing Set

- `paxiom-build-map.html` (R-Series) — phased roadmap, Phase 0 → Phase 5.
- `paxiom-phase-0-status.html` (G-Series) — substrate gate audit trail. Names
  acceptance criteria, evidence locations, and operator commands for A-120 / S.01–S.03.
- `paxiom-phase-1-blueprint.html` (A-Series) — service-by-service Phase 1 specifications.
- `paxiom-phase-2-vision.html` (F-Series) — Phase 2 planning brief.
- `paxiom-operations-runbook.html` (O-Series) — operator runbook (O-700 / O-701 / O-702 cross-link to `k-luecke/bls-verifier`).
- `paxiom-project-narrative.html` (B-Series) — narrative + thesis.
- `paxiom-key-identity-blueprint.html` (CA-Series), `paxiom-audit-relay-blueprint.html`,
  `paxiom-compliance-architecture.html` — supporting blueprints.
