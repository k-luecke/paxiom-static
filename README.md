# Paxiom Static Site

Public static website for `paxiom.org`.

This repository is intentionally separate from the private Paxiom core repo. It contains only public website and documentation assets suitable for GitHub Pages.

## Deploy

Pages is published via the GitHub Actions workflow at
`.github/workflows/pages.yml` (`actions/deploy-pages@v4`). To deploy:

1. Push to `main`.
2. The workflow uploads the repo via `actions/upload-pages-artifact@v3`
   and deploys to `paxiom.org` (custom domain configured in `CNAME`).

To wire a fresh fork: open `Settings -> Pages` and set the source to
`GitHub Actions`. Do **not** use "Deploy from a branch" — that would
bypass the workflow.

## Pages

Top-level pages:

- `index.html` — homepage.
- `docs.html` — drawing-set index.
- `services.html` — service catalog overview.
- `status.html` — phase-0 / phase-1 status snapshot.
- `contact.html` — contact and channels.
- `404.html` — fallback.

Drawing set:

- `paxiom-build-map.html` (R-Series) — phased roadmap, Phase 0 → Phase 5.
- `paxiom-phase-0-status.html` (G-Series) — substrate gate audit trail.
- `paxiom-phase-1-blueprint.html` (A-Series) — service-by-service Phase 1 specs.
- `paxiom-phase-2-vision.html` (F-Series) — Phase 2 planning brief.
- `paxiom-operations-runbook.html` (O-Series) — operator runbook
  (O-700 / O-701 / O-702 cross-link to `k-luecke/bls-verifier`).
- `paxiom-project-narrative.html` (B-Series) — narrative + thesis.
- `paxiom-key-identity-blueprint.html` (CA-Series),
  `paxiom-audit-relay-blueprint.html`,
  `paxiom-compliance-architecture.html`,
  `ao-zk-proving-architecture.html` — supporting blueprints.
