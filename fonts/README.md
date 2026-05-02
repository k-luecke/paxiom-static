# `fonts/` — body face is DM Sans (SIL OFL, served via Google Fonts CDN)

Paxiom's brand body face is **DM Sans**, an SIL-Open-Font-License geometric
sans-serif designed by Colophon Foundry / Indian Type Foundry. Loaded
on every page via the existing Google Fonts CDN link in `<head>` —
no `.woff2` files committed to this repo, no licence audit trail
needed, no deploy-time wiring required.

The earlier `fonts.css` / vendored-`.woff2` scaffolding is gone. This
directory is intentionally empty in the public repo.

## Why DM Sans

After two iterations on commercial faces (Neutraface Text, Brandon
Grotesque) — both of which would have required either a deploy-time
asset pipeline or careful licence administration to ship correctly
from a public repo — we landed on the SIL-OFL path. DM Sans is the
closest practical OFL match for the architectural-binder body face
the brand identity calls for: geometric proportions, slightly
humanist warmth, low x-height, designed for body sizes.

The visual identity does not depend on a specific commercial face.
What carries the binder feel is JetBrains Mono on labels, Times New
Roman on serif headers, generous whitespace, and the colour palette.
The body sans-serif is one of several variables; picking the OFL
option keeps the repo licence-clean for free.

If at any point the brand identity is found to genuinely require
Brandon Grotesque or another commercial face, the path back is
documented at the bottom of this file.

## Self-hosting (optional, for later)

DM Sans is currently loaded from `https://fonts.googleapis.com/...`
because that's the simplest path that ships license-clean now.
Reasons you might want to self-host instead:

- **Privacy.** Google Fonts CDN sees a request from every page-view.
  Self-hosting keeps that off Google's logs.
- **Performance.** One fewer DNS + TLS handshake on the critical
  path; same-origin CSS preloads more aggressively.
- **Resilience.** No external CDN dependency; the site keeps
  rendering correctly during a Google outage.

To switch, drop OFL `.woff2` files for the weights in use into
`/fonts/`, replace `fonts.css` with the matching `@font-face` rules,
and remove the `https://fonts.googleapis.com/...` `<link>` tag from
each page's `<head>` (DM Sans portion only — JetBrains Mono is also
on Google Fonts and stays).

The OFL license requires you to:
1. Bundle the OFL.txt file alongside the redistributed .woff2 files.
2. Not sell the fonts as a standalone product.
3. Not use the original font names if you modify the font files.

None of those are tricky for a normal self-hosted deployment.

## Earlier history (audit trail)

The repo went through three brand-face iterations:

1. **Neutraface Text** (Phase 0 launch) — commercial; House
   Industries. Eight `.woff2` files were committed to a public repo,
   which is almost always prohibited regardless of whether a web
   licence exists. Caught in PR-#9 audit review.
2. **Brandon Grotesque** (interim) — also commercial; HVD Fonts.
   Same redistribution posture. CSS swapped, no `.woff2` files
   committed; would have required a deploy-time pipeline to render
   the licensed face on the live site.
3. **DM Sans** (current) — SIL OFL. License-clean for both serving
   and redistribution. Loaded via Google Fonts CDN with no
   committed bytes; self-hosting is a one-file-change follow-up if
   ever desired.

Anyone with a clone of the older history still has the Neutraface
files locally; the active repo no longer redistributes them.

## If a commercial face becomes genuinely necessary later

The two commercial faces evaluated are visually adjacent:

- **Neutraface Text** — geometric, architectural, low x-height,
  square dot on `i`. Closest to Richard Neutra's lettering.
- **Brandon Grotesque** — geometric humanist, slightly rounder,
  warmer than Neutraface. Less architectural feel.

Either would require:

1. A web licence covering paxiom.org (single domain or unlimited).
2. A deploy pipeline that injects `.woff2` files from a private
   location into `paxiom.org/fonts/` at publish time, NOT into
   this public repo.
3. Updating `fonts.css` to declare `@font-face` rules for the
   licensed face, paths pointing at `/fonts/...` populated by the
   pipeline.
4. Updating each page's body `font-family` to put the licensed
   face first in the stack: `'Brandon Grotesque', 'DM Sans',
   system-ui, -apple-system, sans-serif`. Keeping DM Sans as a
   fallback before the system stack means the licensed face is
   the brand expression and DM Sans is the cleanly-licensed
   fallback if a deploy fails or a contributor builds locally
   without licence access.

That's a deferred change with a clear path. Today's posture is
DM Sans across the board.
