# /fonts/ — intentionally empty

The Paxiom static site uses **system fonts only**. No web fonts are loaded;
no font binaries are vendored.

## Why

The original design called for DM Sans (body) and JetBrains Mono (mono),
served via the Google Fonts CDN. Each page load pinged
`fonts.googleapis.com` and `fonts.gstatic.com`, leaking client IPs to a
third party we have no reason to involve in serving public marketing
pages. The audit (L-4 / follow-up #54) called this out as a privacy and
supply-chain hygiene gap.

Two paths considered:

1. **Self-host** the `.woff2` files. Closes the privacy problem but adds
   a font-subsetting toolchain (`pyftsubset`), OFL attribution
   maintenance, per-weight binary management, and visual-diff QA on
   every release.
2. **Drop custom fonts entirely.** Closes the privacy problem with no
   binaries, no licensing tail, no toolchain. The binder/drawing-set
   aesthetic is driven by layout, rules, spacing, serif headings, and
   the project mark — not by DM Sans specifically.

We picked (2). DM Sans and JetBrains Mono are both OFL-licensed and
legally fine to vendor; the issue was always the third-party network
dependency, which (2) eliminates without taking on the maintenance load
of (1).

## Stacks now in use

Defined inline in each page's `<style>` block (and centralised tokens in
`/fonts.css`):

| Role        | Stack                                                                                       |
|-------------|---------------------------------------------------------------------------------------------|
| Body sans   | `system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`                      |
| Mono / code | `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace`       |
| Headings    | `"Times New Roman", Times, serif`  (kept; renders from system on every platform)            |

SVG `<text>` `font-family` attributes use a shorter mono stack
(`ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace`) to
avoid embedding quoted family names inside double-quoted attribute
values. The Linux-specific `"Liberation Mono"` fallback is omitted from
the SVG context only.

## CSP

`style-src 'self' 'unsafe-inline'; font-src 'self';` — no third-party
domains. `font-src 'self'` is harmless and future-safe even though
nothing currently loads from `/fonts/`.

## If we ever reintroduce a custom face

1. Drop subsetted `.woff2` files into this directory.
2. Add `@font-face` rules in `/fonts.css` pointing at them.
3. Update the body / mono stacks in every page's inline `<style>`.
4. Update this README.

Never load from `fonts.googleapis.com`, `fonts.gstatic.com`, or any
other third-party font CDN.

## Earlier history (audit trail)

The repo went through three brand-face iterations:

1. **Neutraface Text** (Phase 0 launch) — commercial; House Industries.
   Eight `.woff2` files were committed to a public repo, which is almost
   always prohibited regardless of whether a web licence exists. Caught
   in PR-#9 audit review.
2. **Brandon Grotesque** (interim) — also commercial; HVD Fonts. Same
   redistribution posture. CSS swapped, no `.woff2` files committed;
   would have required a deploy-time pipeline to render the licensed
   face on the live site.
3. **DM Sans + JetBrains Mono via Google Fonts CDN** — license-clean
   (both OFL) but introduced the third-party network dependency this
   change removes.
4. **System fonts only** (current) — no licence tail, no third-party
   network dependency, no `.woff2` files vendored.
