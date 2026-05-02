# `fonts/` — licensing audit pending

> **OPEN, operator action required.** This directory commits eight
> Neutraface Text `.woff2` files to a **public** GitHub repository.
> Neutraface is a commercial House Industries family. No license file
> is present in this repo documenting the rights under which these
> files are redistributed. Until that is resolved, treat as a known
> open compliance question.

## Why this matters

Two distinct surfaces:

1. **Serving from paxiom.org.** Most commercial web-font EULAs allow
   self-hosted serving on a single domain after license purchase. If
   you have a Neutraface web license and `paxiom.org` is on the
   licensed domain list, this surface is fine.
2. **Hosting in a public GitHub repo.** Even with a valid web license,
   most commercial font EULAs prohibit redistribution. A public repo
   that ships the `.woff2` files lets anyone download the font without
   attribution or licensing — which is a separate violation from the
   serving question.

The first is your call once the license is verified; the second is
unambiguous and should be addressed regardless.

## Three concrete options

Pick one (any of them resolves both surfaces):

### 1. Verify license + restrict hosting

- Confirm the Neutraface web license covers paxiom.org.
- Move the `.woff2` files out of the public repo. Two ways to do that:
  - Build step: copy from a private location into the `gh-pages`
    deploy branch, but keep `main` clean.
  - Server-side serving: host the fonts behind paxiom.org/_fonts/
    with a separate origin/CDN that doesn't expose them as
    downloadable artifacts (Netlify/Cloudflare access policies, etc.).
- Add a `fonts/LICENSE.txt` describing the license and link to House
  Industries' EULA reference.

### 2. Swap to a permissively-licensed equivalent

Several open-source families approximate Neutraface's geometric-with-
character feel and are SIL-OFL or SIL-OFL-with-RFN:

- **Cabin** (SIL OFL) — geometric, slightly rounded, comfortable on
  long-form text. Closest visual match.
- **Public Sans** (SIL OFL) — US gov standard, sans-serif workhorse,
  unambiguously redistributable.
- **Inter** (SIL OFL) — already widely used in tech docs; if the
  display feel matters less than the body comfort, this is the safest.

Switching is a one-file change to `fonts.css` plus committing the new
`.woff2` files in place of the Neutraface ones. Visual diff: small.

### 3. Drop bundled fonts entirely; ship the system font stack

The body rule on every paxiom-static page already cascades to
`'Neutraface Text', system-ui, -apple-system, sans-serif`. Removing
the `@font-face` blocks (and the `.woff2` files) is harmless to the
fallback layout — modern macOS / Windows / Linux all render the system
stack acceptably for the binder aesthetic. Cheapest option, smallest
download, no licensing overhead.

## What I recommend (pick one)

For a public-website-on-a-public-repo posture, **Option 2 or Option 3**
is the simplest path. The architectural-binder visual identity does
not depend on Neutraface specifically — what carries the look is the
combination of generous whitespace, JetBrains Mono for labels, and
serif headers (Times New Roman, which is universally available).
Swapping the body face for Public Sans or dropping it for the system
stack preserves the identity at near-zero implementation cost.

If the brand identity does require Neutraface, **Option 1** is the
correct path and the work is licensing administration plus a deploy
pipeline change — not a code change in this repo.

This README is the explicit prompt for that decision. Until it
resolves, the public site continues to serve Neutraface as it has;
nothing here breaks. The risk surface is licensing, not user
experience.
