# `fonts/` — Brandon Grotesque (licensed brand face)

Paxiom's brand body face is **Brandon Grotesque** by HVD Fonts /
Hannes von Döhren. It's a commercial font; redistributing the
`.woff2` files via this public repository would violate the EULA
regardless of which weights are shipped.

## What lives here

This directory is **intentionally empty in the public repo.** The
`.woff2` files for the licensed Brandon Grotesque faces are provided
to `paxiom.org` at deploy time, not via this checkout. Two equivalent
ways to make that work:

1. **Deploy-time copy.** The deploy pipeline (Netlify / Cloudflare /
   GH Pages publish step) copies the `.woff2` files from a private
   location into `paxiom.org/fonts/` before publishing. The public
   repo never touches them.
2. **Separate font origin.** The `@font-face` declarations in
   `/fonts.css` reference an absolute URL on a separately-hosted
   origin (e.g. `https://fonts.paxiom.org/...`) governed by
   referrer-locked CDN access. Same effect; trades complexity for
   stricter control.

The repo's `fonts.css` currently uses `/fonts/...` paths, which
matches option (1). If you switch to option (2), update the URL
prefixes in `fonts.css` and document the new origin here.

## Expected file names (option 1)

The `@font-face` rules in `fonts.css` reference these paths.
Ten files; pair regular + italic at five weights:

```
fonts/BrandonGrotesque-Light.woff2
fonts/BrandonGrotesque-LightItalic.woff2
fonts/BrandonGrotesque-Regular.woff2
fonts/BrandonGrotesque-RegularItalic.woff2
fonts/BrandonGrotesque-Medium.woff2
fonts/BrandonGrotesque-MediumItalic.woff2
fonts/BrandonGrotesque-Bold.woff2
fonts/BrandonGrotesque-BoldItalic.woff2
fonts/BrandonGrotesque-Black.woff2
fonts/BrandonGrotesque-BlackItalic.woff2
```

CSS weight mapping:

| weight | file                                |
|-------:|-------------------------------------|
|    300 | `Light` / `LightItalic`             |
|    400 | `Regular` / `RegularItalic`         |
|    500 | `Medium` / `MediumItalic`           |
|    600 | `Bold` / `BoldItalic`               |
|    700 | `Black` / `BlackItalic`             |

If any weight is missing at deploy time, the system-font fallback
(`system-ui, -apple-system, sans-serif`) takes over for that weight
— the page renders correctly, just without the licensed face. This
is by design: the public repo is a working dev environment by itself.

## License audit trail

- **Family:** Brandon Grotesque
- **Foundry:** HVD Fonts / Hannes von Döhren
- **License type:** commercial; web license required for paxiom.org
- **Web license file:** *operator action — record the EULA reference
  and seat count in a private record once the licence is in hand*
- **Repository disposition:** `.woff2` files NOT committed; provided
  via deploy pipeline. This README replaces a `LICENSE.txt` because
  the licence covers a private deployment seat, not a redistribution
  grant — there is nothing for a public reader of this repo to
  download under licence.

## Earlier history

Phase 0 of the public site shipped Neutraface Text `.woff2` files in
this directory by mistake — also a commercial font, also redistributed
without licence. They were removed and the brand face swapped to
Brandon Grotesque in the same commit (`paxiom-static@…`). Anyone with
a clone of the older history still has the Neutraface files locally;
the active repo no longer redistributes them.

## If the licence is not yet in hand

The `@font-face` rules will produce 404s on the live site until the
files are provisioned. The page still renders via the system-font
fallback, so the public site does not break visually — it just
doesn't carry the brand face yet. Provision via option (1) or (2)
above when the licence arrives.

## Open question (if relevant)

If at any point Brandon Grotesque becomes licensing-prohibitive (for
instance: per-pageview pricing on a high-traffic public site), the
two open-source visual neighbours worth evaluating are **DM Sans**
(closer to geometric architectural feel) and **Outfit** (slightly
warmer, more character). Both are SIL-OFL and may be self-hosted
without licence overhead.
