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
