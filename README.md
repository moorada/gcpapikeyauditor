# GCP API Key Auditor

Browser-based tool to audit a Google Cloud API key and estimate its exposure surface:

- Which APIs are reachable from a browser context
- Whether key restrictions (referrer / IP / app) are enforced
- Abuse impact per endpoint (cost, data access, auth risk)
- Automatic project-ID disclosure detection and project-scoped probes

No data leaves your environment — the key is only sent directly to Google APIs (or through your own proxy).

---

## Architecture

| Layer | Technology |
|-------|-----------|
| Frontend | Static HTML / CSS / JS — no build step |
| Backend proxy | Cloudflare Pages Functions (`/functions/api/`) |
| Hosting | Cloudflare Pages |

The proxy is required only for endpoints that block browser CORS (Maps REST, some AI APIs). Without it the tool runs in **client-only mode** using JSONP for Maps endpoints.

---

## Local development

### Option A — Wrangler (recommended, mirrors production)

Runs both the static frontend and the Pages Functions locally.

```sh
npm install
npm run dev
```

Open `http://localhost:8787`. The backend activates automatically.

### Option B — Node.js proxy

```sh
npm install
npm start
```

Open `index.html` directly in the browser. The backend on `localhost:3001` is detected automatically.

### Option C — Client-only (no install)

Just open `index.html` in any browser. Maps REST endpoints fall back to JSONP; other CORS-blocked probes will show as `unknown`.

---

## Deploy to Cloudflare Pages

### First deploy (via CLI)

```sh
npm install
npx wrangler login
npm run deploy:cli
```

Wrangler will create the Pages project and print the deployment URL.

### Configure a custom domain

1. In the [Cloudflare dashboard](https://dash.cloudflare.com), go to **Pages → your project → Custom domains**.
2. Add your domain (e.g. `gcpapikeyauditor.alongale.com`).
3. Cloudflare will add the DNS record automatically if your domain is on the same account.

### Subsequent deploys

Push to `main` — Cloudflare Pages auto-deploys on every push. No build command needed; leave both **Build command** and **Deploy command** empty in the dashboard.

To deploy manually from the CLI instead:
```sh
npm run deploy:cli
```

---

## Security notes

- The proxy (`/functions/api/probe.js`) only forwards requests to `*.googleapis.com` over HTTPS. All other targets are rejected with HTTP 403.
- The API key travels in the POST body, never in URLs or query parameters, so it does not appear in Cloudflare access logs.
- The tool is a **client-side exposure estimate**. It cannot read internal GCP key policy or IAM configuration without OAuth credentials.

---

## Probe coverage

| Category | APIs tested |
|----------|-------------|
| Maps | Geocoding, Places, Directions, Distance Matrix |
| AI | Gemini, Vision, Translation, Natural Language, Text-to-Speech, Speech-to-Text |
| Location | Geolocation |
| Auth | Firebase Identity Toolkit |
| Media | YouTube Data v3, Google Books |
| Search | Custom Search, Knowledge Graph |
| Firebase | Dynamic Links |
| Storage* | Cloud Storage bucket list |
| Infrastructure* | Pub/Sub topic list |

\* Added automatically when a project ID is discovered via error response leakage.
