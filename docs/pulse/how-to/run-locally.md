# Run Pulse locally

Build a local copy of Pulse from its public repository. You need Python 3.12 or later and Node.js 22.18 or later. The initial data download is approximately 400 MB.

## Install and start

```bash
git clone https://github.com/Nimstead/pulse.git
cd pulse
npm ci
npm run data
npm run dev
```

Open the local URL printed by Vite, normally `http://localhost:5173`. Confirm that the reports display their feed dates and that **Your CVEs** loads its worked example.

`npm run data` writes generated JSON under `public/data/`. Later runs use conditional requests to avoid downloading unchanged feeds.

## Check and build

```bash
npm test
npm run check
npm run build
```

The build renders public reports as HTML and checks the output and sitemap. Serve `dist/` on a static host.

If the data build fails, inspect the source-specific error and retain the previous working publication. Do not present a partial refresh as a current report.

For deployment and browser-test configuration, use the [Pulse repository instructions](https://github.com/Nimstead/pulse/blob/main/README.md).

Source: [Pulse repository documentation](https://github.com/Nimstead/pulse/blob/main/README.md).
