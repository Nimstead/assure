# Nimstead documentation wiki

Static, searchable documentation for `https://docs.nimstead.systems`. Markdown lives in `../docs`; `products.json` defines the product directory, with Assure first. `pages.json` controls published articles and order; every article names its product and Diataxis group. The build rewrites repository links to site routes where a published page exists.

## Build and verify

From this directory, with Node.js 22:

```bash
npm ci
npm run build
npm test
npm run dev
```

Open `http://localhost:4321`. The build fails on missing local targets and heading links. Search runs in the browser and sends no queries to a service. Articles and navigation remain available without JavaScript.

`DOCS_SOURCE_REF` selects the GitHub branch for source/edit links. It defaults to the current checkout branch. Set it to `main` for a build from merged main.

## Maintain content

1. Edit the canonical Markdown under `docs/`.
2. Add a record in `pages.json` for each new published page, including its product ID. Add new products to `products.json`.
3. Choose one primary Diataxis type and place the page in that group.
4. Build, test, and inspect desktop/mobile layouts before publication.
5. Keep historical plans linked to their repository source, not presented as current operator instructions.

## Publish

The Sites project ID is tracked in `.openai/hosting.json`. Publish the verified `dist` tree as a static artifact with that same identity. The Sites source checkout is a publication snapshot; the Assure repository remains the canonical source for Markdown, templates, and styling.

Do not create a second Sites project for an update. Use the Sites source helper and the existing project credential, save the exact pushed snapshot, then deploy that saved version. The custom domain is `docs.nimstead.systems`.

Fonts and favicon are reused from Nimstead's public website. `DESIGN.md` records the reading interface's tokens and behaviour. No analytics, cookies, account system, or browser editing service is added.

Pulse articles live under `docs/pulse/` and cite the maintained Pulse repository. Check its current implementation when changing claims. Existing Assure article routes remain stable; product homes are `/assure/` and `/pulse/`.

The API catalog and `docs/reference/openapi.json` come from `scripts/export_api_docs.py`, run through the locked API environment. Refresh these before building after API changes. API CI checks freshness; the site build publishes the JSON at `/reference/openapi.json`. Empty response schemas retain their documented limitations.
