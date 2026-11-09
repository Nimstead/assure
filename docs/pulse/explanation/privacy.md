# How private list analysis works

Pulse keeps a personal CVE list in browser memory. It does not need an account or a server-side list store.

## Requests do not follow your list

The personal-list view fetches the complete public index. Every visitor uses the same index requests. Downloading descriptions fetches all description shards in a fixed order.

This costs more bandwidth than fetching only selected IDs. It avoids revealing the selected IDs through per-CVE request paths. The fixed worked example is the same for every visitor.

## Persistence is an explicit action

Snapshots and handovers are created only when requested. A snapshot preserves the selected IDs and public observations without retaining the raw scanner export. The file still contains potentially sensitive information about the user's interests or environment.

Reloading clears the in-memory session. **Clear** removes the list and comparison baseline from the page, with one in-memory undo step. Neither action deletes files already downloaded or clipboard text already copied.

## External links have a separate boundary

Opening a public CVE link sends that selected ID to the linked site. Decide whether to follow that link separately from the privacy properties of local analysis.

See [analyse your list](../how-to/analyse-list.md) and [snapshots](../how-to/snapshots.md).

Source: [Pulse repository documentation](https://github.com/Nimstead/pulse/blob/main/README.md).
