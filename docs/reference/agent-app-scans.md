# Agent application metadata scans

Optional scans read application package metadata from disk. They do not establish runtime use or exhaustive discovery. Their default readers do not import discovered Python modules or launch package programs.

## Interfaces and records

| Function | Inputs and result |
| --- | --- |
| `local_roots()` | Slash on non-Windows. Fixed-drive roots C through Z on Windows. No mount validation |
| `net_mounts()` | Recognized /proc/mounts network paths. OSError returns empty. Escaped paths are not decoded |
| `scan_jars(roots,max_seconds=300,max_files=500000,mounts=None,owned=...)` | Maven package list and Java summary |
| `scan_apps(roots,owned=...,problems=(),seconds=120,entries=300000,max_packages=20000,mounts=None,known=None)` | PyPI/npm list, Python source line, npm source line, summary |
| `package_owned(dpkg_info,apk_db,which,nt)` | Ownership predicate and optional warning. Windows default is captured at import |
| `regular(path)` | Point-in-time lstat regular-file result. OSError returns false. This does not secure a later open |

Package records contain ecosystem, name, version and source. Deduplication uses full location before source truncation to 255 characters. Different long paths can become indistinguishable after truncation.

## Java discovery

Java scans supplied roots for jar/war/ear names. Normal opt-in uses local_roots(), not app_roots. It reads matching META-INF/maven group/artifact pom.properties and one nested jar level.

Properties entries must declare at most 64KiB uncompressed size. Nested jars must declare at most 50MiB. Coordinate/version shapes and lengths are checked. Filename coordinates supply missing property names. Later duplicate properties replace earlier values.

Corrupt/unreadable archives and several ZIP/runtime errors are skipped without an unread counter. A bad nested jar can stop the remaining entries of that archive. Earlier discoveries remain. Unexpected ZIP, callback and type errors can propagate.

| Java summary field | Meaning |
| --- | --- |
| `files` | Walked filenames, including nonarchives, capped at max_files for display |
| `complete` | No time/file budget stop. Does not establish successful reads or exhaustive discovery |
| `partial` | Optional budget-stop text |
| `owned` | Candidate archives excluded by ownership predicate |
| `locations` | First 100 sorted coordinate/version/location triples. Location suffixes have at most 300 characters |

Missing roots and traversal failures can produce complete=true with no packages. Bad archives can leave it true too. scan_jars() has no separate package-count cap.

## Python and npm discovery

Default Python roots cover declared system/user site-packages and dist-packages globs. Npm defaults cover declared global install folders. Windows defaults assume C:. Other layouts need extra roots.

Extra-root discovery searches eight levels for install folders. It excludes selected directories and observed links. Python readers accept dist-info and egg-info. Npm readers accept package.json, scopes and nested node_modules through depth six.

Python reads at most 65,536 text characters. Exact Name/Version headers before a blank line are accepted, with first values retained. Name separators/case are normalized. Shape validation does not establish installed or runtime state.

Npm checks current regular-file status and size at most 1MiB before json.load. Concurrent changes can invalidate that size check. Name/version shapes are checked. Ordinary I/O/parse problems become unread counts. Recursion and other unexpected failures can propagate.

known is a pair of Python/npm glob sequences. A pair of empty sequences disables default roots for tests. Default install folders and explicitly named install-folder roots can bypass discovery walk exclusions. Callers must select appropriate roots.

### Default root patterns

| Platform/ecosystem | Glob |
| --- | --- |
| Linux Python | `/usr/lib/python3*/site-packages` |
| Linux Python | `/usr/lib/python3*/dist-packages` |
| Linux Python | `/usr/lib/python3/dist-packages` |
| Linux Python | `/usr/lib64/python3*/site-packages` |
| Linux Python | `/usr/local/lib/python3*/site-packages` |
| Linux Python | `/usr/local/lib/python3*/dist-packages` |
| Linux Python | `/usr/local/lib64/python3*/site-packages` |
| Linux Python | `/root/.local/lib/python3*/site-packages` |
| Linux Python | `/home/*/.local/lib/python3*/site-packages` |
| Linux npm | `/usr/lib/node_modules` |
| Linux npm | `/usr/local/lib/node_modules` |
| Windows Python | `C:\Program Files\Python*\Lib\site-packages` |
| Windows Python | `C:\Program Files (x86)\Python*\Lib\site-packages` |
| Windows Python | `C:\Python*\Lib\site-packages` |
| Windows Python | `C:\Users\*\AppData\Local\Programs\Python\Python*\Lib\site-packages` |
| Windows Python | `C:\Users\*\AppData\Roaming\Python\Python*\site-packages` |
| Windows npm | `C:\Program Files\nodejs\node_modules` |
| Windows npm | `C:\Users\*\AppData\Roaming\npm\node_modules` |

These globs supplement extra roots. They do not infer every virtual environment or project folder.

## Budgets, paths and ownership

Time and entry budgets are shared across discovery and both language scans. Checks occur at traversal/metadata boundaries. Directory listing, glob expansion, ZIP reads and metadata reads are not hard wall-clock bounded.

The package threshold is checked after a folder. Internal work can exceed max_packages. The returned sorted list is capped at that value. Python records precede npm in this ordering.

Network exclusion recognizes nfs, nfs4, cifs, smb3, smbfs, fuse.sshfs, 9p and afs through exact mountpoint strings. Observed child links and repeated mounted filesystems are pruned where discovery applies those checks. Root aliases, known folders, escaped paths and concurrent changes limit these guards. They are not filesystem isolation guarantees.

Walk filters exclude the /proc, /sys, /dev, /run and /snap root prefixes. Windows patterns exclude Windows, $Recycle.Bin and System Volume Information directories at a drive root. Known/direct install folders can bypass these discovery filters.

Ownership uses selected apk/dpkg file-list paths when available. RPM uses a location heuristic, not a database query. Partial file-list reads return a partial predicate and warning. They can permit duplicate classification. Windows ownership defaults to false. A custom install inside an RPM-owned-tree heuristic can be excluded without actual ownership proof.

## Application status and summary

Python/npm source lines contain state/count and optional error. Shared ownership/root problems affect both. Unread metadata, budget stops and retained counts determine partial/failed states. A source completed before a later stop can remain ok.

Summary fields are owned, folders, entries, seconds and roots. Entries counts budget checks, not every filesystem entry. Folders counts selected install directories. Roots retains at most 20 labels of at most 300 trailing characters. Direct helper/config input is not itself limited to 20 roots.

These functions perform no host writes or upload. Trusted argument shapes and callbacks remain necessary. Related: [enable optional collection](../how-to/collect-application-metadata.md), [agent core](agent-core.md), [source](../../agent/nimstead_agent.py).
