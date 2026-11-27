# Spec: paths — how an attacker gets from the network to root to the next Linux machine (V1)

Status: **approved 2026-11-26** (written on `/agent-skills:spec` "Next phase. Impress me. Market leader tool."; the owner
moved it on with `/agent-skills:plan`, taking each open question's recommendation). Follows the runtime phase (0.14).
Plan: `tasks/plan-paths.md`, tasks: `tasks/todo-paths.md`. DECISIONS from 165. Ships as 0.15.0 with agent 0.11.0.

## Objective

**The gap.** Nimstead's reports and attack-path view cover Windows only: Linux hosts get no paths at all ("Linux hosts and
SBOMs get no paths. Their settings facts would come first", `docs/engine/design-paths.md`). Since 0.14 Nimstead knows which
vulnerable library a listening Linux service has loaded, and which user that service runs as. The next question a security
lead asks is **"and then what?"**:

1. Getting in as `www-data` through nginx's `libssl3`: can `www-data` become root?
2. Once root, what does the machine hand over? On Linux fleets that is mostly **SSH private keys**: deploy keys, backup
   keys, an admin's old `id_rsa` left in `/root/.ssh`.
3. Which other machines do those keys open, as which account? Keys spread over years, so nobody can answer that today
   without reading every `authorized_keys` by hand.

Wiz and Orca find SSH keys on cloud VM disks that open other VMs. XM Cyber sells "choke points". BloodHound maps Active
Directory. Each of them is cloud or agentless SaaS, or doesn't cover Linux SSH. The on-premises and self-hosted Linux fleets
where SSH keys are the main way to move between machines get nothing, and Tenable, Qualys and Rapid7 VM agents list CVEs per
host. Nimstead can answer all three questions from the agent that is already on each machine.

**Who.** The security lead who has to cut paths, not count CVEs. The platform engineer who owns the keys and `sudoers`. The
auditor who asks "if the web server falls, what else goes with it?"

**What sets ours apart** (the promises the rest of Nimstead keeps):
1. **Exact, not guessed.** A key edge from A to B exists only when the public half of a private key held on A appears in an
   `authorized_keys` on B (same SHA-256 fingerprint). It is graded *confirmed* only when B's sshd listens beyond loopback and
   lets that account in by key, the key needs no passphrase, and A was seen holding a connection open to B. No edge comes from
   a name, a guess or a probe.
2. **Privilege-aware.** The runtime read knows the user each listening program runs as. A flaw in a root listener is root
   straight away. A flaw in `www-data`'s nginx needs a way up that `www-data` can actually use: a local flaw any user can
   reach, a group that equals root (`docker`, `lxd`, `disk`), `sudo` with no password, or a file root runs that `www-data`
   can write. This closes design-paths' "Not yet: whether an escalation flaw is reachable from the entry's privilege level"
   for Linux.
3. **Nothing secret leaves the machine.** The agent reads only the public half of a private key: an OpenSSH-format key
   stores it unencrypted in its header; for an older PEM key the `.pub` file beside it is used, and without one the key is
   counted but not identified. What it sends: fingerprint, key type, whether a passphrase protects it, the owning account and
   path. Key comments (often an email address), private-key bytes, credential-file contents and forced-command text are
   never sent.
4. **Break it where it's cheapest.** Each chain says what to fix. Across the fleet, **choke points** rank the single actions
   that cut the most machines off from every way in. For example: "Retire deploy's key (held on build-1, authorized on 9
   machines): 7 machines become unreachable from the 3 machines with a way in from the network."

### User stories and acceptance
- **S1.** As a security lead, a Linux machine's report and drawer show its attack paths in words. For example: "From the
  network: CVE-2026-1234 in libssl3, loaded by nginx.service listening on 10.0.4.7:443, which runs as www-data. Becoming
  root: www-data is in the docker group. Taking credentials: root's SSH key /root/.ssh/id_ed25519 (no passphrase). Then:
  this machine's keys open 3 accounts on 2 machines."
- **S2.** The fleet attack-path view includes Linux machines and key edges: "build-1 → db-1: the key /root/.ssh/id_ed25519
  on build-1 is authorized for root on db-1; db-1's sshd listens on 10.0.4.9:22 and allows root by key; build-1 had a
  connection open to db-1". Each edge carries its grade and reason. Chains from machines with a way in (or marked
  internet-facing) list every machine reachable, fewest hops first.
- **S3.** The fleet view's **choke points** list up to ten single actions, each with how many machines it cuts off and what
  doing it means: update one package on one machine, retire a key, remove a key from one `authorized_keys`, or change one
  setting.
- **S4.** Linux settings that open a stage become findings, like Windows' settings findings: each says what was read, who it
  helps and the fix in words. They show in Findings, Fix first, tickets and the evidence pack like any finding.
- **S5.** A machine's owner turns these reads off locally (`"paths": false` in the agent's configuration, or
  `enroll --no-paths`). The server can't turn them back on. Packages and runtime are read as before.

## Scope

### Module 1: `linux-facts`, what the agent reads (agent 0.11.0, Linux)

One bounded pass at each inventory, as root. Its addresses and peers go in the inventory's `facts` (the keys Windows
already sends). Everything else goes in a top-level `access` object with an `access` collection line: it is too big for
`facts`' 64 KB limit, and only paths and settings read it (planning, 2026-11-26).
- **sshd.** `sshd -T` (the effective configuration): `permitrootlogin`, `pubkeyauthentication`, `passwordauthentication`,
  `kbdinteractiveauthentication`, `permitemptypasswords`, `authorizedkeysfile`, `authorizedkeyscommand` (set or not),
  `allowusers`, `denyusers`, `allowgroups`, `denygroups`, plus whether the configuration has `Match` blocks. Where sshd
  listens comes from the runtime read.
- **Accounts.** Accounts with a login shell, plus root and every account a running program uses (name, uid, groups) from
  `/etc/passwd` and `/etc/group` (`getent` where NSS adds directory users), and whether each one's password is usable,
  locked or empty, read from `/etc/shadow`. Only that state is sent, never the hash (T0: AlmaLinux's image ships
  `PermitRootLogin yes`, which matters only if root has a password). Members of root-equivalent groups: `docker`,
  `lxd`, `incus-admin`, `disk`. `sudo -n -l -U <account>` for those accounts (at most 32): only an entry of
  `NOPASSWD: ALL` (any runas) counts.
- **Files root runs that others can write.** For each systemd system service that runs as root: its unit file and
  `ExecStart` executable. Then `/etc/crontab` and the files in `/etc/cron.d` and `/etc/cron.{hourly,daily,weekly,monthly}`.
  Each file and each parent directory up to `/` is checked: writable by a non-root owner, by a group other than root, or by
  everyone. The fact names who can write it.
- **Keys held.** In each listed account's `~/.ssh` (root's included), plus `IdentityFile` lines in `~/.ssh/config`: each
  private key's account, path, type, SHA-256 fingerprint of the public key, and whether a passphrase protects it (OpenSSH
  cipher not `none`, or PEM `ENCRYPTED`). Regular files only, opened without following links, owned by that account or root,
  at most 64 KB read.
- **Keys trusted.** Each listed account's `AuthorizedKeysFile` (with `%h`, `%u` and `%%` expanded): for each key, its
  account, fingerprint, type, its `from=` patterns (16 at most, 64 characters each), and whether it has `command=` or
  `restrict`. The command's text is never sent.
- **Other credentials, presence only.** `/etc/krb5.keytab`, and in each listed account's home: `.aws/credentials`,
  `.kube/config`, `.docker/config.json`, `.pgpass`, `.netrc`, `.git-credentials`. The fact holds kind, account and path,
  never the contents.
- **Network.** Its own IPv4 addresses, and the private-range addresses it holds an established TCP connection to (from
  `/proc/net/tcp`), as DECISIONS 112 does on Windows. Public addresses are never sent.
- **Budgets** (named constants, each stop said in the same words every time): 64 accounts, 16 key files per account, 1,000
  trusted keys per account, 1 MB per `authorized_keys`, 512 files root runs, 10 seconds for the pass. A pass that hits one
  is **partial**: what it saw counts, nothing is concluded from what it didn't see, and a fact it couldn't read is `null`,
  never empty. Run without root, the pass is partial and says so.
- Windows facts are unchanged. Local opt-out as in S5.

### Module 2: `linux-checks`, settings judged into findings (API)

`linconfig.evaluate(facts)`, the Linux counterpart of `winconfig.evaluate`, gives findings in a `LinuxConfig` ecosystem,
each with a `CFG:` id, a severity, who it helps and its fix in words (no automated fix in V1):

| Check | Opens | Rule |
|---|---|---|
| `ssh-root-password` | Getting in | sshd listens beyond loopback, `permitrootlogin yes`, password or keyboard-interactive sign-in is on, and root's password is usable |
| `ssh-empty-passwords` | Getting in | sshd listens beyond loopback, `permitemptypasswords yes`, and an account that may sign in has an empty password |
| `root-equivalent-group` | Becoming root | an account other than root is in `docker`, `lxd`, `incus-admin` or `disk` |
| `sudo-nopasswd-all` | Becoming root | an account other than root has `NOPASSWD: ALL` |
| `writable-root-run` | Becoming root | a file root runs, or a folder above it, is writable by someone other than root |
| `shadow-readable` | Taking credentials | `/etc/shadow` is readable by a non-root account or group other than `shadow` |

A check whose facts weren't read opens nothing. A check that is fixed closes on the next complete read, as `winconfig`
findings do.

### Module 3: `linux-paths`, attack paths on one Linux machine (engine)

`engine/paths.py` builds paths for Linux with the same four stages. "Becoming SYSTEM or an administrator" reads "Becoming
root" there. Ways through each stage:
- **Getting in:** a vulnerable verdict whose vector is network with no privileges and high impact, on a package the server's
  runtime memory has as **listening** (loaded by a program listening beyond loopback within seven days). Graded no better
  than *reasonable*, because the host firewall isn't read. A known-exploited remote flaw with no listener seen is
  *reasonable*, as on Windows. `ssh-root-password` and `ssh-empty-passwords` count too. Each way carries the listening
  program's user.
- **Becoming root:** a vulnerable verdict whose vector is local with low or no privileges and high impact (the running
  kernel's verdicts included, R7.7), which any local user can use. A setting from Module 2 counts only for the user it
  helps: the way-in user is in that group, has that `sudo` entry, or can write that file (or everyone can). A way in through
  a program that runs as root **skips this stage**, and the path says why.
- **Taking credentials:** once root, every key held on the machine (no passphrase: graded as read; with a passphrase:
  *unverified*, "needs its passphrase"), `krb5.keytab` (the machine's domain account), and the other credential files
  ("opens something beyond this fleet: not followed"). Without root, only keys and files the way-in user owns.
- **Then (reaching other hosts):** the number of keys held, pointing to the fleet view, which knows where they open.
- The path rules are unchanged: a path from the network needs a way in plus escalation or credentials; a foothold path
  needs both; grade = the weakest step; **Break it** = the narrowest stage. Windows paths are unchanged.

### Module 4: `fleet-ssh`, key edges, chains and choke points (API)

- **Key edges** in `engine/fleet.py`, beside the existing Windows edges. A→B for each key K held on A and each account u on
  B whose trusted keys include K, when all of these hold:
  - A's report has a path that reaches root, or reaches K's owner.
  - B's sshd listens beyond loopback, with public-key sign-in on.
  - u may sign in: for root, `permitrootlogin` isn't `no`; u isn't blocked by Allow/Deny users or groups.
  - Every `from=` on the line matches one of A's addresses, or there is no `from=`.

  Grades:

  | Situation | Grade |
  |---|---|
  | No passphrase | *reasonable* |
  | No passphrase, and A was seen connected to one of B's addresses | *confirmed* |
  | Key has a passphrase | *unverified* |
  | Line has `command=` | *unverified* ("signs in only to a forced command") |
  | Line has `restrict` without `command=` | grade unchanged; the reason says there's no terminal or forwarding, though commands still run (T0) |
  | B's sshd has `Match` blocks | no better than *reasonable* |
  | B has `authorizedkeyscommand` set | *unverified* ("keys come from a command that isn't read") |

  Each edge says what B hands over: root if u is root or root-equivalent on B, otherwise u, and B's own foothold path
  continues from there.
- **Chains:** the existing breadth-first walk from machines with a way in or marked internet-facing, now through Windows
  and key edges alike.
- **Choke points**, new in `GET /api/attack-paths`. Candidates: each machine's way in (one package update or setting on a
  starting machine), each key (retire it: delete it on the machines that hold it, remove it wherever it's trusted), each key
  line on one target, and each Windows edge's setting on its target. For each candidate (at most 200), remove what it
  removes and count the machines no longer reachable from any start. The top ten, largest first, each give the action in
  words, its machines cut, and the paths it removes.
- `MAX_EDGES` and the per-organisation read limit stay; key edges count toward them.

### Module 5: `paths-ui` (web)
- **Machine drawer / report:** Linux paths with the way-in user, "skips becoming root" where the program runs as root, and
  credentials in words.
- **Fleet attack paths (Assets):** key edges in words (key path on A, account on B, why the grade). A **Choke points** card
  above the chains, each linking to the machines and findings it names.
- **Findings:** the six `LinuxConfig` checks with their fix text, filterable like Windows' settings.

### Out of scope (deferred, V2 backlog)
- **Keys loaded in a signed-in user's ssh-agent** (forwarded agents): reading them means connecting to someone's agent.
  Agent sockets are counted, not opened.
- **SSH certificates** (`TrustedUserCAKeys`, a CA key held on a machine opening every machine that trusts it), and
  `AuthorizedKeysCommand` key sources (LDAP, IAM).
- **`known_hosts` and `~/.ssh/config` host entries** as routing hints (hashed entries need per-host matching).
- **`sudo` rules other than `NOPASSWD: ALL`** (specific commands that escape to a shell).
- **Linux to Windows edges** (a keytab or sssd cache giving an Active Directory account), and cloud or Kubernetes
  credentials followed into their accounts.
- **Fixes for Linux settings and keys** (remove a key, change sshd): a new remote action needs its own trust design.
- **Container escape paths**, the host firewall, and `Match` blocks judged per user and address.
- **Password reuse across machines:** it would need password hashes off the machine, which is never acceptable.

## Tech stack
Unchanged: the agent is one Python file (stdlib only, Python 3.9+ on Linux); the API is Python 3.14, FastAPI, SQLAlchemy and
Alembic; the web app is React 19 with TanStack Router and Query, Tailwind, Vitest and Playwright with axe. No new dependency.
One migration: an `asset_access` table (one row per host, the latest `access` read), so the assets list never loads key
lists, as `asset_runtime` does for runtime. Settings findings use the finding table, and choke points are computed per
request. Proof tooling, in disposable machines only: OpenSSH (`ssh`, `ssh-keygen -lf`, `sshd -T`), `ss`, `getent`,
`id`, `find`, Podman.

## Commands
```
API + agent tests:  (cd api && uv run ruff check src tests ../agent ../sandbox ../scripts && PYTHONUTF8=1 uv run pytest -q)
Agent facts on Linux (WSL, root and non-root):  wsl -d Ubuntu -- python3 -m pytest api/tests/test_agent_linux_facts.py
Web:                (cd web && npm test && npx tsc --noEmit && npm run build && npm run e2e)
Docs checks:        (cd api && PYTHONUTF8=1 uv run python ../scripts/check_docs.py && uv run python ../scripts/export_api_docs.py --check)
Real-host proof:    (cd api && uv run python ../sandbox/paths_lab.py)        # a fresh disposable lab each run
Performance:        (cd api && uv run python ../sandbox/perf.py --assets 1000 --paths)
```

## Project structure (what this phase touches)
```
agent/nimstead_agent.py               → Linux facts, opt-out, AGENT_VERSION 0.11.0
api/src/nimstead/access.py, db.py, migrations/ → validate and store the access read, AssetAccess (new)
api/src/nimstead/linconfig.py         → Linux settings checks (new)
api/src/nimstead/scan.py              → LinuxConfig findings open and close
api/src/nimstead/engine/paths.py      → Linux paths, way-in user, credentials
api/src/nimstead/engine/fleet.py      → key edges, choke points
api/src/nimstead/app.py               → inventory `access` body, /api/attack-paths key edges and choke points
api/tests/test_agent_linux_facts.py, test_linconfig.py, test_paths_linux.py, test_fleet_keys.py (new)
web/src/assets.tsx, findings.tsx, lib.ts, paths.test.tsx (new)
sandbox/paths_lab.py (new), sandbox/perf.py --paths
docs/engine/design-paths.md, docs/how-to, docs/reference, docs/explanation, README.md, CHANGELOG.md, STATUS.md, DECISIONS.md
```

## Code style
Follow the file you are in. The fleet builder is the model: facts that may be missing are `None`, never empty; every grade
has its reason in words; caps are named with the reason beside them:
```python
def _list(facts: dict, key: str, cap: int) -> set[str] | None:
    """A list fact as a set, or None when the agent couldn't read it (an old agent, a failed read): None is never "empty"."""
```
Agent parsers do no I/O, so they are tested on recorded text (`sshd -T` output, key headers, `authorized_keys` lines,
`/etc/group`), and budgets are constants with the reason in a trailing comment, as the runtime read's are.

## Testing strategy
- **Agent unit tests** (parsers on recorded text from real Debian, Alma and Alpine machines; the pass on a fake root):
  `sshd -T`, OpenSSH and PEM key headers (passphrase or not, every key type, a truncated or garbage header),
  `authorized_keys` options (quoted `from=` with commas, `command=` with escaped quotes, `restrict`, `cert-authority`
  skipped), `%h/%u` expansion, groups and NSS, `sudo -l` output, writable-path rules (owner, group, other, parent folder,
  sticky `/tmp`), budgets with stable words, partial as non-root. A test that a private key's bytes, a key comment, a
  forced command and a credential file's contents never reach the body. Hostile files: a symlink to root's key, a FIFO named
  `id_rsa`, another user's key in someone's `~/.ssh`, 10,000 trusted keys, a 100 MB `authorized_keys`, comments with a
  newline or right-to-left override.
- **API tests:** each `linconfig` check opens, closes and stays shut on unread facts. Host paths: way-in user, root listener
  skipping escalation, a setting counting only for the user it helps, credentials with and without root, a passphrase
  key graded *unverified*, Windows paths byte-identical. Key edges: every grading rule, `from=` matching
  (CIDR, wildcard, negation), Allow/Deny, root login values. Chains through mixed Windows and Linux edges. Choke points:
  counts against a brute-force recount on small graphs, ties, the 200-candidate cap.
- **Web unit tests:** drawer wording for each stage, edge wording, the choke points card, the settings findings.
- **e2e:** fleet view with key edges and choke points, a Linux machine's paths; axe clean at 1440 and 375, light and dark.
- **Real proof** (`sandbox/paths_lab.py`): see the success criteria.
- **Review:** an independent code review and a security audit. Every finding fixed with a test that fails first. A mutation
  check of `linconfig.py`, the key-edge grading and the choke-point count.

## Boundaries
- **Always:** treat everything a user controls in their home (key files, `authorized_keys`, `~/.ssh/config`, file names,
  comments) as hostile: no links, regular files only, owner checked, bytes capped. Send no private-key bytes, comments,
  credential contents or forced commands. Write tests before commits, each fix with a test that fails without it. Run
  `check_docs.py` and `export_api_docs.py --check` before pushing. Check the branch right before each commit (shared
  checkout).
- **Ask first:** approving the `release` environment gate (the owner's, unless they say "you do it", for that run);
  anything that costs money or touches a machine that isn't disposable; any SSH sign-in outside the disposable lab.
- **Never:** have the agent or server use a key, agent socket or credential it found (only the proof harness signs in, and
  only inside the lab); read a private key past its public header; probe or scan other machines (DECISIONS 27); lower or
  hide a finding because of a path; delete a test that fails.

## Success criteria
1. **Facts, exactly.** The lab is four machines: systemd containers on one private Podman bridge in a fresh disposable WSL
   distro, each with its own addresses, accounts, sshd and the real enrolled agent; Debian 13, AlmaLinux 9 and Alpine 3.21
   among them. On each, the agent's facts equal the oracles:
   - accounts and groups = `getent passwd` and `id -Gn`
   - sshd = `sshd -T`
   - held and trusted fingerprints = `ssh-keygen -lf` on each file
   - writable root-run files = a `find` of the same rule
   - peers = `ss -Htn state established`, private addresses only

   Every difference is listed with its reason in the run record; none is unexplained.
2. **Edges equal what ssh can do.** The lab plants these cases:
   - a plain trusted key
   - `from=` allowing A, and `from=` excluding A
   - `command=`, and `restrict`
   - `PermitRootLogin no`, and `PermitRootLogin prohibit-password`
   - `AllowUsers` without the account, and `DenyUsers` with it
   - `PubkeyAuthentication no`
   - a key with a passphrase
   - a key removed after a report
   - sshd stopped

   For each, the fleet view's edge and grade agree with a real `ssh -o BatchMode=yes -o IdentitiesOnly=yes -i <key>
   <account>@<B> true` run from A as the key's owner. Every edge graded *reasonable* or *confirmed* signs in. Every case with
   no edge fails. The passphrase key's edge is *unverified*: it fails without the passphrase and signs in with it. The
   forced-command edge is *unverified* with its reason.
3. **Privilege-aware paths.** On the entry machine (nginx on a vulnerable `libssl3`, listening on its bridge address, running
   as `www-data`, with `www-data` in the `docker` group), the network path is getting in, then becoming root through the
   docker group (the harness, as `www-data`, reads `/etc/shadow` through a container), then root's key with no passphrase.
   Its chain continues along the fleet's key edges. On a machine whose vulnerable listener runs as root, the path skips
   becoming root and says why. On a machine where the way-in user has no setting to use, the path uses a local-vector flaw
   with its own grade.
4. **Chains and choke points are real.** The chain from the entry machine lists exactly the machines the harness reaches by
   walking `ssh` hop by hop with the keys it finds (breadth first, from the entry machine). Then the top choke point is
   applied for real (the key removed where it's trusted). After the next reports, the reachable set shrinks by exactly the
   predicted count, and `ssh` along the removed edge fails.
5. **Settings findings.** Each of the six checks opens on a machine where it's planted and closes when it is fixed for real.
   None opens on stock Debian 13, AlmaLinux 9 and Alpine 3.21 with OpenSSH's default configuration.
6. **Nothing secret leaves; hostile files stay inert.** Searches of the server's stored inventories and the evidence pack
   find no private-key bytes, key comments, forced commands or credential-file contents. Every hostile file from the agent
   tests, planted in the lab, is refused or capped with its stable words. A budget hit marks the read partial, and nothing is
   concluded from what wasn't read.
7. **Cost.**
   - The facts pass takes under 2 s on a machine with 50 accounts and 500 trusted keys.
   - At 1,000 hosts (`perf.py --paths`, a synthetic key graph of 3 held and 20 trusted keys per host),
     `GET /api/attack-paths` with choke points has a median under 2 s.
   - The inventory median stays within 20% of 0.14.1's on the same machine.
8. **Nothing else moves.** Windows host and fleet paths are identical on the stored German Windows 10 inventory and in
   every existing test. API, agent (Linux, root and non-root), web unit, `tsc`, build and e2e are green; CI is green
   including PostgreSQL 17; the docs checks pass.

## Open questions (each with a recommendation; the owner decides)
1. *Is this the right next phase?* Recommended: yes. The other deferred items are smaller steps on the same ground: the
   containers' runtime and Windows loaded modules extend 0.14's read, and the host firewall refines one reason. This one
   turns Nimstead from a list of what's vulnerable into which machines fall together, and it's the one no on-premises VM
   tool answers.
2. *Should settings become findings, or only path steps?* Recommended: findings, as on Windows. A finding is the unit people
   fix, ticket and evidence. A step without one can't be tracked.
3. *Should a held key be a finding?* Recommended: no. Most machines hold keys legitimately; a key matters when it opens
   something, which only the fleet view knows. It shows in paths and choke points instead.
4. *Is the `sudo -l` call acceptable?* It runs `sudo` as root for up to 32 accounts. sudo logs each call, which some
   auditors will see. Recommended: yes, said in the docs and the collection line, and skipped when `"paths": false`.
5. *Does the lab need real VMs instead of containers?* Recommended: containers on a bridge give each machine its own address
   and namespaces, which is everything the facts and `ssh` see. VMs only add boot time. If systemd containers won't run
   under WSL, the fallback is three disposable WSL distros with sshd on distinct ports; their shared address would then make
   "seen connected" untestable, and that limit would be stated.
