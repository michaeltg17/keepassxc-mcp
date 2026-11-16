# SECURITY.md — threat model

keepassxc-mcp's design goal is one sentence: **the agent may write to a sandbox; only a
human holding the main vault password may write to the vault.** Everything below follows
from that.

## Actors

| Actor                        | Assumed capability                                             |
| ---------------------------- | -------------------------------------------------------------- |
| The AI agent (MCP client)    | Untrusted by design. Runs `keepassxc-mcp` (mcp mode) as your OS user. May stage, list, request. |
| The human                    | Runs `keepassxc-mcp promote` in a real terminal. Knows the main vault password. |
| keepassxc-cli                | Trusted dependency (official KeePassXC binary) — all kdbx crypto and writes. |
| Local malware / other apps   | Same-OS-user code can read anything the user can read (config, staging file, keylogger the password you type). Out of scope; nothing this tool does makes that worse. |

## Security invariants (enforced in code)

1. **The main vault password never exists in config, on disk, or in any process the
   agent can reach.** It is read interactively (masked `Console.ReadKey` loop) in
   `promote` mode only, and goes straight into keepassxc-cli's stdin. It is never
   returned from any function, never logged, and `finally`-cleared at the end of the
   approval flow.
2. **The MCP server process cannot merge.** It has no tool that unlocks the main vault;
   the merge diff is computed by the approver process at approval time (the agent cannot
   pre-seed or fake a diff).
3. **Config-only vault paths.** `mainVaultPath` / `stagingVaultPath` are read at startup;
   no tool accepts a database path argument. Agents cannot point the tools at arbitrary
   kdbx files.
4. **Passwords travel via stdin only** — never argv (argv is visible to process lists).
   Process launch uses argv arrays, never shell strings, so no quoting/injection surface.
5. **Staging is flushed after every successful merge** (delete + re-create with the
   config password) — no re-merging stale entries, no merge-history bloat in the vault.
6. **Redaction filter**: any exception/log text in agent-facing paths passes through
   `Redact` for config-known secrets (currently `stagingPassword`). The main password is
   never in scope of the redactor because it is never in scope of the code.
7. **Post-merge verification**: every promoted entry and attachment is re-read from the
   main vault and its sha256/size compared against the request. Mismatch → staging is
   kept, the request is kept, and the human is told.
8. **Stale-mtime warning**: if the main kdbx changed since the last promote (edited by
   the GUI or a sync tool outside this flow), the approver is warned before anything is
   merged.

## What agents CAN do

- Create/edit entries (title, notes) and import file attachments **into `staging.kdbx` only**.
- List everything staged, with per-attachment name/size/sha256 from the staging database.
- Write a `pending-request.json` describing staged intent.
- Read config-adjacent non-secret files (`pending-request.json`, `state.json`) — they are
  agent-visible by design: the agent wrote them.

## What agents CANNOT do

- Read or write the main vault: no tool unlocks it, and the password is unreachable.
- Merge, promote, or delete anything in the main vault. Only the terminal approver can.
- Target vaults other than the configured ones.
- Persist anything to the vault without an explicit `y` + master password from a human
  sitting at a terminal.

## What this does NOT protect against (read this)

- **Staging is not a confidentiality boundary.** `stagingPassword` lives in config and
  `staging.kdbx` is a file the same-OS-user (and therefore the agent) can read. The
  password exists because kdbx format-mandates one and because the file should stay
  encrypted if copied. Do not stage secrets you wouldn't want local user-level code to
  read; attachments are chosen by the agent from local paths, so treat staged content as
  already-public at that trust level.
- **Your main vault must have a master password** (keyfile optional on top). A
  keyfile-only vault is agent-readable (same OS user can read the keyfile), so the
  approval gate would be the only line of defense. Password + optional keyfile keeps the
  secret human-only.
- A compromised *terminal* (keylogger) or a human who approves without reading the
  dry-run diff defeats the flow — that is the human gate's trust, by definition.
- keepassxc-cli bugs, KeePassXC format weaknesses, and OS-level credential theft are out
  of scope.
- Ctrl+C after the final confirm can interrupt between merge and staging-flush; the
  worst case is a re-runnable state (staging kept, request kept, duplicate-safe merge),
  never a vault write the human didn't confirm.

## If you think you found a vulnerability

Open a [GitHub security advisory](https://github.com/michaeltg17/keepassxc-mcp/security/advisories/new)
rather than a public issue.
