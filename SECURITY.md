# SECURITY.md — threat model

keepassxc-mcp's design goal is one sentence: **the agent may write to a sandbox; only a
human holding the main vault password may write to the vault.** Everything below follows
from that.

## Actors

| Actor                        | Assumed capability                                             |
| ---------------------------- | -------------------------------------------------------------- |
| The AI agent (MCP client)    | Untrusted by design. Runs `keepassxc-mcp` (mcp mode) as your OS user. May stage, list, request. |
| The human                    | Runs `keepassxc-mcp promote` in a real terminal — possibly a window the agent opened *for them* (`vault_open_approver`) after they agreed in chat; they still type everything in it. Knows the main vault password. |
| The reader process           | `keepassxc-mcp reader`: separate process, own terminal window, same identity-banner rule as the approver. Holds the master password in memory only; performs main-vault **reads** (metadata only) over a file protocol. Never merges, never writes. |
| keepassxc-cli                | Trusted dependency (official KeePassXC binary) — all kdbx crypto and writes. |
| Local malware / other apps   | Same-OS-user code can read anything the user can read (config, staging file, keylogger the password you type). Out of scope; nothing this tool does makes that worse. |

## Security invariants (enforced in code)

1. **The main vault password never exists in config, on disk, or in any process the
   agent can reach.** It is read interactively (masked `Console.ReadKey` loop) in
   `promote` mode only, and goes straight into keepassxc-cli's stdin. It is never
   returned from any function, never logged, and `finally`-cleared at the end of the
   approval flow. The invariant is about who **types**, not who launches the window
   (see "The approver window" below).
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
9. **The reader session keeps the "who types" rule.** `keepassxc-mcp reader` (opened by
   a human, or by the agent via `vault_reader_open` after asking in chat) prompts for the
   master password once, masked, in its own terminal window with the same identity banner
   as the approver. The password lives only in that process's memory, is never written to
   a pipe this server owns (reader commands/results travel as files), is redacted from
   every reader result as belt-and-braces, and is zeroed when the session closes
   (explicit close, idle timeout, or the orphan guard when its server exits).
10. **Main-vault reads are label-only.** `vault_search` returns entry paths; `vault_get`
    returns title/username/URL/UUID/notes/attachment names. The password field is never
    printable through this path: keepassxc-cli `show` masks it as `PROTECTED`, and no
    read tool asks for it — see "Field visibility" below for the full contract. A vault
    secret value enters model context only through a flow
    that marks it as such (`vault_stage_value` tags `seen-by-model`; F5-style reveal is
    not built yet). Generation (`vault_generate`, `keepassxc-mcp generate`) and piped
    ingest (`keepassxc-mcp stage`) put values into staging without ever printing them.
11. **Exposure tracking holds no secrets.** `provenance.json` records paths/UUIDs, origin
    tags (`generated`/`piped`/`seen-by-model`), timestamps and sha256 fingerprints — never
    values (the fingerprint is a rotation-tracking hint, not a MAC). The file is
    disposable by design: `keepassxc-mcp audit`/`vault_audit` list what was exposed, and
    if the file is gone the fallback is simply "rotate manually". Tool descriptions make
    the end-of-task `vault_audit` call part of the contract.

## The approver window: who launches vs who types

By default (`"allowAgentApproverWindow": true`, omitting the key = true) the agent may
open the approver for the human via the `vault_open_approver` MCP tool (or the
`keepassxc-mcp promote-window` CLI verb). What that does — and does not — do:

- It launches *this same executable* in `promote` mode in a **new visible OS terminal
  window** (cmd /k on Windows, Terminal.app via osascript on macOS, the first available
  terminal emulator on Linux; headless systems get an honest "open a terminal yourself"
  fallback). The launcher pipes **no** stdin, passes **no** secrets, and receives no
  result back — a fresh, independent process tree with its own console input buffer.
- The window prints an **identity banner** (own path + own sha256) and then waits for the
  human to press **Enter in that window** before showing anything or prompting.
- The tool refuses without a recorded pending request, refuses outright when
  `allowAgentApproverWindow` is `false`, and its description obligates the agent to have
  asked the user in chat first ("task is done — want me to open the approval prompt?").

**What it weakens, honestly:** the human no longer exclusively initiates *when* a
credential prompt can appear. A steered agent (prompt injection from content it read)
could pop approval windows unprompted; the human must still type `y` and the password,
and should verify the identity banner path matches the installed binary before typing.
Set `"allowAgentApproverWindow": false` to restore strict human-launch mode — then the
tool refuses and only manual `keepassxc-mcp promote` exists.

## Field visibility: what counts as "the secret"

The kdbx **file** is encrypted as a whole — at rest, every field of every entry is
protected by the master key. The interesting question is what is visible *once a
process holding the vault can talk to the agent*, and there our contract is deliberate
and simple:

> **The entry's password field is the secret.** Everything else about an entry is a
> label, visible to the agent by design. If you want a value kept from the agent,
> put it in the password field — anything you write into notes is agent-visible.

| What                                   | At rest (kdbx) | To the agent, through our tools |
| -------------------------------------- | -------------- | ------------------------------- |
| Main vault master password             | required to open | **never** — typed at a keyboard into another process (invariant 1) |
| Entry **password field**               | encrypted | **never** — `show` reports it as `PROTECTED`; no tool requests it; flows that move values (generate/stage/rotate) print only length + fingerprint |
| Attachment **contents**                | encrypted | **never fetched** — tools handle only name, size and sha256 (integrity receipts). Note: a sha256 of a tiny, guessable file is a commitment; contents stay unseen, but don't attach 20-byte "secret" text files as if they were passwords |
| Entry paths / groups / titles          | encrypted | visible — these are the labels the design is built to expose |
| Username, URL, notes                   | encrypted | visible — treat any text you stage or any notes you write as agent-readable |
| UUIDs, provenance records, pending-request, state | plaintext metadata files | visible by design; they hold paths/hashes/timestamps, never values (invariant 11) |

Staging entries follow the same rule: `vault_list_staged` prints their notes and
attachment metadata, never the password field. In short: **values in, receipts out —
the only value that stays invisible is the one in the password field.**

## What agents CAN do

- Create/edit entries (title, notes) and import file attachments **into `staging.kdbx` only**.
- List everything staged, with per-attachment name/size/sha256 from the staging database.
- Write a `pending-request.json` describing staged intent.
- Open the approver's terminal window (`vault_open_approver`, if enabled in config) or the
  reader's terminal window (`vault_reader_open`) — in both cases it can open the window but
  can never complete it: `y` and the password are keyboard input to another process's console.
- Put secrets into staging *without printing them*: `vault_generate` (value generated inside
  keepassxc-cli), the piped CLI verb `keepassxc-mcp stage`, or `vault_stage_value` (value
  already in model context → honestly tagged `seen-by-model`). Rotate a staged secret with
  `vault_rotate` (regenerated inside keepassxc-cli). Receipts carry paths, UUIDs,
  fingerprints and lengths — never values.
- Read main-vault entry **paths and metadata only** (`vault_search`, `vault_get`), and only
  while a human-typed reader session is open. Secret values never travel this path.
- Read/write `provenance.json` (and `pending-request.json`, `state.json`) — non-secret
  metadata files, agent-visible by design.

## What agents CANNOT do

- **Write** to the main vault: no tool unlocks it for writing, and the merge needs the
  terminal approver. It can see entry paths and metadata — never secret values — and only
  through a reader session a human typed into.
- Ever read or hear the master password: both the approver's and the reader's prompts are
  keyboard input to other processes' consoles; the reader's file protocol carries commands
  and metadata results, never the password.
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
- **Exposure tracking is best-effort.** `provenance.json` only records values that moved
  through this tool's flows. If a secret was pasted into a chat outside keepassxc-mcp, or
  typed on a keyboard near a keylogger, no tool here knows. `vault_audit` is a hygiene
  aid, not a proof; rotation of anything uncertain is the safe default. Fingerprints are
  sha256 of values — fine for tracking rotation, not secret-proof for weak values.
- **The reader window weakens timing, like the approver window:** a steered agent can ask
  to pop a password prompt (`vault_reader_open`); the human still types, should verify the
  identity banner, and should close the session when done (`vault_reader_close`) instead
  of letting it idle out. Reads it enables are metadata-only regardless.
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
