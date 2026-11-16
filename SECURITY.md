# SECURITY.md — threat model

keepassxc-mcp's design goal is one sentence: **the agent may write to a sandbox; only a
human holding the main vault password may write to the vault.** Everything below follows
from that.

## Actors

| Actor                        | Assumed capability                                             |
| ---------------------------- | -------------------------------------------------------------- |
| The AI agent (MCP client)    | Untrusted by design. Runs `keepassxc-mcp` (mcp mode) as your OS user. May stage, list, request. |
| The human                    | Runs `keepassxc-mcp promote` in a real terminal — possibly a window the agent opened *for them* (`vault_open_approver`) after they agreed in chat; they still type everything in it. Knows the main vault password. |
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

## What agents CAN do

- Create/edit entries (title, notes) and import file attachments **into `staging.kdbx` only**.
- List everything staged, with per-attachment name/size/sha256 from the staging database.
- Write a `pending-request.json` describing staged intent.
- Open the approver's terminal window (`vault_open_approver`, if enabled in config) — it
  can open that window but can never complete it: `y` and the password are keyboard input
  to another process's console.
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
