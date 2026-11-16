# keepassxc-mcp

A cross-platform MCP server + CLI that gives an AI agent a **request → approve → merge**
path into a [KeePassXC](https://keepassxc.org/) vault — entries with notes and **file
attachments** — without ever exposing the vault's master password to the agent.

The agent stages changes into a sandbox database freely; a human approves in their own
terminal; only then does anything touch the real vault.

```
 agent (MCP, stdio)                    human (real terminal)
 ──────────────────                    ──────────────────────
 vault_stage_entry ──┐
 vault_list_staged   ├─► staging.kdbx ──► vault_promote ──► pending-request.json
                     │                            │
                     │                            ▼
                     │              keepassxc-mcp promote   ← the ONLY process
                     │              dry-run diff + y/N +    that ever sees the
                     │              master password (hidden) master password
                     │                            │
                     ▼                            ▼
               never merged ───────────────► keepassxc-cli merge ──► main.kdbx
                                                 verify ──► flush staging
```

All kdbx work is done by the official `keepassxc-cli` — this repo implements **no** kdbx
crypto.

## Why

No password manager ships an approval queue for agent-initiated writes. Bitwarden needs
the master password to unlock even for automation; KeePassXC's browser integration
protocol can't write attachments and is URL-scoped. This tool builds the queue itself: a
staging kdbx the agent owns, a pending-request file, and a terminal approver.

## Design

One executable, two modes — on purpose. An MCP stdio server owns its stdin/stdout for
JSON-RPC and can never prompt on a terminal, so approval lives in a separate mode:

| Command                  | Who runs it  | What it does                                                        |
| ------------------------ | ------------ | ------------------------------------------------------------------- |
| `keepassxc-mcp`          | the agent    | stdio MCP server: `vault_stage_entry`, `vault_list_staged`, `vault_promote` |
| `keepassxc-mcp promote`  | the human    | reviews the request + a **live** `merge --dry-run` diff, confirms, types the master password |
| `keepassxc-mcp status`   | either       | shows config (staging password redacted), staging contents, pending request |

`vault_promote` **never merges**. It snapshots staging (entries + per-attachment
sha256/size) into `pending-request.json`. The real merge diff against the main vault can
only be computed by a process that can unlock the main vault — that is the approver, not
the agent. So the diff is computed live, at approval time, and shown before anything is
written. This is strictly stronger than a pre-stored diff: it can't be faked by the agent
and it reflects any edits made to the main vault in the meantime.

## Setup

Prerequisites: **.NET 10** (to build) and **keepassxc-cli** (KeePassXC ≥ 2.7.x — on
Ubuntu the `keepassxc` package ships `/usr/bin/keepassxc-cli`).

```sh
git clone https://github.com/michaeltg17/keepassxc-mcp
cd keepassxc-mcp
dotnet build -c Release
# binary: src/KeePassxcMcp/bin/Release/net10.0/keepassxc-mcp(.exe)
```

### Config

`%APPDATA%\keepassxc-mcp\config.json` on Windows, `~/.config/keepassxc-mcp/config.json`
on Linux/macOS (or set `KEEPASSXC_MCP_CONFIG` to the file or its directory):

```json
{
  "mainVaultPath": "/vaults/passwords.kdbx",
  "mainKeyfilePath": null,
  "stagingVaultPath": "/vaults/staging.kdbx",
  "stagingPassword": "any-string-kdbx-requires-a-password",
  "keepassxcCliPath": "keepassxc-cli"
}
```

- `mainKeyfilePath` is optional: `null`/absent → password-only main vault; set → both
  keyfile and password are supplied in a single keepassxc-cli call.
- `stagingPassword` is format-mandatory (a kdbx cannot have no credentials). It is **not
  a security boundary** — see [Security model](#the-honest-security-model).
- The main vault password is *not a config field*. It never exists in config, on disk,
  or anywhere the agent process can read it.

⚠ **Keep `config.json` and the kdbx files out of any VCS-tracked or file-sync folder.**
Both default locations above are outside your home *documents*; pick paths accordingly.

The staging database is created automatically on first use; it is flushed (deleted and
re-created) after every successful promote.

Check everything: `keepassxc-mcp status`.

### Registering with MCP clients

MCP clients that support per-tool approval should gate these tools — chat consent plus
the terminal password prompt are two independent gates.

**OpenCode** (`opencode.jsonc`; tools are named `<server>_<tool>`, and Code Mode groups
them under the normalized server name):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "keepassxc": {
        "type": "local",
        "command": ["/path/to/keepassxc-mcp"],
        "environment": { "KEEPASSXC_MCP_CONFIG": "/path/to/config.json" }
      }
    }
  }
}
```

Use OpenCode's permissions to gate the tools (per `action` patterns matching
`keepassxc_*`) if you want the client — not just the terminal — to confirm before the
agent can stage or request promotion.

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "keepassxc": {
      "command": "/path/to/keepassxc-mcp",
      "env": { "KEEPASSXC_MCP_CONFIG": "/path/to/config.json" }
    }
  }
}
```

Claude Desktop shows a confirmation for every tool call; keep it on.

## Promoting staged changes

```
$ keepassxc-mcp promote
main vault : /vaults/passwords.kdbx (password + keyfile)
staging    : /vaults/staging.kdbx
Requested 2026-11-16T03:00:00Z by vault_promote:
  entry      Inbox/Legal/Contract
  attachment Inbox/Legal/Contract :: contract.pdf (3072 B, sha256 9f2a…)

Merge these 1 entries into /vaults/passwords.kdbx? [y/N] y
Master password for the main vault (input hidden): *****

merge --dry-run (computed now against the current main vault):
        Added: '/Passwords/Inbox' (…)
        Added: '/Passwords/Inbox'/'Contract' [{…}]
Verifying promoted entries in the main vault...
OK: 1 entries promoted to the main vault; staging flushed; pending request cleared.
```

- Ctrl+C or `n` at any prompt → no-op; staging, vault and request untouched.
- If the main kdbx's mtime changed since the last promote (edited by the GUI or a sync
  tool outside this flow), the approver sees a warning first.
- Exit codes: `0` merged, `1` error/no request, `2` denied (also `130` on Ctrl+C).

## The honest security model

Full details in [SECURITY.md](SECURITY.md). The short version:

- The MCP server process **never sees, requests, or can receive** the main vault
  password. Only interactive `promote` mode ever touches it — masked console read →
  straight into keepassxc-cli's stdin, never persisted, never in exceptions or logs
  (there is a redaction filter for password-shaped values as a belt-and-braces measure).
- Staging is **not** a confidentiality layer against the local user or the agent. Its
  password exists in config because kdbx format requires one and because the file should
  stay encrypted if it gets copied somewhere. **The only real gate is the main vault
  password**, which never leaves the terminal.
- Your main vault **must have a master password** (keyfile optional on top). The agent
  runs as the same OS user; a keyfile-only vault would be agent-readable. Only the
  staging secret may be agent-reachable — by design.
- Tool vault paths come from config only. Tools cannot target arbitrary databases.

## keepassxc-cli facts (verified against KeePassXC 2.7.x)

- Unlock/creation passwords are fed via **piped stdin**, never argv. `db-create -p` and
  `merge` prompt twice (password, repeat / main, staging) — stdin lines match that order.
- A **keyfile+password** DB needs both in one invocation (`-k <path>` + stdin password);
  either alone fails. Keyfiles are config-supplied paths, never typed.
- `merge --dry-run` prints the diff to stdout (`Added: …` on 2.7.10+; older builds say
  `Creating missing …` — the tests accept both); `-q` silences it — so merge is called
  *without* `-q` and the prompt echo is filtered.
- `attachment-import -f` overwrites; `show --show-attachments` lists
  `name (size)`; `attachment-export` round-trips byte-identical (verified by sha256).
- `mkdir` walks one level at a time (no `-p`); `add` on an existing entry fails, so
  re-staging uses `edit --notes` + `attachment-import -f`.
- A kdbx cannot have empty password **and** empty keyfile — hence `stagingPassword`.
- `ls -R -f` prints groups with a trailing `/` and empty groups as `[empty]`.

## Tests

Integration only — they drive the real `keepassxc-cli` against throwaway
`db-create`d databases in a temp dir, and launch the built exe as a child process for
the CLI and MCP end-to-end paths (the MCP e2e speaks stdio JSON-RPC through the
official SDK client). The suite **skips itself** if keepassxc-cli is unavailable
(set `KEEPASSXC_CLI=/path/to/keepassxc-cli` to point it explicitly).

```sh
dotnet test
```

GitHub Actions runs the matrix on Windows, Ubuntu and macOS with KeePassXC installed
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Out of scope (v1)

Secret backup/rotation tooling (general hygiene, not this tool's purpose), remote/TCP or
multi-machine deployment, KeePassXC's browser-integration protocol, reading main-vault
secrets from the agent, selective per-entry promotion, keyfile-based auth for the
staging DB.

## License

No license is attached (see repository settings). Add one before reusing the code.
