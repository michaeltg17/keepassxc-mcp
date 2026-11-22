# SPEC.md — secret flows and tool contract

Status: **implemented in 0.3.0** (F5–F11 deferred to 0.4.x). This file is the complete
inventory of flows and tools the program handles. The threat model (who may touch what,
and why) lives in [SECURITY.md](SECURITY.md); the invariants named INV-x below are
amendments to that file's list. The reader session (main-vault reads) is reflected in
SECURITY.md as part of the implementation, not silently.

The design copies 1Password's agent story — references in, values never out, substitution
at process/file boundaries — adapted to KeePassXC via keepassxc-cli, and keeping this
repo's differentiator: the staging → human-promote gate for all vault writes.

## P. Principles

- **P1 — Security before automation.** A flow that cannot run without a secret entering
  model context may still proceed — but the exposure is then *recorded* (E3,
  `seen-by-model`) so the task's final `vault_audit` surfaces every flagged entry for
  rotation. That record-and-surface guarantee is the requirement; a tool additionally
  *stopping and warning* where a value-free alternative exists (e.g. F1 generate instead
  of pasting a value) is its preference, never a silent degradation. The user keeps the
  last word on every listed entry.
- **P2 — Labels only.** Tool inputs and outputs are entry paths (`Services/webhook`),
  fingerprints (first hash chars), provenance tags and yes/no answers — never secret
  values, except where a flow explicitly allows it (F2.2, F3, F5).
- **P3 — Values move through channels the model composes but never reads:** the MCP
  writing a file, spawning a child with injected env, or a shell pipe into a CLI ingest
  command (`gh api … | keepassxc-mcp stage --label x`).
- **P4 — Exposure is recorded, not denied.** A secret that passed through model context
  is tagged `seen-by-model` (see E3); the response is rotation advice, never amnesia.

## INV. Invariants (amendments to SECURITY.md)

- **INV-A** A vault secret value enters model context only via a flow that marks it as
  such (F2.2, F3, F5). All other flows are label-only by construction.
- **INV-B** The master password remains human-typed-only (SECURITY.md inv. 1 unchanged):
  typed once per reader session (E1), in a terminal the MCP server can never read.
- **INV-C** All main-vault **writes** still go staging → human promote (SECURITY.md
  unchanged). New in 0.3.0: the reader process performs main-vault **reads**; it still
  never merges.
- **INV-D** The provenance sidecar (`provenance.json`, app-data dir) contains **no secret
  values** — only paths/UUIDs, origin tags, timestamps and hashes. It is disposable by
  design (E3): nothing else depends on it.
- **INV-E** Output of any child process spawned by a value-injecting flow is masked
  against the values it injected before the harness sees it (extends `Redact`).

## A. Flows INTO the vault

- **F1 Generate new secret** — `vault_generate(label, profile)`. Value produced by
  `keepassxc-cli generate` (or `diceware`), stored straight into staging, strength
  checkable with `analyze`/`estimate`. Returns label + fingerprint only.
  Model never sees the value. Provenance: `generated`. ✅ preferred birth path.
- **F2 Capture service-generated secret** — a service (GitHub, Stripe…) mints a key shown
  once. In priority order:
  1. **Piped ingest (best):** `keepassxc-mcp stage --label X` in a shell pipeline (the
     value is read from stdin, exactly one line). Value flows service → child stdout →
     CLI stdin → staging; the model sees only the exit code. Provenance: `piped`.
  2. **Direct ingest:** `vault_stage_value(label, value)` when the value is already in
     the agent's context. Provenance: `seen-by-model`.
- **F3 Store existing secret** — same as F2.2 for anything the agent already holds.
  Provenance: `seen-by-model`.

## B. Flows OUT of the vault

- **F4 Look up / describe (default)** — `vault_search(term)`, `vault_get(path)` return
  paths, titles, usernames, URLs, groups, fingerprint, provenance — **never** the
  password/OTP fields.
- **F5 Reveal value (escape hatch)** — `vault_get(path, reveal: "password")`, logged to
  the reader window; any gate or confirmation around it is decided when it is built —
  no config keys are added before they are needed. Any revealed value becomes
  `seen-by-model`. *(Deferred past 0.3.0.)*
- **F6 Copy to clipboard** — `vault_copy(path, ttl)` via `keepassxc-cli clip` from the
  reader process; auto-clear after TTL. Niche: GUI/browser logins and human handoff, not
  coding flows (the agent can always read the clipboard). *(Deferred.)*

## C. Flows that USE a value without the model seeing it

- **F7 Inject-exec** (`op run` analog) — `vault_exec(cmd, env:{VAR: entryPath})`: spawn
  the child with real values injected; output masked per INV-E. *(Deferred.)*
- **F8 File substitution** (1Password Environments/.env analog) — `vault_apply_file(target,
  bindings)`: the MCP writes real values into `.env`/config files with a comment naming
  the entry label. Diff-first, never silently overwriting a hand-edited file. *(Deferred.)*
- **F9 Verify** — `vault_check_file(target)`, `vault_fingerprint(path)`: hash comparisons,
  yes/no answers, never values. *(Deferred.)*

## D. Lifecycle flows

- **F10 Rotate** — `vault_rotate(path)`: in-place regeneration of the **staged** entry via
  `keepassxc-cli edit -g …` (staging's key is config-derived, so no main-vault password is
  involved; the rotated copy goes through the human promote). Provenance updated; old
  fingerprint recorded as retired. Drives the E3 audit list to zero.
- **F11 Delete / revoke** — `vault_mark_delete(path)` stages a tombstone (path + UUID)
  shown in the promote diff; after human confirmation the Promoter runs
  `keepassxc-cli rm` on main **directly** — merge is not relied on for deletion
  (verified: `rm` recycles; merge resolves recycles inconsistently). Recycle-bin
  semantics keep deletes restorable. *(Deferred.)*
- **F12 Promote** — existing staging → main gate, unchanged.

## E. Enablers (mechanisms, not flows)

- **E1 Reader session** — `vault_reader_open` pops a terminal window (same identity-banner
  pattern as the approver): the human presses Enter, verifies the binary, and types the
  master password once (3 attempts, masked). A separate **reader process** holds it in
  memory and services main-vault reads (F4; later F5–F11) over a file protocol — never a
  pipe this server owns, so the password has no channel to travel on. Agent-openable
  unconditionally: no config gate (there are no existing users to protect from the new
  capability). The session ends on `vault_reader_close`, after a fixed idle timeout
  (10 min), or when the server that started it exits (orphan guard). The human can always
  run `keepassxc-mcp reader` themselves instead.
- **E2 Masking pipeline** — INV-E machinery: the reader/exec hosts remember injected values
  and rewrite them in captured output as `<secret redacted>`.
- **E3 Provenance sidecar** — `provenance.json` beside `state.json`:
  `{path, uuid, origin: generated|piped|seen-by-model, created, fingerprint}`.
  `vault_audit` answers: *which of my vault secrets have ever been visible to a model?*

  **Task-bound lifecycle (P1 in practice):** exposure tracking is scoped to one agent
  task. The tool descriptions make the end-of-task duty part of the contract — an agent
  that used vault tools finishes by calling `vault_audit` and, if the list is non-empty,
  warning the user which entries to rotate. The user then chooses: rotate (F10), dismiss
  specific entries, or discard the whole file. Discarding is a first-class, always-valid
  option: the sidecar is best-effort leak tracking, and its worst case is an empty
  audit list — the user is asked to rotate manually, which is strictly safer than no
  tracking at all. We automate what we can; the human keeps the last word.

## Tool contract (0.3.0 additions)

| Flow | MCP tool | CLI verb |
|---|---|---|
| F1 | `vault_generate` | `keepassxc-mcp generate` |
| F2/F3 | `vault_stage_value` | `keepassxc-mcp stage --label …` (value on stdin) |
| F4 | `vault_search`, `vault_get` | — (needs a reader session: `keepassxc-mcp reader`) |
| F10 | `vault_rotate` | — (staged change → promote) |
| E3 | `vault_audit` (+ dismiss verbs) | `keepassxc-mcp audit` |
| E1 | `vault_reader_open` / `vault_reader_close` | `keepassxc-mcp reader` |

Config changes in 0.3.0: **none.** No new keys, no compat flags — there are no existing
users to protect, so config stays minimal. The reader window is agent-openable
unconditionally, the idle timeout is fixed (10 min); any gate a future flow needs (F5)
arrives with that flow, not before it.

## Verified CLI capabilities (2026-11-22, real keepassxc-cli)

- Present and used by this spec: `generate`, `diceware`, `analyze`, `estimate`,
  `edit -g` (in-place regeneration), `clip`, `search`, `show`, `ls`, `rm`, `merge`.
- `edit` supports only title/username/url/notes/password — **no kdbx custom attributes**,
  hence provenance lives in the sidecar (INV-D).
- `rm` = recycle-bin move, and merge propagates recycle moves dependably enough to never
  rely on it (duplicate Recycle Bin groups observed) → F11 design above.
- Random generation stays in the official binary — this repo still holds no crypto or
  password-generation code of its own.

## 1Password → this spec

| 1Password | here |
|---|---|
| `op://vault/item/field` references | entry paths as labels |
| MCP never returns secret values | F4 default; F5 gated + logged (future) |
| Environments / mounted `.env` | F8 |
| `op run` injection | F7 |
| desktop-app auth prompt instead of password-in-protocol | E1 reader window |
| output masking (`<concealed …>`) | E2 / `Redact` extension |
| agent can add secrets | F1/F2/F3 → staging |

Not copied: 1Password has no pre-write review gate. The staging → promote human gate
stays and is this project's core.

## Release plan

- **0.3.0** — implemented: E1 reader session; F4 lookups (label-only); F1 generate;
  F2/F3 ingest (piped stdin + `vault_stage_value`); E3 provenance + `vault_audit` + the
  end-of-task duty; F10 rotate; no new config keys. Docs: SECURITY.md invariants amended,
  reader/audit drills added to MANUAL_TEST.md (wiki update published separately).
- **0.4.x** — F7 exec, F8 file substitution, F9 verify, F6 clipboard, F5 reveal,
  F11 delete.

## Open questions

1. ~~UUID stability across staging→promote merge~~ **Resolved:** merge preserves entry
   UUIDs (verified by hand and by the `MergeUuidStabilityTests` e2e test) — the sidecar's
   UUID corroboration is sound.
2. Reader vs. Promoter process sharing one password window vs. two prompts when both are
   pending in one session (prefer one shared reader the Promoter also uses? tests the
   "who types" invariant — decide at design review).
3. Version/release mechanics: 0.3.0 is a feature minor; keep one PR per flow-group to
   keep the `## Changes` release notes legible.
