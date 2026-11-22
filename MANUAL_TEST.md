# Manual verification against a real vault

The automated suite (see `AGENTS.md`) fakes nothing, but it runs against throwaway test
vaults — never the user's real one, and never a real human typing a real password into a
real terminal window. This drill covers exactly that residue. Run it:

- after each release (PR merged, release published) and after updating the installed binary;
- whenever `promote`, the merge/verification flow, or the approver-window launcher changes;
- whenever the `reader` mode, its file protocol, the provenance sidecar, or the
  generate/stage/rotate flows change (Part B below).

Rules that hold throughout: the main vault password is typed only by the human, only into
the window — never shown here, never in any tool the agent uses. The window banner is the
proof of WHICH binary you are testing.

## Setup

1. Installed binary: `%LOCALAPPDATA%\Programs\keepassxc-mcp\keepassxc-mcp.exe`.
   Confirm it is the release under test: `keepassxc-mcp version`, and `status` shows
   `app version` + a reachable `keepassxc-cli`.
2. Agent side: the MCP server connected to that same binary (check with
   `vault_list_staged` — it must answer).
3. Pick a marker name for the test entry, e.g. `ManualTest-<version>` — its notes must say
   it is a test entry, safe to delete. Pick a small file with NO secret in it as the
   attachment, and precompute its hash: `Get-FileHash -Algorithm SHA256 <file>`.

## Part A — the promote flow drill

1. `vault_stage_entry` the marker entry + attachment → the receipt's sha256/size must
   match the precomputed hash.
2. `vault_list_staged` → entry path and attachment name/size/sha256 shown.
3. `vault_promote` → "Promotion request recorded"; nothing merged (main vault untouched).
4. Ask the human for consent, then `vault_open_approver` → a real window opens.
   **Verify the banner**: `this executable : <installed path> (v<version>)` and its sha256
   match `Get-FileHash` of the installed exe. This step is the whole point of the drill —
   it proves the human is about to type the password into the binary you released.
5. In the window, walk the flow deliberately:
   Enter → manifest matches what was staged → `y` →
   **a wrong password on purpose** → must print `Attempt failed: …` and re-prompt
   `attempt 2/3` with NOTHING written →
   **empty Enter** → must print `Empty password — not tried…` and re-prompt `attempt 3/3` →
   the real password → live `merge --dry-run` diff → `y` → merge + `Verifying promoted
   entries…` → `OK: 1 entries promoted … staging flushed; pending request cleared.`
   Exit code of the window process: 0.

## Success checklist

- [ ] banner path/version/sha256 = the installed release binary
- [ ] wrong + empty password consumed attempts, wrote nothing, re-prompted correctly
- [ ] promote ended `OK`, its own post-merge verification passed (that IS the byte-check —
      it re-exports and compares hashes inside the flow)
- [ ] `keepassxc-mcp status`: `staged entries: 0`, `pending request : none`,
      `last promote` updated to now
- [ ] the human sees the marker entry in the vault GUI (optional but convincing)
- [ ] no vault paths, secrets, or machine-specific values were written to the repo

## Failure probes (rotate one per release — they exercise the exit contract)

| probe | expected |
|---|---|
| 3 wrong passwords at the prompt | `3 password attempts failed…`, exit 1, staging+request kept |
| `n` at the confirm prompt | `Denied.`, exit 2, nothing changed |
| Ctrl+C in the window | `Aborted (Ctrl+C).`, exit 130, nothing changed |
| delete the pending request, rerun promote | refuses with "No pending promotion request", exit 1 |

## Part B — the secret-flow drill (reader, generate, ingest, audit)

Run this instead of/in addition to Part A when the reader or secret flows changed.
The whole part is about one fact: **no secret value ever appears in the agent's
conversation or in any tool output** — you verify that with your own eyes in the vault GUI.

1. `vault_generate` a marker secret, e.g. `ManualTest-<version>-gen` (length 20).
   Receipt shows path/UUID/fingerprint/length — and no value. `keepassxc-mcp audit`
   (or `vault_audit`) shows it as `generated`, exposed: 0.
2. Piped ingest: `'piped-test-value' | keepassxc-mcp stage --label ManualTest-<version>-piped`.
   The value must never appear in the command's output. Audit shows it as `piped`.
3. `vault_stage_value` with an obvious throwaway value → tagged `seen-by-model`;
   `vault_audit` now flags it `<-- ROTATE or dismiss`. Then `vault_rotate` that entry →
   audit is clean again (old fingerprint retired). Open the vault GUI: the entries exist
   with real passwords you never saw.
4. Ask the human for consent, then `vault_reader_open` → a reader window opens.
   **Verify the banner** (path/version/sha256 = the installed binary, same as Part A step 4).
   In the window: Enter → **a wrong password on purpose** → `Attempt failed`, re-prompt
   `attempt 2/3` → the real password → `Reader session open`.
5. `vault_search <term>` → entry PATHS only. `vault_get` on the marker entry → title/
   username/URL/UUID/notes and `Provenance:` — the password line is `PROTECTED`, and the
   real value appears nowhere. `status` shows `reader session : OPEN (pid …)`.
6. `vault_reader_close` → `status` shows `reader session : none`. Also test the human
   path once: run `keepassxc-mcp reader` yourself in a real terminal, close with Ctrl+C.
7. End the task the way the tool contract demands: `vault_audit`, and confirm you would
   surface anything flagged. Then `keepassxc-mcp status`: provenance summary consistent
   with the audit (tracked = 3, exposed = 0 after the rotate).

Part B checklist:

- [ ] reader banner path/version/sha256 = the installed release binary
- [ ] wrong password in the reader window consumed an attempt, opened nothing
- [ ] no secret VALUE appeared in any tool result, window output, or `status`
- [ ] `vault_generate` + rotate kept provenance straight (generated/piped/seen-by-model,
      rotate clears exposure)
- [ ] reader closes by request, by Ctrl+C, and disappears from `status`
- [ ] clean up: remove the three `ManualTest-…-gen/piped/…` entries from staging before
      promoting anything for real (or promote one on purpose and delete it in the GUI)

## Leave-behinds

The marker entry stays in the real vault on purpose (its notes say it is safe to delete —
the human removes it whenever). Delete any plaintext copies you made of the attachment file.
Never commit vault paths or anything secret.
