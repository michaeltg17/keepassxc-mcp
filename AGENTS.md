# Agent notes

Read before making changes in this repo.

## Flow

- Work on `dev`, open PRs to `main` **from `dev` only** (CI runs on dev pushes and
  gates the PR; PRs from other branches have no checks and block safely).
- Merging a PR that bumps `<Version>` in `src/KeePassXCMcp/KeePassXCMcp.csproj`
  publishes the GitHub Release automatically. **Only bump the version when a real
  release is intended** — it changes shipped binaries, not workflow files.
- Every user-visible behavior is tested e2e (real keepassxc-cli, child processes,
  or stdio JSON-RPC). Do not add mock-based unit tests.
- After each release and after updating the installed binary, run the real-vault manual
  verification in `MANUAL_TEST.md` — the automated suite never touches a real vault or a
  real human at a password prompt; that drill does.
- Pre-release verification without touching the release machinery: run the **Beta**
  workflow (Actions → Run workflow, or `gh workflow run beta.yml --ref dev`). It publishes a
  GitHub *prerelease* `v<csproj-version>-beta.N` built from that exact ref (N
  auto-increments, CI must be green on the commit). It never bumps the csproj — beta
  versions are command-line build inputs only. `releases/latest` skips prereleases, so
  normal installs are unaffected; opt in with `KEEPASSXC_MCP_PRERELEASE=1` in the installer.

## PR description format (this becomes the release notes)

The merged PR's description is appended to the GitHub Release notes. Structure it
so the first section is the changelog:

```markdown
## Changes
- user-visible change, one bullet per change, phrased for someone installing
- say what got fixed/added/removed; omit internal churn

## Why / ## Details        (optional, after Changes)
```

The publish job copies the `## Changes` section into the release notes verbatim
(falls back to the whole description if `## Changes` is missing — so never omit it
in a release PR). Write bullets for users, not for the diff: "wrong vault password
no longer flushes staging", not "fix Promoter.cs exit path".

## Automatic dev cycle

Applies only when the user asks to start the automatic dev cycle.

- The task board is
  https://github.com/users/michaeltg17/projects/10/views/1.
- Tasks ready for start developing are the ones in the `Ready` column;
  never pick ones in the backlog. Ignore any task assigned to
  `michaeltg17`. Only pick unassigned tasks not in the backlog column.
- Work on exactly one task at a time. Move a card to `In progress` only
  at the moment its implementation starts, never while scouting or
  batching cards; the `In progress` column must reflect what is actually
  being developed right now (at most one card, plus any cards already
  there from before the cycle). If a picked task turns out to be blocked
  or is deferred before its work starts, leave (or move it back to)
  `Ready` instead of `In progress`.
- Do the work, then commit and push on `dev` and open/update the
  `dev` → `main` PR, following the `## Flow` and `## PR description format`
  sections above. Never bump `<Version>` during the cycle — releasing is
  the user's decision.
- A task counts as finished when it is committed, pushed, the PR is
  updated, and CI is green on the pushed commit. If the GitHub CI run is
  cancelled or stuck, do not wait for it: validate locally that CI passes
  (`dotnet build -c Release` then `dotnet test -c Release --no-build` —
  the real keepassxc-cli suite), then treat the task as done and go to
  the next one.
- Never ask the user questions during the cycle. If clarification or a
  decision is needed, move the card to `In review`, assign it to
  `michaeltg17`, leave a comment on the task describing the open question,
  and continue with the next eligible task.
- On finish, move the card to `Done`. If the work needs user review,
  move it to `In review` instead, assign it to `michaeltg17`, and leave a
  comment on the task describing what was done and what to review.
- Card operations (list / move / assign / comment) are provided by the
  `github-project-board` skill — load it when starting the cycle.
- Then pick the next eligible task from the `Ready` column and repeat;
  stop and report a summary when no eligible tasks remain.

## Hard rules

- Never bundle or re-implement kdbx/crypto work: everything goes through the
  external keepassxc-cli.
- The main vault password must never appear in config, on disk, in code, or in
  any process the MCP server can reach — keep it that way.
- Commit no machine-specific paths, vault files, or secrets; config lives in the
  user's app-data dir, docs live in the `wiki/` submodule (push it separately).
- README stays minimal; details go in the wiki.
