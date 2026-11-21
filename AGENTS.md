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

## Hard rules

- Never bundle or re-implement kdbx/crypto work: everything goes through the
  external keepassxc-cli.
- The main vault password must never appear in config, on disk, in code, or in
  any process the MCP server can reach — keep it that way.
- Commit no machine-specific paths, vault files, or secrets; config lives in the
  user's app-data dir, docs live in the `wiki/` submodule (push it separately).
- README stays minimal; details go in the wiki.
