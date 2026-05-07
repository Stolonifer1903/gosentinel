---
description: Create sequential, meaningful git commits for the current set of staged or unstaged changes.
---

## Commit Format

<type>(<scope>): <short description ≤50 chars, imperative tense>

[optional body — explain WHY, not WHAT]

[optional footer — Phase ref, breaking changes]

## Types

- feat → new module, flag, struct, or capability
- fix → bug fix in existing code
- refactor → restructure without behaviour change
- test → adding or updating tests only
- docs → comments, README, implementation plans
- chore → deps, config, tooling

## Rules

1. One commit = one logical unit. Never bundle module + tests + bug fix together.
2. Run `go test ./internal/<package>/... -race` before every commit.
3. Use `git add <specific files>` — never `git add .`
4. Use `git add -p` when one file contains changes for two commits.
5. Verify `git diff --staged` before committing.
6. Derive scope from the package of the modified file.

## Steps

1. Identify what logical unit of work is complete and compiles.
2. Run tests: `go test ./internal/<pkg>/... -race`
3. Stage only relevant files: `git add <file>`
4. Check staged diff: `git diff --staged`
5. Commit: `git commit -m "<type>(<scope>): <description>"`
6. For multi-line messages: `git commit` (opens editor).
