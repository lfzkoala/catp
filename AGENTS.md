# CATP Agent Instructions

This file is for AI agents working in this repository.

Follow these instructions unless a higher-priority system/developer instruction
or an explicit user request says otherwise.

## Mission

Keep CATP focused.

CATP is an agent authorization and audit protocol. Its core work is to help
agent activity become constrained, recorded, and externally verifiable.

Do not turn CATP into a broad agent platform, dashboard, reputation system,
registry, hosted service, or generic ZK playground unless the user explicitly
asks for that direction.

When the current direction is unclear, read:

- `README.md` for the user-facing product shape
- `IMPLEMENTATION_PLAN.md` for active milestones
- `ARCHITECTURE.md` for system boundaries
- relevant files in `docs/` for detailed operations

## Before Editing

Before changing files, state briefly:

- what will change
- why it matters
- likely affected files
- how you will verify it

Then implement. Do not stop at a proposal when the user asked to continue
development.

## Development Rules

1. Prefer small, mainline-focused changes.
2. Prefer the correct implementation over demo-only shortcuts.
3. Use existing project patterns before adding abstractions.
4. Add or update tests when behavior changes.
5. Do not revert user changes unless explicitly asked.
6. If the worktree is dirty, inspect it before editing.
7. Do not reintroduce removed or deferred subsystems without an explicit user request.
8. Use `IMPLEMENTATION_PLAN.md` as the source of truth for current implementation focus.
9. Commit every code or documentation change unless the user explicitly says not to commit.

## Documentation Rules

README is the project homepage. Keep it short and current.

README should explain what exists now. Do not put roadmap in README.

Use:

- `IMPLEMENTATION_PLAN.md` for roadmap and active milestones
- `ARCHITECTURE.md` for system design
- `docs/INSTALL.md` for installation and user flow
- security or E2E docs for specialized operational details

Delete or consolidate stale docs when they no longer serve the current project.

## Verification

Run the smallest verification set that covers the change.

Use existing package scripts, CI config, component docs, and `CONTRIBUTING.md`
as the source of truth for commands.

Use targeted tests for narrow changes and broader checks for shared behavior,
release work, contracts, or verifier changes.

If you cannot run a relevant check, say so clearly in the final response.

## Release Rules

- Do not bump a version just because a local publish failed.
- If npm publish fails for an existing scoped package, check authentication and package ownership first.
- Verify published packages before tagging or announcing.
- Use isolated temporary directories and `CATP_HOME` for fresh-install smoke tests.
- Git tags should match package versions.

## Cleanup Rules

Delete or consolidate code only when it is outside the active project direction
or clearly duplicated.

Do not remove active optional backends or security checks just because they are
not part of the default user path.

Prefer one canonical helper for duplicated semantics such as policy
commitments, audit export hashing, receipt verification, and manifest
validation.

## Default Bias

When unsure, choose:

- current implementation plan over new scope
- README clarity over README completeness
- explicit tests over manual confidence
- repository-local verification over external services
- conservative cleanup over broad rewrites
