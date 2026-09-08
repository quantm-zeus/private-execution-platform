# Contributing

Read docs/PRD.md, INVARIANTS.md and ARCHITECTURE.md before changing code. Use one branch/worktree per worker. Respect ownership scopes in STATUS.md. Keep commits small and compiling. Run cargo fmt --check, cargo clippy --workspace --all-targets -- -D warnings, and cargo test --workspace before handoff. Workers do not merge their own branch. Maintainer reviews architecture, tests and invariants before integration.
