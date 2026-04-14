# Contributing to BitAiir Core

Thanks for your interest in contributing! BitAiir is an open-source
cryptocurrency implementation written in Rust, and every improvement —
bug report, fix, doc tweak, test, feature — is welcome.

This document covers how to get the code building locally, the
workflow we use for changes, and the conventions we follow.

## Ground rules

- **Be respectful.** Discuss code, not people.
- **Small, focused changes merge faster** than sprawling ones.
- **Consensus-critical code** (`bitaiir-chain`, `bitaiir-crypto`,
  anything that can accept or reject blocks/transactions) gets
  extra scrutiny. Expect more review rounds and more test coverage
  requests here.
- **Security issues**: do **not** open a public issue. See
  [`SECURITY.md`](SECURITY.md) for the responsible-disclosure policy.

## Setting up the development environment

### Prerequisites

- Rust stable (1.85 or newer). Install via [rustup](https://rustup.rs/).
- Git.
- **Linux only**: system packages for `arboard` (clipboard) —
  `libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev`.

### Clone and build

```bash
git clone https://github.com/bitaiir/bitaiir.git
cd bitaiir
cargo build --workspace
```

First build takes a few minutes (Argon2id + ecosystem). Incremental
builds are fast.

### Run the local checks

Before opening a pull request, make sure everything passes what CI
runs on every commit:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

CI also builds for RISC-V cross-compilation; you don't have to
reproduce that locally unless you touched something that might
break it (e.g. platform-specific code).

### Try the daemon

Quick sanity check on testnet (fast block times, separate data
directory from mainnet):

```bash
cargo run --release --bin bitaiird -- --testnet -i --mine
```

In another terminal:

```bash
cargo run --release --bin bitaiir-cli -- --testnet getblockchaininfo
```

## Workflow

BitAiir uses a **pull-request-based** workflow. Nobody — not even
maintainers — pushes directly to `master`. This keeps CI as a gate
in front of the main branch and every change has a reviewed record.

### 1. Fork & branch

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/<your-user>/bitaiir.git
cd bitaiir
git remote add upstream https://github.com/bitaiir/bitaiir.git

git checkout -b feat/short-description
```

Branch names: `feat/`, `fix/`, `refactor/`, `docs/`, `ci/`,
`test/` — whatever fits.

### 2. Make the change

Keep commits focused. Multiple small commits on a branch are fine —
they get squashed on merge.

### 3. Commit style

We use [Conventional Commits](https://www.conventionalcommits.org/)
loosely:

```
<type>(<scope>): <short summary>

<body — the "why", not the "what">
```

Examples from the history:

```
feat(net): header-first sync — validate PoW on headers before fetching bodies
fix(tui): extend right-click paste suppression for large selections
security(wallet): zeroize secrets, enforce passphrase policy, bump Argon2
docs: add SECURITY.md with responsible disclosure policy
```

Types we use: `feat`, `fix`, `refactor`, `perf`, `security`, `docs`,
`test`, `ci`, `chore`, `style`.

### 4. Sign your commits with DCO

We use the [Developer Certificate of Origin](https://developercertificate.org/).
By signing off, you assert that you wrote the code (or have the right
to submit it) under the project's MIT license.

Sign off each commit with `-s`:

```bash
git commit -s -m "feat(chain): short summary"
```

This appends a `Signed-off-by: Your Name <your.email@example.com>`
line, which is all the DCO requires. No CLA, no paperwork.

### 5. Push and open a pull request

```bash
git push -u origin feat/short-description
gh pr create --fill
```

Fill in the PR template. Link any related issue with
`Closes #123` / `Fixes #123`.

### 6. Review and iterate

CI runs automatically (fmt, clippy, test on Linux/macOS/Windows,
RISC-V cross-build). Fix anything it flags. Reviewers may request
changes — push additional commits to the same branch, the PR
updates itself.

### 7. Merge

Once CI is green and review is done, a maintainer squash-merges the
PR. Master stays linear; your multi-commit branch becomes one commit
with the PR description as its body.

## Style conventions

### Rust

- `cargo fmt` is authoritative. If it disagrees with your aesthetic,
  `cargo fmt` wins.
- Clippy warnings are errors in CI (`-D warnings`). If a lint is
  genuinely wrong, use `#[allow(clippy::foo)]` with a comment
  explaining why.
- Prefer `rustdoc` comments (`///`) on public items. Don't comment
  the obvious — explain *why*, not *what*.
- No `unsafe` without a `// SAFETY:` comment justifying it.
  `bitaiir-net` and `bitaiir-types` crates forbid unsafe entirely
  (`#![forbid(unsafe_code)]`).

### Tests

- Add tests for new behavior. Consensus-critical code should have
  tests that cover both the happy path and at least one failure case.
- Integration-style tests that spin up multiple nodes are welcome —
  add them under `tests/` in the relevant crate.

### Documentation

- Public API changes update the doc comments.
- User-visible changes (new CLI flag, new RPC method, changed
  behavior) update `README.md` and the relevant doc in `docs/`.

## Reporting bugs

Open a [GitHub issue](https://github.com/bitaiir/bitaiir/issues)
using the bug report template. Include:

- BitAiir version (`bitaiird --version`).
- OS + architecture.
- Whether you're on mainnet or testnet.
- Steps to reproduce.
- Relevant log output.

For **security** bugs, **do not** open a public issue — follow
[`SECURITY.md`](SECURITY.md).

## Proposing features

Open an issue with the feature-request template first. For anything
non-trivial, it's worth discussing the approach before writing code —
saves everyone time.

## Good first issues

Look for the [`good-first-issue`](https://github.com/bitaiir/bitaiir/labels/good-first-issue)
label on open issues. These are scoped small and well-suited to
someone new to the codebase.

## Questions

- General discussion: [GitHub Discussions](https://github.com/bitaiir/bitaiir/discussions)
  (if enabled) or issues.
- Dev contact: [dev@bitaiir.org](mailto:dev@bitaiir.org).

Thanks for contributing!
