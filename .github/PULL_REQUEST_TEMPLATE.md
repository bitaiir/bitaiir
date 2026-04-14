<!--
Thanks for opening a PR!

Keep the title short and in the form `<type>(<scope>): <summary>`
— for example `feat(net): batch getblocks requests`.  See
CONTRIBUTING.md for full conventions.
-->

## Summary

<!-- What does this PR do, and why?  One or two paragraphs. -->

## Related issue

<!-- `Closes #123` / `Fixes #123`, or "None" if this is a standalone change. -->

## How I tested this

<!--
Describe the manual and automated testing you did.  For
consensus-critical changes (anything in bitaiir-chain, bitaiir-crypto,
or the validation path), include at least one scenario where a
malformed input is correctly rejected.
-->

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` passes
- [ ] `cargo test --workspace --locked` passes
- [ ] I tested this against a local `bitaiird` (mainnet or testnet)

## Checklist

- [ ] My commits are signed off (`git commit -s`) per the DCO
- [ ] I added tests for new behavior (or explained in the PR why tests aren't applicable)
- [ ] I updated the relevant docs (`README.md`, `docs/`, or in-code rustdoc)
- [ ] For public-facing changes (CLI flag, RPC method, wire protocol), I noted it in the summary above
