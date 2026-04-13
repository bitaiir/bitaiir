# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in BitAiir Core, **please report it responsibly**. Do not open a public issue.

**Email:** [security@bitaiir.org](mailto:security@bitaiir.org)

Include as much detail as possible:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix development | Depends on severity |
| Public disclosure | After fix is released |

## Scope

The following are in scope for security reports:

- **Consensus bugs** — anything that could cause chain splits, invalid blocks accepted, or valid blocks rejected
- **Cryptographic issues** — weaknesses in key generation, signing, hashing, or wallet encryption (AES-256-GCM, Argon2id)
- **P2P network attacks** — denial of service, eclipse attacks, message parsing exploits
- **Wallet vulnerabilities** — unauthorized access to private keys, bypass of encryption or lock mechanisms
- **RPC exploits** — unauthorized command execution, information leaks

## Out of Scope

- Bugs in third-party dependencies (report upstream, but let us know too)
- Social engineering attacks
- Issues requiring physical access to the machine

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (current) | Yes |

## Recognition

We appreciate responsible disclosure. Contributors who report valid security issues will be acknowledged in the release notes (unless they prefer to remain anonymous).

## Contact

- **Security reports:** [security@bitaiir.org](mailto:security@bitaiir.org)
- **General contact:** [contact@bitaiir.org](mailto:contact@bitaiir.org)
- **Development:** [dev@bitaiir.org](mailto:dev@bitaiir.org)
