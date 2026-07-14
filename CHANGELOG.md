# Changelog

## [1.0.0] - 2026-07-14
### Added
- Initial release of VirlySentry.
- YAML-driven rule engine covering OWASP Top 10 categories (SQLi, XSS/SSTI, LFI/RFI, SSRF, Command Injection, Insecure Deserialization, XXE, Weak Crypto/Hardcoded Secrets, Security Misconfiguration, Broken Access Control, Vulnerable Components).
- AST-based dead code detector for unused Python functions/methods.
- Console, JSON, and HTML report formats.
- CLI commands: `scan`, `rules`, `init`.
- Inline suppression marker `virlysentry:ignore`.
- CI/CD severity gating via `--fail-on`.
- Example GitHub Actions workflow.
