# Release verification

- Run `npm run check` on supported Node versions.
- Parse manifest/examples and exercise valid/unsafe CLI paths.
- Verify browser app routes, CSP/security headers, keyboard focus and report live region.
- Scan tracked files for credentials and employer/private identifiers.
- Inspect deterministic build hashes and archive checksum.
- Obtain independent protocol/security/release review and fix blockers.
- Verify signed commit/tag, exact-commit CI, Pages deployment, live content, and release assets separately.
- Keep OpenAI submission, approval, and publication as distinct states.
