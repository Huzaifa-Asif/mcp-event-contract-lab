# Security policy

Report suspected vulnerabilities privately through GitHub Security Advisories without real secrets or production payloads. Supported code is `main` and the latest release.

The tool rejects fixtures over 1 MiB, caps catalogs and samples, bounds schema traversal, never fetches URLs, renders with `textContent`, flags secret-like fields, removes control/bidirectional characters from Markdown, and uses no third-party dependencies. Its signature checks validate only sanitized header shape; they do not perform cryptographic verification.
