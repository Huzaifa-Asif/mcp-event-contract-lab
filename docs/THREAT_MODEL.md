# Threat model

Assets are developer attention, local fixture confidentiality, and report integrity. Untrusted JSON crosses into local browser/CLI code; the app has no network, credential, account, or storage boundary.

- Secret mistakes: flag obvious secret-key fields and never echo values; detection is incomplete.
- Resource exhaustion: 1 MiB fixture, 100-event and 250-sample limits plus a validation budget.
- SSRF: callback/event URLs are never fetched or linked.
- Prompt injection: event descriptions and payload strings are treated as data and instruction-like text is flagged.
- Report injection: browser uses `textContent`; Markdown strips control/bidirectional characters and escapes backticks.
- Supply chain: no runtime or development dependencies; CI actions are pinned.
- False assurance: reports preserve explicit limitations.

Out of scope: live signature verification, callback DNS/TLS/redirects, authorization, subscription storage, refresh/replay/reconnect, retry scheduling, compromised hosts, and complete protocol/JSON Schema conformance.
