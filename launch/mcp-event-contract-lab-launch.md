# Audit MCP Events Before the First Webhook Fires

An event integration can look correct in two places and still fail at the seam between them. The catalog says an event is named `comment.created` and promises a payload. Hours later, a webhook arrives with a different name, an extra field, a reused ID, or a retry decision that no longer matches the response.

MCP Event Contract Lab makes that seam reviewable before a live subscription test.

## Two contracts, one failure surface

MCP Events starts with discovery. A server advertises event definitions, filter input schemas, payload schemas, and webhook delivery. Runtime delivery then adds event identity, occurrence time, user-authored data, cursor behavior, signed headers, subscription identity, response handling, and retries.

Most tools inspect only one side. A JSON Schema validator can check the payload shape. A webhook relay can show a request. Neither necessarily answers whether the captured request still matches the event the server advertised.

The Lab accepts one sanitized fixture containing both. Its browser UI and CLI compare catalog and sample evidence locally. It checks the current protocol/capability marker, stable dotted names, webhook delivery, bounded object schemas, unique event IDs, timezone-aware timestamps, header/body identity, redacted signature evidence, the 256 KiB body ceiling, payload/schema agreement, retry evidence, and instruction-like user text.

```sh
node cli.mjs examples/valid.json --markdown
```

## Why offline

Callback testing carries real operational risk: signing secrets, public endpoints, SSRF defenses, DNS resolution, redirects, retries, and potentially sensitive user content. This preflight intentionally accepts none of those responsibilities. It does not fetch a callback or verify a signature. Fixtures use synthetic data and redacted signature markers; reports contain paths and finding codes rather than submitted values.

That boundary makes the tool useful earlier, when developers are still aligning contracts and can safely share evidence in code review.

## Where it fits

Use MCP Inspector and ChatGPT for the real lifecycle. Use Standard Webhooks/Svix tooling when cryptographic verification is the question. Use Hookdeck, Outpost, or Webhook Relay for delivery infrastructure and observability. Use a full JSON Schema implementation when complete schema semantics matter.

MCP Event Contract Lab is the checklist between catalog design and those live systems.

It also avoids a neighboring concern on purpose. Subscription storage, refresh, reconnect, replay state, and retry scheduling belong to lifecycle implementations such as `mcp-subscription-sentinel`; this app does not model them.

## What a clean report means

A clean report means the evaluated fixture passed a bounded offline profile. It does not establish HMAC validity, callback safety, authorization, persistence, full JSON Schema or MCP conformance, accessibility certification, OpenAI approval, or deployability.

The next step is still an isolated end-to-end test: discover the catalog, subscribe, verify the callback, send matching and non-matching events, test acknowledgements and retry boundaries, revoke access, unsubscribe, and confirm delivery stops.

## Release

MCP Event Contract Lab v0.1.0 is MIT-licensed, zero-dependency, and includes a browser UI, CLI, portable audit skill, synthetic examples, threat model, privacy/security guidance, tests, and release checklist. Repository and live-demo links will be finalized only after exact-commit CI and deployment verification.

_Draft prepared 2026-10-24 MYT. No editorial publication destination has been selected or authorized._
