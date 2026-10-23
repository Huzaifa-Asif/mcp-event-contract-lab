# Research and alternatives — 2026-10-24

## Need

Current OpenAI MCP Events guidance requires protocol `2026-07-28`, advertised events capability, webhook-only delivery, separate input and payload schemas, unique IDs preserved across retries, signed header/body agreement, one event per request, a 256 KiB body limit, bounded retries, no retries for 410/413, and untrusted treatment of user-authored text. These rules span discovery and delivery, creating a useful offline comparison point before live testing.

Primary source: [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events). Security/privacy baseline: [OpenAI plugin security and privacy](https://developers.openai.com/plugins/guides/security-privacy).

## Alternatives

- MCP Inspector and ChatGPT exercise a reachable server and full lifecycle.
- Svix and Standard Webhooks tooling verify or deliver live signed requests.
- Hookdeck Outpost and Webhook Relay provide delivery infrastructure/observability.
- Generic JSON Schema validators deeply validate one schema, without the MCP catalog/delivery comparison.

Those are stronger for live transport. This project is narrower: sanitized saved-fixture triage with no credentials or network.

## Novelty and overlap limit

Event schema validation and webhook linting are established. Originality is limited to the bounded cross-check between current MCP event definitions and captured delivery evidence. Subscription lifecycle, refresh, reconnect, state persistence, and retry planning are excluded because `mcp-subscription-sentinel` owns that scope. No code from alternatives was copied.
