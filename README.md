# MCP Event Contract Lab

An offline, zero-dependency browser and CLI preflight for MCP Events catalogs and sanitized delivery evidence. It checks discovery capability, event definitions, bounded schemas, event/header identity, timestamps, payload size, sample/schema agreement, retry evidence, secret-like fields, and instruction-like user content without contacting a callback.

## Why

MCP Events combines two contracts: what a server advertises through `events/list`, and what it later delivers as a signed webhook. Generic webhook relays show traffic; this tool compares those saved contracts before a live subscription test.

## Run

Requires Node.js 20+.

```sh
npm run check
npm start
node cli.mjs examples/valid.json --markdown
```

Open `http://127.0.0.1:4173`. Use synthetic content and the redacted signature marker `v1,[REDACTED]`. The app never fetches URLs, verifies live HMAC signatures, sends events, or stores input.

## Fixture API

See `examples/valid.json`. A fixture contains `protocolVersion`, discovered `capabilities`, event definitions, and captured `samples`. Every sample contains the event body fields, redacted header evidence, and response attempts. Exit codes are 0 for no critical/high findings, 1 for findings, and 2 for invalid input.

The portable workflow is at `skills/audit-mcp-event-contracts/SKILL.md`. This static utility does not expose an MCP server and is not an OpenAI directory submission.

## Scope limits

This is not a webhook receiver, signature verifier, SSRF tester, full JSON Schema validator, subscription manager, retry scheduler, protocol certification, or evidence of OpenAI approval. Subscription lifecycle, refresh, reconnect, and state-machine behavior are expressly excluded to avoid duplicating `mcp-subscription-sentinel`.

MIT licensed. See the privacy, security, support, contribution, conduct, research, threat-model, and release-verification documents.
