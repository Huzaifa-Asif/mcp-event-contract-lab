const MAX_BYTES = 262_144;
const MAX_EVENTS = 100;
const MAX_SAMPLES = 250;
const SECRET = /^(?:secret|token|password|api[_-]?key|authorization|signing[_-]?(?:key|secret)|client[_-]?secret|webhook[_-]?secret|access[_-]?token)$/i;
const INSTRUCTION = /ignore (?:all |any )?(?:previous|prior|above) instructions|system prompt|exfiltrat|send (?:the )?(?:secret|credential)|act as (?:the )?system/i;
const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const add = (out, severity, code, message, path = null) => out.push({ severity, code, message, path });

function object(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  if (new TextEncoder().encode(JSON.stringify(value)).byteLength > MAX_BYTES * 4) throw new Error(`${label} exceeds the 1 MiB fixture limit`);
}
function strings(value, label, out, path) {
  if (!Array.isArray(value) || value.some((x) => typeof x !== "string" || !x.trim())) { add(out, "high", `invalid-${label}`, `${label} must be an array of non-empty strings.`, path); return []; }
  return value;
}
function scan(value, path, out) {
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const childPath = `${path}.${key}`;
    if (SECRET.test(key) && child !== null && child !== "" && child !== "[REDACTED]") add(out, "critical", "secret-bearing-fixture", "Remove secrets, tokens and signing keys before analysis.", childPath);
    if (child && typeof child === "object") scan(child, childPath, out);
  }
}
function hasInstructions(value) {
  if (typeof value === "string") return INSTRUCTION.test(value);
  if (Array.isArray(value)) return value.some(hasInstructions);
  if (value && typeof value === "object") return Object.values(value).some(hasInstructions);
  return false;
}
function schemaShape(schema, path, out) {
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) { add(out, "critical", "invalid-schema", "Schema must be an object.", path); return; }
  if (schema.type !== "object") add(out, "high", "schema-object-type", 'Schema should declare type: "object".', `${path}.type`);
  if (!schema.properties || typeof schema.properties !== "object" || Array.isArray(schema.properties)) add(out, "high", "schema-properties-missing", "Schema must declare object properties.", `${path}.properties`);
  if (schema.required !== undefined && (!Array.isArray(schema.required) || schema.required.some((x) => typeof x !== "string"))) add(out, "high", "schema-required-invalid", "Schema required must be an array of strings when present.", `${path}.required`);
  if (schema.additionalProperties !== false) add(out, "medium", "schema-open-shape", "Set additionalProperties to false for a narrow contract.", `${path}.additionalProperties`);
}
function matchesType(value, type) {
  if (type === "null") return value === null;
  if (type === "integer") return Number.isInteger(value);
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  if (type === "array") return Array.isArray(value);
  if (type === "object") return value !== null && typeof value === "object" && !Array.isArray(value);
  return typeof value === type;
}
function validate(value, schema, path, out, budget = { left: 10_000 }) {
  if (--budget.left < 0) { add(out, "critical", "validation-budget", "Validation exceeded the safe operation bound.", path); return; }
  if (!schema || typeof schema !== "object") return;
  if (schema.type === "object") {
    if (!matchesType(value, "object")) { add(out, "critical", "payload-schema-mismatch", "Expected an object.", path); return; }
    for (const key of schema.required ?? []) if (!Object.hasOwn(value, key)) add(out, "critical", "payload-schema-mismatch", `Required property ${key} is missing.`, `${path}.${key}`);
    for (const [key, child] of Object.entries(value)) {
      if (schema.properties?.[key]) validate(child, schema.properties[key], `${path}.${key}`, out, budget);
      else if (schema.additionalProperties === false) add(out, "high", "payload-schema-mismatch", `Additional property ${key} is not allowed.`, `${path}.${key}`);
    }
  } else if (schema.type === "array") {
    if (!Array.isArray(value)) add(out, "critical", "payload-schema-mismatch", "Expected an array.", path);
    else if (schema.items) value.forEach((item, index) => validate(item, schema.items, `${path}[${index}]`, out, budget));
  } else if (schema.type && !matchesType(value, schema.type)) add(out, "critical", "payload-schema-mismatch", `Expected ${schema.type}.`, path);
  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) add(out, "high", "payload-schema-mismatch", "Value is not in the declared enum.", path);
}

export function analyzeBundle(bundle) {
  object(bundle, "fixture");
  const findings = [];
  scan(bundle, "$", findings);
  if (bundle.protocolVersion !== "2026-07-28") add(findings, "high", "protocol-version", "MCP Events for ChatGPT requires protocol version 2026-07-28.", "$.protocolVersion");
  if (!bundle.capabilities?.events || typeof bundle.capabilities.events !== "object" || Array.isArray(bundle.capabilities.events)) add(findings, "critical", "events-capability-missing", "server/discover must advertise the events capability as an object.", "$.capabilities.events");
  if (!Array.isArray(bundle.events) || !bundle.events.length) throw new Error("events must be a non-empty array");
  if (bundle.events.length > MAX_EVENTS) throw new Error(`events exceeds the ${MAX_EVENTS}-event limit`);
  if (!Array.isArray(bundle.samples)) throw new Error("samples must be an array");
  if (bundle.samples.length > MAX_SAMPLES) throw new Error(`samples exceeds the ${MAX_SAMPLES}-sample limit`);
  const catalog = new Map();
  for (const [index, event] of bundle.events.entries()) {
    const path = `$.events[${index}]`;
    if (!event || typeof event !== "object" || Array.isArray(event)) { add(findings, "critical", "invalid-event", "Event definition must be an object.", path); continue; }
    if (typeof event.name !== "string" || !event.name.trim()) add(findings, "critical", "event-name-missing", "Event name must be non-empty.", `${path}.name`);
    else {
      if (!/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+$/.test(event.name)) add(findings, "medium", "event-name-convention", "Dotted lowercase names are a project convention, not an MCP requirement.", `${path}.name`);
      if (catalog.has(event.name)) add(findings, "critical", "duplicate-event-name", "Event names must be unique.", `${path}.name`); else catalog.set(event.name, event);
    }
    if (typeof event.description !== "string" || event.description.trim().length < 12) add(findings, "medium", "weak-event-description", "Describe the user-visible occurrence specifically.", `${path}.description`);
    if (hasInstructions(event.description)) add(findings, "high", "instruction-like-description", "Event descriptions must describe data, not instruct the model.", `${path}.description`);
    if (hasInstructions(event.inputSchema) || hasInstructions(event.payloadSchema)) add(findings, "high", "instruction-like-schema", "Schema text contains instruction-like language; treat it as untrusted metadata.", path);
    const delivery = strings(event.delivery, "delivery", findings, `${path}.delivery`);
    if (!delivery.includes("webhook")) add(findings, "critical", "webhook-delivery-missing", "ChatGPT MCP Events currently requires webhook delivery.", `${path}.delivery`);
    if (delivery.some((item) => item !== "webhook")) add(findings, "medium", "unsupported-delivery", "Polling and streaming delivery are not supported by this integration.", `${path}.delivery`);
    schemaShape(event.inputSchema, `${path}.inputSchema`, findings);
    schemaShape(event.payloadSchema, `${path}.payloadSchema`, findings);
  }
  const ids = new Set();
  for (const [index, sample] of bundle.samples.entries()) {
    const path = `$.samples[${index}]`;
    if (!sample || typeof sample !== "object" || Array.isArray(sample)) { add(findings, "critical", "invalid-sample", "Sample must be an object.", path); continue; }
    const allowed = new Set(["eventId", "name", "timestamp", "data", "cursor", "headers", "attempts", "bodyBytes"]);
    const body = {};
    for (const [key, value] of Object.entries(sample)) {
      if (!["headers", "attempts", "bodyBytes"].includes(key)) body[key] = value;
      if (!allowed.has(key)) add(findings, "high", "top-level-application-field", "Keep application fields inside data.", `${path}.${key}`);
    }
    if (typeof sample.eventId !== "string" || !sample.eventId.trim()) add(findings, "critical", "event-id-missing", "Each delivery needs a stable eventId.", `${path}.eventId`);
    else if (ids.has(sample.eventId)) add(findings, "critical", "duplicate-event-id", "Event IDs must be unique across distinct samples; model retries as attempts within one sample.", `${path}.eventId`); else ids.add(sample.eventId);
    const event = catalog.get(sample.name);
    if (!event) add(findings, "critical", "unknown-event", "Delivery name is not declared in the event catalog.", `${path}.name`);
    const time = typeof sample.timestamp === "string" ? Date.parse(sample.timestamp) : NaN;
    if (!Number.isFinite(time) || !/(Z|[+-]\d\d:\d\d)$/.test(sample.timestamp ?? "")) add(findings, "high", "invalid-event-timestamp", "timestamp must be ISO 8601 with a timezone.", `${path}.timestamp`);
    if (sample.cursor !== null) add(findings, "medium", "cursor-manual-review", "This fixture profile expects null unless replay is intentionally implemented and separately reviewed.", `${path}.cursor`);
    const headers = sample.headers;
    if (!headers || typeof headers !== "object" || Array.isArray(headers)) add(findings, "critical", "headers-missing", "Capture delivery header names with redacted values.", `${path}.headers`);
    else {
      const normalized = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
      if (normalized["webhook-id"] !== sample.eventId) add(findings, "critical", "webhook-id-mismatch", "webhook-id must equal the body eventId.", `${path}.headers.webhook-id`);
      if (!/^\d{10}$/.test(String(normalized["webhook-timestamp"] ?? ""))) add(findings, "high", "signing-timestamp-invalid", "webhook-timestamp must be Unix seconds.", `${path}.headers.webhook-timestamp`);
      if (typeof normalized["webhook-signature"] !== "string" || !/^v\d+,\[REDACTED\]$/.test(normalized["webhook-signature"])) add(findings, "high", "signature-evidence-missing", "Record only a redacted signature marker such as v1,[REDACTED].", `${path}.headers.webhook-signature`);
      if (typeof normalized["x-mcp-subscription-id"] !== "string" || !normalized["x-mcp-subscription-id"].trim()) add(findings, "high", "subscription-header-missing", "Capture a non-empty subscription ID.", `${path}.headers.X-MCP-Subscription-Id`);
    }
    const reconstructedBytes = new TextEncoder().encode(JSON.stringify(body)).byteLength;
    if (sample.bodyBytes === undefined) add(findings, "medium", "exact-body-bytes-missing", "Provide bodyBytes from the exact signed request bytes; reconstructed JSON size is only an estimate.", `${path}.bodyBytes`);
    else if (!Number.isInteger(sample.bodyBytes) || sample.bodyBytes <= 0) add(findings, "high", "invalid-body-bytes", "bodyBytes must be a positive integer.", `${path}.bodyBytes`);
    if ((Number.isInteger(sample.bodyBytes) ? sample.bodyBytes : reconstructedBytes) > MAX_BYTES) add(findings, "critical", "payload-too-large", "One exact event body exceeds 256 KiB.", path);
    if (event) validate(sample.data, event.payloadSchema, `${path}.data`, findings);
    if (hasInstructions(body)) add(findings, "high", "instruction-like-event-data", "Event body contains instruction-like language; treat it as untrusted data.", path);
    if (!Array.isArray(sample.attempts) || !sample.attempts.length) add(findings, "high", "attempt-evidence-missing", "Capture at least one delivery response attempt.", `${path}.attempts`);
    else {
      for (const [attemptIndex, attempt] of sample.attempts.entries()) {
        const attemptPath = `${path}.attempts[${attemptIndex}]`;
        if (!Number.isInteger(attempt.status) || attempt.status < 100 || attempt.status > 599) add(findings, "high", "invalid-response-status", "Attempt status must be an HTTP status.", `${attemptPath}.status`);
        if ([410, 413].includes(attempt.status) && attempt.retryPlanned === true) add(findings, "critical", "forbidden-retry", `Do not retry HTTP ${attempt.status}.`, `${attemptPath}.retryPlanned`);
        if (attempt.status >= 200 && attempt.status < 300 && attempt.retryPlanned === true) add(findings, "high", "retry-after-ack", "A 2xx acknowledges receipt; do not retry it.", `${attemptPath}.retryPlanned`);
      }
      if (sample.attempts.length > 1 && new Set(sample.attempts.map((item) => item.signingTimestamp)).size !== sample.attempts.length) add(findings, "high", "reused-signing-timestamp", "Each retry needs a fresh signing timestamp and signature.", `${path}.attempts`);
    }
  }
  findings.sort((a, b) => RANK[a.severity] - RANK[b.severity] || a.code.localeCompare(b.code) || String(a.path).localeCompare(String(b.path)));
  const summary = Object.fromEntries(Object.keys(RANK).map((level) => [level, findings.filter((item) => item.severity === level).length]));
  return { schemaVersion: 1, status: summary.critical || summary.high ? "needs-attention" : "reviewed", summary, findings, limitations: ["Offline analysis does not verify HMAC signatures, callback networking, authorization, persistent storage, or live ChatGPT behavior.", "Exact 256 KiB enforcement requires bodyBytes captured from the exact signed request bytes; reconstructed JSON is only an estimate.", "The JSON Schema evaluator is intentionally bounded and incomplete.", "Subscription lifecycle, refresh, reconnect and retry scheduling are excluded to avoid overlap with mcp-subscription-sentinel.", "A clean report is not protocol conformance, security certification, OpenAI review, approval, or publication."] };
}

export function formatMarkdown(report) {
  const clean = (value) => String(value).replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, "?").replaceAll("`", "\\`");
  return ["# MCP event contract report", "", `Status: **${report.status}**`, "", ...report.findings.map((item) => `- **${item.severity.toUpperCase()}** \`${clean(item.code)}\`: ${clean(item.message)}${item.path ? ` (\`${clean(item.path)}\`)` : ""}`), "", "## Limitations", "", ...report.limitations.map((item) => `- ${item}`), ""].join("\n") + "\n";
}
