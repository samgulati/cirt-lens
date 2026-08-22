# Security and trust model

CIRT Lens is a local, single-user portfolio demonstration using synthetic telemetry. It intentionally has no authentication; production would require identity, RBAC, tenant isolation, CSRF policy, rate limiting, and durable secret management.

Detection and correlation are deterministic. Evidence confidence is a `/100` support heuristic, not probability or model certainty. Failed authentication and denied MFA prompts may provide context, but only successful authentication with impossible-travel or new-device evidence can causally support the post-authentication privileged-action rule.

The app never executes telemetry command lines, scans networks, or connects response controls to infrastructure. Actions are audited simulations. `CONTAINED` cannot be directly assigned through the ordinary incident-status API; it is derived only when all required playbook objectives execute. `RESOLVED` is an explicit analyst decision.

External AI is optional and backend-only. Only structured JSON claims with incident-owned evidence IDs are accepted. Malformed, plain-text, or unsupported output is retried once and replaced with deterministic local output. Citation validation constrains evidence ownership but does not prove interpretation. Analyst notes are also untrusted text; plain-text reports reproduce them verbatim and must not be rendered as trusted HTML.

The browser receives no API secret. Pydantic rejects extra telemetry fields, request sizes and pagination are bounded, SQLAlchemy parameterizes queries, CORS is restricted to local development origins, and server exceptions do not expose stack traces.
