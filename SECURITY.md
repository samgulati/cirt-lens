# Security policy

## Supported versions

Security fixes are applied to the latest version on the `main` branch and the latest tagged release.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting feature on the repository Security page. Include the affected endpoint or component, reproduction steps, impact, and any suggested mitigation.

You should receive an acknowledgement within seven days. Confirmed reports will be handled privately until a fix is available.

## Demonstration safety

CIRT Lens uses synthetic telemetry. The default connector is a deterministic fake, and response actions run in dry-run mode. Never configure a live connector against production identities or infrastructure. Development credentials, `.env` files, tokens, incident exports, and real telemetry must not be committed.

The project is a portfolio demonstration, not a certified security product or a substitute for professional incident-response tooling.
