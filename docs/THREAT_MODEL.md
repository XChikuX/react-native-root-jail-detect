# Threat Model

This library is a client-side heuristic. A capable attacker can patch the app,
hide artifacts, hook checks, or falsify results. A clean result means only that
the available checks found no evidence.

Do not authorize sensitive actions from a client-provided score or signal list.
Use layered controls: provider-verified attestation, short-lived server decisions,
rate limits, telemetry, step-up authentication, and transport protections that
fit the product's risk model.

Rooted and jailbroken users are not automatically malicious. Treat signals as
product-policy inputs, choose thresholds deliberately, and offer a recovery path
where inappropriate blocking could harm legitimate users.

When using Play Integrity, send its token to your backend with a server-issued
nonce. Verify it directly with Google and bind the resulting policy to a
short-lived session. Never trust a client boolean as the integrity verdict.
