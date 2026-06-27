---
title: "ADR-003: Soft-Fail Certificate Revocation"
category: decision
status: "Accepted"
---

# ADR-003: Soft-Fail Certificate Revocation

## 1. Purpose

Hard-fail revocation checking has a long history of breaking legitimate connections when CRL/OCSP servers are unreachable. For a transport stack that must run in P2P and mobile environments with spotty connectivity, soft-fail is the pragmatic default that matches browser behavior without sacrificing security mitigations like OCSP stapling and short-lived certificates.

## 2. Detailed Specification
### 2.1 Context

Hard-fail certificate revocation checking (strict CRL or OCSP failure = connection refused) has historically caused widespread availability issues when revocation servers are unreachable, slow, or misconfigured.


### 2.2 Decision

Adopt soft-fail certificate revocation as the default policy. If CRL or OCSP data cannot be fetched or parsed, the connection continues rather than aborting. Hard-fail remains an opt-in setting for environments that require it.


### 2.3 Consequences

- **Availability**: Matches browser behavior (Chrome, Firefox, Safari) where soft-fail is the de-facto standard to avoid breaking legitimate sites.
- **Security posture**: A revoked certificate may still be accepted if the revocation infrastructure is down or blocked. We mitigate this with short-lived certificates, OCSP stapling support, and certificate transparency logging where applicable.
- **libp2p alignment**: libp2p TLS peer authentication does not rely on PKI revocation; self-signed certificates are validated via peer ID. Soft-fail is therefore low-risk for our primary P2P use case.
- **Configuration surface**: Adds a `revocationPolicy` enum (`softFail`, `hardFail`, `disabled`) to the connection configuration.