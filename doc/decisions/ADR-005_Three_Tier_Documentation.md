---
title: "ADR-005: Three-Tier Documentation"
category: decision
status: "Accepted"
---

# ADR-005: Three-Tier Documentation

## 1. Purpose

RFC researchers, protocol implementers, and new contributors need different information at different levels of detail. A flat documentation structure forces everyone to wade through irrelevant material. This decision establishes three tiers-research, specs, architecture-so that each audience finds what it needs without cross-referencing fatigue.

## 2. Detailed Specification
### 2.1 Context

The project must capture RFC analysis, implementation blueprints, and high-level architecture. A single flat doc directory risks mixing audiences: researchers need RFC notes, implementers need specs, and new contributors need architecture overviews.


### 2.2 Decision

Organize documentation into three tiers:
1. `doc/research/` — RFC and draft analysis, prior art, ecosystem gaps.
2. `doc/specs/` — Formal specifications, wire formats, state machines, acceptance criteria.
3. `doc/architecture/` — Module overviews, data flow, API surface, integration contracts.


### 2.3 Consequences

- **Clear audience**: Researchers can ignore architecture internals; implementers can ignore RFC summaries if they already know the protocol.
- **Some overlap**: A concept like flow control appears in all three tiers (RFC notes, formal spec, architecture diagram). We accept duplication if it prevents cross-referencing fatigue.
- **Discoverability**: The central `INDEX.md` must be kept up to date so readers can navigate across tiers.
- **Maintenance burden**: Three directories mean three places to update when a design changes. We mitigate this by treating `doc/specs/` as the authoritative source for behavior and `doc/architecture/` as the authoritative source for code structure.