# Extension & Contribution Guide

**Version**: 1.0-draft  
**Status**: Guide  
**Subsystem**: Documentation & Protocol Extensions

---

## 1. Purpose

This document defines the process for adding a new protocol extension, formal specification, or research note to `dart_quic`. Following these conventions keeps the documentation consistent, discoverable, and ready for implementation.

---

## 2. When to Add a New Spec

Create a new spec document when:

- You are adding support for a new QUIC version, frame type, or transport parameter.
- You are adding an HTTP/3 extension, WebTransport feature, or libp2p protocol.
- The RFC or draft you are targeting is stable enough to write acceptance criteria against.
- The topic is too large for an inline section in an existing spec (more than two sections or cross-cutting concerns).

Do **not** create a new spec for:

- Minor clarifications to an existing spec (edit the original).
- Pure bug fixes (use inline comments or the issue tracker).
- Architecture discussions without a concrete protocol target (use a research note first).

---

## 3. Document Template

Every new spec must use the following frontmatter and section structure:

```markdown
# Spec Title

**Version**: 1.0-draft
**Status**: Specification | Draft | Experimental
**Subsystem**: Subsystem Name

---

## 4. Purpose

One-paragraph summary of what this document specifies and why.

## 5. Scope

What is in scope and what is explicitly out of scope.

## 6. Background

RFC references, draft links, prior art, and definitions.

## 7. Design

The core specification: state machines, frame formats, algorithms, and wire encodings.

## 8. API Impact

How this spec affects the public Dart API or internal interfaces.

## 9. Acceptance Criteria

A checklist of conditions that mark this spec as "complete."

## 10. Security Considerations

Threat model, edge cases, and mitigations.

## 11. References

Links to RFCs, drafts, and related `dart_quic` documents.
```

Use sentence case for headings. Number top-level sections. Use tables for option comparisons and code blocks for wire formats or pseudo-code.

---

## 12. Checklist for New Extensions

Before marking a new extension as complete, verify:

- [ ] A research note exists in `doc/research/` summarizing the RFC or draft.
- [ ] A formal spec exists in `doc/specs/` using the canonical template.
- [ ] `doc/INDEX.md` is updated with links to both the research note and the spec.
- [ ] Dependent specs are updated with cross-references (bidirectional links).
- [ ] `doc/specs/ROADMAP.md` is updated with milestones or phase adjustments.
- [ ] New error codes are registered in `doc/specs/ERROR_REGISTRY.md` if applicable.
- [ ] Fuzz targets are added or planned in `doc/specs/FUZZING_SPEC.md` if the extension introduces new parsing paths.
- [ ] An ADR is created in `doc/decisions/` if the extension required an architectural decision.

---

## 13. Research Note Template

Research notes live in `doc/research/` and precede formal specs. Use this structure:

```markdown
# RFC XXXX Notes: Title

**RFC**: XXXX
**Authors**: Author Names
**Published**: Date
**Status**: Standards Track | Draft | Experimental
**Companion RFCs**: Related RFC numbers

---

## Abstract

Brief summary of the document.

## Key Design Principles

Numbered list of the most important design choices.

## Relevance to dart_quic

Numbered list of what we must implement, change, or watch out for.

## References

Links to the RFC and companion documents.
```

Research notes may be less formal than specs but must still be accurate and cite sources.

---

## 14. Naming Conventions

| Document Type | Directory | Filename Pattern | Example |
|---------------|-----------|------------------|---------|
| Research note | `doc/research/` | `<TOPIC>_NOTES.md` | `RFC_9000_NOTES.md` |
| Formal spec | `doc/specs/` | `<TOPIC>_SPEC.md` | `QUIC_WIRE_SPEC.md` |
| Architecture doc | `doc/architecture/` | `<TOPIC>.md` | `DATA_FLOW.md` |
| ADR | `doc/decisions/` | `ADR-NNN_<SHORT_TITLE>.md` | `ADR-001_Pure_Dart_No_FFI.md` |
| Registry / policy | `doc/specs/` | `<TOPIC>.md` | `ERROR_REGISTRY.md` |

- Use ALL_CAPS with underscores for protocol-specific files.
- Use CamelCase for general architecture files.
- ADR filenames must include the three-digit number and a short, underscore-separated title.
- Keep filenames under 40 characters where possible.