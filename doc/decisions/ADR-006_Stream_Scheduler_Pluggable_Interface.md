---
title: "ADR-006: Stream Scheduler as Pluggable Interface"
category: decision
status: "Accepted"
---

# ADR-006: Stream Scheduler as Pluggable Interface

## 1. Purpose

Stream scheduling is not one-size-fits-all: a web server may prioritize certain streams; a libp2p node may want fair bandwidth sharing; a media client may prioritize video over metadata. Baking in a single algorithm would force users to fork the library. A pluggable StreamScheduler interface with a round-robin default keeps the door open for custom schedulers without complicating the common case.

## 2. Detailed Specification
### 2.1 Context

Different applications have different stream scheduling needs. A web server may prioritize certain streams; a libp2p node may want fair bandwidth sharing; a media client may prioritize video over metadata.


### 2.2 Decision

Define the stream scheduler as an abstract interface (`StreamScheduler`) with a round-robin default implementation. Custom schedulers can be injected at connection creation time.


### 2.3 Consequences

- **Extensibility**: Users can implement priority-based, weighted-fair-queuing, or deadline-aware schedulers without forking the library.
- **Simple default**: Round-robin is easy to implement, hard to get wrong, and provides acceptable performance for most use cases.
- **Testing**: The interface allows deterministic scheduler injection in unit tests, making stream multiplexing tests reproducible.
- **API surface increase**: Adds one more configuration knob. We mitigate by providing sensible defaults and clear examples.
- **Performance overhead**: Scheduler selection runs on every stream iteration. The round-robin default is O(1) per active stream.