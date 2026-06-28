# quic_lib Documentation Standards

## Philosophy
Every public API member must have a doc comment. Documentation is the sole source of truth for library consumers. It must explain not just *what* something does, but *why* it exists, *when* to use it, and *how* it fits into the broader protocol stack.

## Required Elements

### Class / Enum / Mixin Documentation
```dart
/// One-sentence summary (RFC reference if applicable).
///
/// 1-3 paragraph explanation of:
/// - What this type represents in the protocol
/// - When and why a caller interacts with it
/// - Relationship to other types in the stack
///
/// ## Example
/// ```dart
/// final x = TypeName(...);
/// ```
///
/// See also:
/// - [RelatedType] — brief description of relationship
/// - RFC 9000 Section X — link or reference
class TypeName { ... }
```

### Constructor Documentation
```dart
/// Creates a [TypeName] suitable for <use-case>.
///
/// The [paramName] controls <behavior>. If omitted, defaults to <value>.
/// Throws [StateError] if <precondition>.
TypeName({required this.paramName}) { ... }
```

### Method Documentation
```dart
/// <Imperative sentence describing action>.
///
/// <Paragraph explaining protocol context, side effects, or preconditions>.
///
/// Returns <description of return value>.
/// Throws [ExceptionType] if <condition>.
Future<Uint8List> doThing() { ... }
```

### Getter / Property Documentation
```dart
/// <Noun phrase describing the value>.
///
/// <Why this matters to the caller>.
bool get isReady => ...;
```

### Enum Value Documentation
```dart
enum ConnectionState {
  /// The connection has been created but no handshake has begun.
  ///
  /// Transitions to [handshaking] on first packet transmission.
  idle,

  /// The TLS handshake is in progress.
  handshaking,
}
```

## Cross-Reference Rules
- Link to related types with `[TypeName]`.
- Link to methods/getters with `[TypeName.memberName]`.
- Never reference private members (`_foo`) in public docs.
- Never reference non-exported types unless they are base classes.

## RFC References
Include RFC citations where the behavior is specified:
```dart
/// QUIC variable-length integer encoding per RFC 9000 Section 16.
```

## Markdown Allowed in Docs
- `/// ## Section headers` for organizing long class docs.
- `/// - Bullet lists` for enumerating behavior.
- `/// ```dart` code blocks for examples.
- `/// *italic*` and `/// **bold**` for emphasis.
