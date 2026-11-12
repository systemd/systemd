---
title: Varlink API Style
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# General guideline

- New Varlink APIs and extensions to existing APIs must follow the
  [UAPI Varlink specification](https://uapi-group.org/specifications/specs/varlink/),
  respecting its requirements, recommendations and permitted exceptions. The
  guidelines below supplement it with systemd-specific conventions.

- Varlink field names should use camelCase. This guideline does not apply to
  well-known and documented configuration options, such as those defined in
  [systemd.unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html),
  where existing naming conventions should be preserved for
  compatibility and clarity.

- Every field and method should include meaningful documentation. It's
  acceptable to reference existing documentation where appropriate.
  Documentation may be omitted only when the meaning is self-evident, even to
  someone not already familiar with varlink interface/method.

- Varlink fields should optimize toward clarity:
  * avoid abbreviations: `cacheDir` -> `cacheDirectory`
  * prefer string values over numeric codes when possible,
    to make interfaces more self-descriptive and easier to understand.

# Interface structure

- Varlink methods should consider splitting their output into 'context' and
  'runtime' sections. The guiding principle is simple: if a property makes
  sense to include in a configuration (e.g. unit file), it belongs to 'context';
  otherwise, it goes under 'runtime'. This split ensures a consistent and
  reusable structure. Functions that describe an object can produce context
  data that other functions can later consume to create a similar object.

  Example: `io.systemd.Unit.List` outputs unit configuration, which can later
  be reused to create another unit via `io.systemd.Unit.StartTransient`.
  The `io.systemd.Unit.StartTransient` call should accept only the 'context'
  portion of the output, without requiring any runtime data such as state
  (e.g. pid) or statistics.

- Following the guideline above, any field within 'context' should be nullable
  by default. This ensures that when a context structure is used as input, the
  caller is not required to provide every field explicitly. Omitted fields are
  automatically assigned their default values, allowing partial context
  definitions to be valid and simplifying reuse across different operations.
  Fields that cannot logically be omitted in input (e.g. a unit type) may remain
  non-nullable.

- Input may accept multiple representations of the same information. Output
  should be normalized and must not include the same information in multiple
  forms. Every output field in a reusable context must be accepted on input,
  so that the context can be fed back without conversion or removal of fields.
  For example, the context returned by `io.systemd.Unit.List` must be usable
  as input to `io.systemd.Unit.StartTransient`. The same principle applies to
  other interfaces that share structures between output and input.

# Enums

- Enum fields in the codebase must be exposed as string values in Varlink, not
  as their underlying integer representations. Use `SD_VARLINK_DEFINE_ENUM_TYPE`
  to declare an enum type in the Varlink specification.

- Enum inputs and outputs must use the values declared in the IDL. When deriving
  enum values from internal names, replace dashes with underscores.
  `JSON_BUILD_STRING_UNDERSCORIFY` outputs a stringified enum value with dashes
  converted to underscores. Use `JSON_DISPATCH_ENUM_DEFINE` for input
  conversion: it first tries the value as-is via the supplied conversion
  function, and if that fails, replaces underscores with dashes and retries.

- Existing string-typed inputs may continue accepting dashed aliases for
  compatibility. Converting such an input to an enum would break clients that
  use the dashed spelling.

- An internal enum may be exposed as a simple string field instead of a Varlink
  enum type when the field is output-only and never provided or controlled by
  the user. However, such fields should avoid using dashes to keep values
  representable as enum members.

  For example, in `io.systemd.Unit`, configuration settings that users select
  in unit files (e.g. `ProtectSystem`, `ExecInputType`) should be proper varlink
  enum types. Runtime state fields that only the engine determines (e.g.
  `ActiveState`, `SubState`) may remain plain strings.

- Under these rules, new inputs exposing internal enums accept only the declared
  spelling. Accepting both dashed and underscored forms is limited to existing
  string-typed inputs. Supporting both forms in new inputs would require either
  adding alias support to IDL validation or an explicit exception permitting
  string-typed inputs.

- A varlink string field that has a finite set of possible values may later be
  converted into an enum without introducing a breaking change. This allows the
  interface to evolve from loosely defined string values to a more explicit and
  type-safe enumeration once the valid options are well established.

# Experimental interfaces

- New interfaces, methods, errors, types, fields and enum values may be marked
  as experimental with `SD_VARLINK_EXPERIMENTAL`, using the `_FULL` variants of
  the definition macros, or the field flags. Experimental items may change
  incompatibly or be removed without advance notice. The marker is shown as a
  `# [Experimental]` comment in the interface description, and is purely
  informational: calls to experimental methods are not refused.

- Mark a whole interface as experimental with `SD_VARLINK_DEFINE_INTERFACE_FULL`
  if it belongs to a component that is documented as experimental. Otherwise,
  mark only the items that are experimental.

- Non-experimental items must not depend on experimental ones: a field that is
  not experimental (and is not part of an experimental method, type, error or
  interface) must not refer to an experimental type. Experimental fields of
  non-experimental methods, types and errors must be nullable, so that callers
  and implementations of the stable parts can ignore them. Experimental enum
  values are only permitted in experimental enums, since a non-experimental
  field of the enum type might otherwise carry them. These rules are checked by
  `varlinkctl validate-idl`, and by the unit tests for the interfaces shipped
  with systemd.

- To stabilize an item, drop the marker. Any experimental types it uses then
  need to be stabilized too.
