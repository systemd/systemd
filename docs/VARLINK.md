---
title: Varlink API Style
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# General guideline

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
  be reused to create another unit via `io.systemd.Unit.StartTransient` (not
  implemented yet). The `io.systemd.Unit.StartTransient` call should accept
  only the 'context' portion of the output, without requiring any runtime data
  such as state (e.g. pid) or statistics.

- Following the guideline above, any field within 'context' should be nullable
  by default. This ensures that when a context structure is used as input, the
  caller is not required to provide every field explicitly. Omitted fields are
  automatically assigned their default values, allowing partial context
  definitions to be valid and simplifying reuse across different operations.
  Fields that cannot logically be omitted in input (e.g. a unit type) may remain
  non-nullable.

# Enums

- Enum fields in the codebase must be exposed as string values in Varlink, not
  as their underlying integer representations. Use `SD_VARLINK_DEFINE_ENUM_TYPE`
  to declare an enum type in the Varlink specification.

- The Varlink IDL validator does not permit enum values that contain dashes.
  Therefore, when defining an enum for Varlink, replace dashes with underscores.

- Varlink interface should output enum values using the underscore form. For
  input, it should accept both the original dash-containing form and the
  underscore form. The following helpers simplify this:
  * `JSON_BUILD_STRING_UNDERSCORIFY` - outputs a stringified enum value
    with dashes converted to underscores.
  * `JSON_DISPATCH_ENUM_DEFINE` - creates a `json_dispatch_*` function that
    accepts both the original and the underscorified enum value as valid input.

- An internal enum may be exposed as a simple string field instead of a Varlink
  enum type when the field is output-only and never provided or controlled by
  the user. However, such fields should avoid using dashes to prevent breaking
  changes if they are later converted into enums (see below).

- A varlink string field that has a finite set of possible values may later be
  converted into an enum without introducing a breaking change. This allows the
  interface to evolve from loosely defined string values to a more explicit and
  type-safe enumeration once the valid options are well established.
