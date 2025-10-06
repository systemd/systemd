# systemd AI Coding Agent Instructions

## Project Overview

systemd is a system and service manager for Linux, written in C (GNU17 with extensions). The project is built with Meson and consists of ~140 components including PID 1, journald, udevd, networkd, and many other system daemons.

## Code Organization (src/)

The dependency hierarchy (bottom to top):
- `src/fundamental/` → EFI + userspace primitives, depends on nothing
- `src/basic/` → Userspace primitives, depends only on fundamental
- `src/libsystemd/` → Public API library (`libsystemd.so`)
- `src/shared/` → Internal shared library (`libsystemd-shared-<nnn>.so`)
- Component dirs (`src/core/`, `src/journal/`, etc.) → Individual daemons/tools

**Rule**: Code in lower layers cannot use code from higher layers. Keep `src/basic/` and `src/shared/` header files lean—prefer `src/basic/forward.h` over including specific headers.

## Build & Test Workflow

Primary development loop with **mkosi**:
```fish
# First time setup
mkosi -f genkey
mkosi -f box -- meson setup build

# Development cycle
mkosi -f box -- meson compile -C build
mkosi -f box -- meson test -C build
mkosi -f box -- meson compile -C build mkosi
mkosi -f box -- meson test -C build --setup=integration TEST-01-BASIC
```

**Unit tests**: Located in `src/test/test-*.c`, use `TEST(name) { ... }` macro. Run with `meson test -C build`.

**Integration tests**: `test/TEST-*-NAME/`, run with `meson test -C build --setup=integration`. Each test boots a full system.

**Fuzzing**: Fuzzers in `src/fuzz/fuzz-*.c` with seed corpus in `test/fuzz/`. Build with `tools/oss-fuzz.sh`.

## Key Files & Directories

- `docs/ARCHITECTURE.md` → code organization details
- `docs/HACKING.md` → development workflow deep dive
- `docs/CODING_STYLE.md` → full style guide
- `meson.build` → build system root
- `.editorconfig` → editor formatting config

## Public API (`libsystemd.so`)

- **Never break ABI/API compatibility**
- Use **ISO C89** only in public header files (no C99/C11 features)
- Add new interfaces instead of changing existing ones
- Mark deprecated with `__attribute__((deprecated))`

## Testing Expectations

- Unit tests for self contained functions with few dependencies
- Integration tests for system-level functionality
- CI must pass (build + unit + integration tests)
- Code coverage tracked via Coveralls

## Common Pitfalls

- **Circular header deps**: Use `forward.h` and forward declarations
- **Breaking `ret_*` contract**: Never modify success outputs on error
- **Missing cleanup attributes**: Results in memory leaks
- **Threading**: Threads are not used in systemd at all
- **Log after error**: Use `log_*_errno()` which returns the error for easy propagation
- **Unit file syntax**: Remember to add to all three locations (gperf, dbus, cli)

## Integration with Development Tools

- **clangd**: Use `mkosi.clangd` script for LSP in mkosi environment
- **VSCode debugging**: Use `mkosi ssh` for remote debugging, see `docs/HACKING.md`
- **CI mirrors**: PRs run on Ubuntu autopkgtest, Semaphore CI, Coverity, OSS-Fuzz

## License & Headers

- Code: **LGPL-2.1-or-later** (exceptions noted in `LICENSES/README.md`)
- All files must have SPDX header: `/* SPDX-License-Identifier: LGPL-2.1-or-later */`

## AI Contribution Disclosure

Per project policy: If you use AI code generation tools, you **must disclose** this in commit messages and PR descriptions. All AI-generated output requires thorough human review before submission.
