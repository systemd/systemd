# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Project Overview

systemd is a system and service manager for Linux, written in C (GNU17 with extensions). The project is built with Meson and consists of ~140 components including PID 1, journald, udevd, networkd, and many other system daemons.

## Key Documentation

Always consult these files as needed:

- `docs/ARCHITECTURE.md` — code organization and component relationships
- `docs/HACKING.md` — development workflow with mkosi
- `docs/CODING_STYLE.md` — full style guide (must-read before writing code)
- `docs/CONTRIBUTING.md` — contribution guidelines and PR workflow

## Build and Test Commands

**CRITICAL: Read and follow these instructions exactly.**

- **NEVER** compile individual files or targets. **ALWAYS** run `mkosi -f box -- meson compile -C build` to build the entire project. Meson handles incremental compilation automatically.
- **NEVER** run `meson compile` followed by `meson test` as separate steps. **ALWAYS** run `mkosi -f box -- meson test -C build -v <TEST-NAME>` directly. Meson will automatically rebuild any required targets before running tests.
- **NEVER** invent your own build commands or try to optimize the build process.
- **NEVER** use `head`, `tail`, or pipe (`|`) the output of build or test commands. Always let the full output display. This is critical for diagnosing build and test failures.

```sh
# Initial setup (one-time)
mkosi -f genkey
mkosi -f box -- meson setup build

# Build everything
mkosi -f box -- meson compile -C build

# Run a specific unit test (also rebuilds as needed)
mkosi -f box -- meson test -C build -v <TEST-NAME>

# Run all unit tests
mkosi -f box -- meson test -C build --print-errorlogs -q

# Build and boot an OS image for integration testing
mkosi -f box -- meson compile -C build mkosi
mkosi boot       # nspawn
mkosi vm          # qemu
```

- **CORRECT**: `mkosi -f box -- meson test -C build -v <TEST-NAME>`
- **WRONG**: Separate compile then test steps
- **WRONG**: `mkosi -f box -- meson compile -C build src/core/systemd` (individual target)
- **WRONG**: `mkosi -f box -- meson test -C build -v <TEST-NAME> 2>&1 | tail -100` (piped output)

## Code Architecture

### Shared Code Dependency Hierarchy (strict layering)

```
src/fundamental/    → no dependencies (used in EFI + userspace)
       ↑
src/basic/          → depends only on fundamental (userspace only)
       ↑
src/libsystemd/     → depends on basic + fundamental (public libsystemd.so)
       ↑
src/shared/         → depends on all above (libsystemd-shared-<nnn>.so)
       ↑
src/<component>/    → individual daemons and tools
```

Code should be linked as few times as possible. Place shared code at the lowest possible layer.

### Key Components

- `src/core/` — PID 1 service manager (system and user instances). Uses `systemd-executor` for process spawning via `posix_spawn()` to avoid fork+exec pitfalls.
- `src/udev/` — udev daemon and udevadm tool
- `src/journal/` — journald logging daemon
- `src/network/` — networkd network manager
- `src/resolve/` — resolved DNS resolver
- `src/login/` — logind session manager
- `src/boot/` — systemd-boot EFI bootloader
- `src/systemctl/`, `src/journalctl/`, `src/analyze/` — CLI tools

### Unit Settings Implementation

Adding a new unit setting requires changes in various places:
1. `src/core/load-fragment-gperf.gperf.in` + `src/core/load-fragment.c` — unit file parsing
1. `src/core/dbus-*.c` — D-Bus interface
1. `src/core/varlink-*.c` — Varlink interface
1. `src/shared/bus-unit-util.c` — client-side parsing for systemctl/systemd-run
1. `test/fuzz/fuzz-unit-file/` — add to fuzz corpus

### Tests

- **Unit tests**: `src/test/` — match source files (e.g., `src/test/test-path-util.c` tests `src/basic/path-util.c`). Use assertion macros from `tests.h` (`ASSERT_GE()`, `ASSERT_OK()`, `ASSERT_OK_ERRNO()` for glibc calls).
- **Fuzzers**: `src/fuzz/` for basic/shared code; next to component code otherwise. Input samples in `test/fuzz/`.
- **Integration tests**: `test/TEST-*` directories, run via systemd-nspawn or qemu.

## Coding Style (Essential Rules)

The full style guide is in `docs/CODING_STYLE.md`. Key rules:

### Formatting
- 8-space indent (no tabs) for C; 4-space for shell scripts; 2-space for man pages (XML)
- ~109 character line limit
- Opening brace on same line: `void foo() {`
- Function parameters with double indent (16 spaces) when broken across lines
- Single-line `if` blocks without braces
- `/* comments */` for committed code; `//` reserved for temporary debug comments
- Pointer in return types: `const char* foo()` (star with type)
- Pointer in parameters: `const char *input` (star with name)
- Casts: `(const char*) s` (space before `s`, not after `*`)

### Naming and Structure
- Structs: `PascalCase`; variables/functions: `snake_case`
- Return parameters prefixed `ret_` (success) or `reterr_` (failure)
- Command-line globals prefixed `arg_`
- Enum flags: use `1 << N` expressions, aligned vertically
- Non-flag enums: include `_FOO_MAX` and `_FOO_INVALID = -EINVAL` sentinels
- Commit messages: prefix with component name (e.g., `journal: `, `nspawn: `)

### Error Handling
- Return negative errno values: `return -EINVAL`
- Use `RET_NERRNO()` to convert libc-style returns
- Combined log+return: `return log_error_errno(r, "Failed to ...: %m")`
- Use `SYNTHETIC_ERRNO()` for errors not from a called function
- Cast ignored errors to void: `(void) unlink("/foo/bar")`
- Always check OOM; use `log_oom()` in program code

### Header Files
- Keep headers lean — prefer implementations in `.c` files
- Include the appropriate forward declaration header (`basic-forward.h`, `sd-forward.h`, `shared-forward.h`) instead of pulling in full headers
- Order: external headers (`<>`), then `sd-*` headers, then internal headers, alphabetically within each group
- No circular header dependencies

### Memory and Types
- Use `_cleanup_free_` and friends for automatic cleanup
- Use `alloca_safe()`, `strdupa_safe()` instead of raw `alloca()`, `strdupa()`
- Never use `off_t`; use `uint64_t` instead
- Use `unsigned` not `unsigned int`; `uint8_t` for bytes, not `char`

### Functions to Avoid
- `memset` → use `memzero()` or `zero()`
- `strcmp`/`strncmp` → use `streq()` / `strneq()`
- `strtol`/`atoi` → use `safe_atoli()`, `safe_atou32()`, etc.
- `basename`/`dirname` → use `path_extract_filename()` / `path_extract_directory()`
- `fgets` → use `read_line()`
- `exit()` → use `return` from main or `_exit()` in forked children
- `dup()` → use `fcntl(fd, F_DUPFD_CLOEXEC, 3)`
- `htonl`/`htons` → use `htobe32()` / `htobe16()`

### File Descriptors
- Always use `O_CLOEXEC` / `SOCK_CLOEXEC` / `MSG_CMSG_CLOEXEC` / ...

### Logging
- Library code (`src/basic/`, `src/shared/`): never log (except `LOG_DEBUG`)
- "Logging" functions log errors themselves; "non-logging" functions expect callers to log
- Non-fatal warnings: suffix with `, ignoring: %m"` or similar

### Integration Tests
- Never use `grep -q` in pipelines; use `grep >/dev/null` instead (avoids `SIGPIPE`)

## Pull Request Review Instructions

- Focus on coding style compliance from `docs/CODING_STYLE.md`
- Only leave comments for logic issues if you are very confident in your deduction
- Frame comments as questions
- Always consider you may be wrong
- Do not argue with contributors; assume they are right unless you are very confident
- Be extremely thorough — every single coding style violation should be reported

## AI Contribution Disclosure

Per project policy: if you use AI code generation tools, you **must disclose** this in commit messages by adding e.g. `Co-developed-by: Claude <claude@anthropic.com>`. All AI-generated output requires thorough human review before submission.
