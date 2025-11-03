# Repository Guidelines

## Project Structure & Module Organization
- `src/` — core implementation (primarily C) organized by subsystem (e.g., `basic/`, `core/`, `shared/`).
- `test/` — unit and integration tests executed via Meson.
- `units/`, `presets/`, `rules.d/`, `tmpfiles.d/`, `sysctl.d/`, `network/` — default unit files and configurations.
- `docs/`, `man/` — documentation and man pages; update when behavior changes.
- `tools/` — helper scripts; `po/` — translations; `mkosi/` — image build configs.

## Build, Test, and Development Commands
- `meson setup builddir -Dtests=true` — configure a fresh build directory.
- `meson compile -C builddir` — build all targets (ninja under the hood).
- `meson test -C builddir --print-errorlogs` — run the full test suite.
- `meson install -C builddir` — install; use `DESTDIR=/path` for staged installs.
- Optional: `mkosi build` — build test images for local/system-level validation.

## Coding Style & Naming Conventions
- C code: format with `.clang-format`; check with `.clang-tidy`. Example: `clang-format -i src/*/*.c`.
- Python tooling: `ruff check`, `pylint`, `mypy`; configs in `ruff.toml`, `.pylintrc`, `mypy.ini`.
- Respect `.editorconfig` (indentation, whitespace). Prefer lower-case names; C symbols in snake_case; files typically `name-part.c`.
- Keep changes minimal; update `man/` and `docs/` when defaults or behavior change.

## Testing Guidelines
- Place tests in `test/` or adjacent subsystem test dirs; name like `test-<area>-<case>.c`.
- Run subsets: `meson test -C builddir <pattern>`.
- Enable coverage: `meson setup builddir -Db_coverage=true` and review reports.

## Commit & Pull Request Guidelines
- Use an area prefix in the subject (e.g., `core: fix ...`, `networkd: add ...`, `udev: ...`).
- Message body: concise summary, rationale, references (issues, docs, man updates).
- PRs: clear description, linked issues, relevant logs/screenshots; include tests and docs/man changes when applicable.
- Ensure CI passes; respond to review feedback promptly.

## Security & Configuration Tips
- Do not include secrets; follow least-privilege defaults.
- Validate changes under `units/`, `tmpfiles.d`, `rules.d`, `sysctl.d` for safe behavior.
- Document capability/SELinux profile changes in `docs/` and `man/`.
