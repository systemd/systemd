# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository. Only add
instructions to this file if you've seen an AI agent mess up that particular bit of logic in practice.

## Legal

 - Only human beings can ever be credited within commit messages. This means no Co-Developed-By or
   Co-Authored-By or anything similar that lists an AI model instead of a human being.

## Key Documentation

Always consult these files as needed:

- `docs/ARCHITECTURE.md` — code organization and component relationships
- `docs/HACKING.md` — development workflow with mkosi
- `docs/CODING_STYLE.md` — full style guide (must-read before writing code)
- `docs/CONTRIBUTING.md` — contribution guidelines and PR workflow

## Running arbitrary commands

- Never use `mkosi box` to wrap commands. You are either already running inside an mkosi box environment or
running outside of it — use the tools available in your current environment directly.

## Build and Test Commands

- Never compile individual files. Always run `meson compile -C build <target>` to build the target you're
working on. Meson handles incremental compilation automatically.
- Never run `meson compile` followed by `meson test` as separate steps. Always run
`meson test -C build -v <TEST-NAME>` directly. Meson will automatically rebuild any required targets before
running tests.
- Never invent your own build commands or try to optimize the build process.
- Never use `head`, `tail`, or pipe (`|`) the output of build or test commands. Always let the full output
display. This is critical for diagnosing build and test failures.

## Integration Tests

- Never use `grep -q` in pipelines; use `grep >/dev/null` instead (avoids `SIGPIPE`)
