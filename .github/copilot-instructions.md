# systemd AI Coding Agent Instructions

## Project Overview

systemd is a system and service manager for Linux, written in C (GNU17 with extensions). The project is built with Meson and consists of ~140 components including PID 1, journald, udevd, networkd, and many other system daemons.

## Key Files & Directories

Always include the following files in the context:

- [code organization details](../docs/ARCHITECTURE.md)
- [development workflow deep dive](../docs/HACKING.md)
- [full style guide](../docs/CODING_STYLE.md)

Include any other files from the [documentation](../docs) in the context as needed based on whether you think it might be helpful to solve your current task or help to review the current PR.

## Pull Request review instructions

- Focus on making sure the coding style is followed as documented in `docs/CODING_STYLE.md`
- Only leave comments for logic issues if you are very confident in your deduction
- Frame comments as questions
- Always consider you may be wrong
- Do not argue with contributors, assume they are right unless you are very confident in your deduction
- Be extremely thorough. Every single separate coding style violation should be reported

## Testing Expectations

- Unit tests for self contained functions with few dependencies
- Integration tests for system-level functionality
- CI must pass (build + unit + integration tests)
- Code coverage tracked via Coveralls

## Integration with Development Tools

- **clangd**: Use `mkosi.clangd` script to start a C/C++ LSP server for navigating C source and header files. Run `mkosi -f box -- meson setup build && mkosi -f box -- meson compile -C build gensources` first to prepare the environment.

## AI Contribution Disclosure

Per project policy: If you use AI code generation tools, you **must disclose** this in commit messages and PR descriptions. All AI-generated output requires thorough human review before submission.
