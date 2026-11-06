#!/usr/bin/python3 -I
# PreToolUse hook: the tool call arrives as JSON on stdin, exit status 2 denies
# it and shows stderr to the agent. The arguments are the checkout and the
# kernel tree, each empty when its index is not served.
import json, os, re, shlex, sys

source, linux = (os.path.realpath(p) if p else "" for p in sys.argv[1:3])
call = json.load(sys.stdin)
tool = call.get("tool_name")
arguments = call.get("tool_input") or {}

SEARCHERS = {"grep", "egrep", "fgrep", "rg", "ag", "ack"}
C_TYPES = {"c", "cpp", "rust", "zig"}
MESSAGE = ("Recursive searches of indexed C code are denied: the semcode tools answer them in one call. "
           "The checkout and its src/ are served by the mcp__systemd__* tools, the kernel tree outside "
           "Documentation/ by the mcp__linux__* tools: find_function and find_type for a definition, "
           "find_callers, find_calls and find_callchain for the call graph, grep_functions with "
           "path_pattern for a regex over function bodies. grep stays available for single files, for the "
           "parts of the checkout outside src/, for searches restricted to other file types with --include, "
           "--glob or the glob and type parameters, and for patterns containing define, as object-like "
           "macros are not indexed.")

def below(path, top):
    return path == top or path.startswith(top + "/")

def indexed(path):
    """A directory of indexed C code: the checkout as a whole or below src/, the
    kernel tree outside Documentation/."""
    if not os.path.isdir(path):
        return False
    path = os.path.realpath(path)
    if source and (path == source or below(path, os.path.join(source, "src"))):
        return True
    if linux and below(path, linux) and not below(path, os.path.join(linux, "Documentation")):
        return True
    return False

def non_c(pattern):
    """A file pattern that selects no indexed C: a suffix other than .c, .h, .rs
    and .zig, or a build file."""
    name = os.path.basename(pattern)
    if "{" in name or re.search(r"\.(c|h|rs|zig)$", name):
        return False
    return bool(re.search(r"\.[A-Za-z0-9_]+$", name) or re.fullmatch(r"(Makefile|Kconfig|Kbuild)\*?", name))

def deny():
    print(MESSAGE, file=sys.stderr)
    sys.exit(2)

def resolve(path, base):
    if path.startswith("/") or not base:
        return path
    return os.path.join(base, path)

def check(operands, base):
    for operand in operands:
        if indexed(resolve(operand.split("*", 1)[0], base)):
            deny()

if tool == "Grep":
    glob = arguments.get("glob") or ""
    kind = arguments.get("type") or ""
    path = arguments.get("path") or ""
    if glob and non_c(glob):
        sys.exit(0)
    if kind and kind not in C_TYPES:
        sys.exit(0)
    if path and indexed(path):
        deny()
    sys.exit(0)

if tool != "Bash":
    sys.exit(0)

command = arguments.get("command") or ""
if "define" in command.lower():
    sys.exit(0)

# One list of words per simple command, split at the shell's separators. A
# segment after a pipe reads it instead of files.
lexer = shlex.shlex(command.replace("\\\n", " ").replace("\n", " ; "), posix=True, punctuation_chars=True)
lexer.whitespace_split = True
try:
    tokens = list(lexer)
except ValueError:
    sys.exit(0)

segments, words, piped = [], [], False
skip = False
for token in tokens:
    if skip:
        skip = False
        continue
    if token in ("|", "|&", ";", "&", "&&", "||"):
        if words:
            segments.append((words, piped))
        words, piped = [], token in ("|", "|&")
    elif token in ("(", ")"):
        continue
    elif "<" in token or ">" in token:
        skip = True  # the redirection's target
    else:
        words.append(token)
if words:
    segments.append((words, piped))

cwd = ""
previous = []
for words, piped in segments:
    if words[0] == "cd":
        cwd = resolve(words[1], cwd) if len(words) > 1 else ""
        previous = words
        continue
    base, recursive, rest = cwd, True, None
    if "git" in words:
        at = words.index("git")
        tail = words[at + 1:]
        while tail and tail[0].startswith("-"):
            if tail[0] == "-C" and len(tail) > 1:
                base = resolve(tail[1], cwd)
                tail = tail[2:]
            elif tail[0].startswith("-C"):
                base = resolve(tail[0][2:], cwd)
                tail = tail[1:]
            else:
                tail = tail[1:]
        if tail and tail[0] == "grep":
            rest = tail[1:]
    if rest is None:
        found = [i for i, word in enumerate(words) if word in SEARCHERS]
        if not found:
            previous = words
            continue
        recursive = words[found[0]] not in ("grep", "egrep", "fgrep")
        rest = words[found[0] + 1:]
    # The first word that is not an option is the pattern unless -e or -f gave
    # it, the rest are the files. A search restricted to other file types is
    # not one semcode answers.
    operands, expect, pattern, restricted, selects_c = [], "", False, False, False
    for word in rest:
        if expect == "filepattern":
            restricted, selects_c, expect = True, selects_c or not non_c(word), ""
        elif expect == "filetype":
            restricted, selects_c, expect = True, selects_c or word in C_TYPES, ""
        elif expect in ("regexp", "patternfile"):
            pattern, expect = True, ""
        elif word.startswith(("--include=", "--glob=")):
            restricted, selects_c = True, selects_c or not non_c(word.split("=", 1)[1])
        elif word.startswith("-g") and len(word) > 2:
            restricted, selects_c = True, selects_c or not non_c(word[2:])
        elif word.startswith("--type="):
            restricted, selects_c = True, selects_c or word[7:] in C_TYPES
        elif word.startswith("-t") and len(word) > 2:
            restricted, selects_c = True, selects_c or word[2:] in C_TYPES
        elif word in ("--include", "--glob", "-g"):
            expect = "filepattern"
        elif word in ("-t", "--type"):
            expect = "filetype"
        elif word in ("-e", "--regexp"):
            expect = "regexp"
        elif word in ("-f", "--file"):
            expect = "patternfile"
        elif word.startswith(("--regexp=", "--file=", "-e", "-f")) and len(word) > 2:
            pattern = True
        elif word in ("--recursive", "--dereference-recursive"):
            recursive = True
        elif word.startswith("--"):
            pass
        elif word.startswith("-") and len(word) > 1:
            if re.search(r"[rR]", word):
                recursive = True
        elif pattern:
            operands.append(word)
        else:
            pattern = True
    if restricted and not selects_c:
        previous = words
        continue
    if not operands:
        # Without files a recursive search covers its directory, any other
        # reads its input. A find piped into it names the files.
        if piped and previous and previous[0] == "find":
            check([w for w in previous[1:] if not w.startswith("-")][:1] or ["."], cwd)
        elif recursive and not piped:
            check([base or "."], "")
    else:
        check(operands, base)
    previous = words
sys.exit(0)
