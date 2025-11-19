# This file does preprocessing before Sphinx is run on the rst files.

# Its main purpose is

# Preprocessing steps:
# 1. Global variable replacement. While there are several
# ways to achieve this in Sphinx (global_substitutions extension or the
# rst_prolog replacements feature of Sphinx), these cannot handle substitutions
# _within_ other formatting, because rst does not support nested inline markup.
# we take all global variables from the `global_substitutions` in
# conf.py and apply them to the rst files before they get handed to Sphinx.
# This way, we can have formatted, globally substituted variables.
#
# 2. Parse our custom include syntax:
# `%% include="standard-specifiers.rst" id="A" %%`
# This is used for block-level includes inside tables, which rst cannot do
# natively.


#!/usr/bin/env python3
import os
import re
import sys
import shutil
import importlib.util

# regex to match: %% include="filename" id="X" %%
INCLUDE_RE = re.compile(
    r'(?P<indent>[ \t]*)%%\s*include="(?P<file>[^"]+)"\s*id="(?P<id>[^"]+)"\s*%%'
)

# regex to locate snippet boundaries inside the include file
START_RE = r"\.\. inclusion-marker-do-not-remove\s+{id}\b"
END_RE   = r"\.\. inclusion-end-marker-do-not-remove\s+{id}\b"

def extract_all_snippet_ids(file_text: str) -> list[str]:
    """
    Scan a snippet file and return a list of all IDs that are defined inside it.
    """
    pat = re.compile(r"\.\. inclusion-marker-do-not-remove\s+([A-Za-z0-9_-]+)\b")
    return pat.findall(file_text)

def extract_snippet(include_file_path: str, snippet_id: str, source_file: str) -> str:
    """
    Extract the snippet content between markers for snippet_id in include_file_path.
    """
    with open(include_file_path, "r", encoding="utf-8") as f:
        text = f.read()

    start_pat = re.compile(START_RE.format(id=re.escape(snippet_id)))
    end_pat   = re.compile(END_RE.format(id=re.escape(snippet_id)))

    start_match = start_pat.search(text)
    if not start_match:
        print(f"WARNING: Snippet start marker not found: file={include_file_path}, id={snippet_id}, referenced in {source_file}")
        return ""

    end_match = end_pat.search(text, start_match.end())
    if not end_match:
        print(f"WARNING: Snippet end marker not found: file={include_file_path}, id={snippet_id}, referenced in {source_file}")
        return ""

    snippet = text[start_match.end() : end_match.start()]
    return snippet.strip("\n")

def expand_custom_includes(text: str, search_paths: list[str], source_file: str) -> str:
    """
    Replace all %% include="file" id="X" %% markers.

    Additionally keeps track of:
      - which snippet IDs *exist* in each include file
      - which snippet IDs are actually *used*
    """

    # Cache snippet files
    file_text_cache = {}
    file_snippet_ids = {}  # {filepath: set(ids in file)}
    used_ids = {}          # {filepath: set(used ids)}

    def resolve_path(filename: str) -> str:
        """
        Search for a file in all search_paths.
        Return full path or raise if not found.
        """
        for dir_ in search_paths:
            candidate = os.path.join(dir_, filename)
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)

        raise FileNotFoundError(
            f"Could not locate snippet file '{filename}' "
            f"in search paths: {search_paths}"
        )

    def load_file(filename):
        full_path = resolve_path(filename)
        if full_path not in file_text_cache:
            with open(full_path, "r", encoding="utf-8") as f:
                text = f.read()
            file_text_cache[full_path] = text
            # Extract defined snippet IDs
            file_snippet_ids[full_path] = set(extract_all_snippet_ids(text))
            used_ids[full_path] = set()
        return full_path

    def replacement(match: re.Match) -> str:
        indent = match.group("indent")
        inc_file = match.group("file")
        inc_id   = match.group("id")

        include_path = load_file(inc_file)
        used_ids[include_path].add(inc_id)

        snippet = extract_snippet(include_path, inc_id, source_file)
        indented = "\n".join(indent + line for line in snippet.splitlines())
        return indented

    # Perform the replacements
    result = INCLUDE_RE.sub(replacement, text)

    return result

def load_conf_py(conf_path: str):
    """Dynamically import a Sphinx conf.py file."""
    spec = importlib.util.spec_from_file_location("conf", conf_path)
    conf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(conf)
    return conf

def copy_and_replace(src_dir: str, dst_dir: str, variables: dict):
    """Copy the full directory and perform replacements only in .rst files."""
    if os.path.exists(dst_dir):
        shutil.rmtree(dst_dir)
    shutil.copytree(src_dir, dst_dir)

    print('--------------------------------------------------------------------')

    replaced_files = 0
    total_files = 0
    for root, _, files in os.walk(dst_dir):
        for name in files:
            if not name.endswith(".rst"):
                continue
            total_files += 1
            path = os.path.join(root, name)
            with open(path, "r", encoding="utf-8") as f:
                original_text = f.read()
            new_text = original_text
            for key, val in variables.items():
                new_text = new_text.replace(f'|{key}|', str(val))
                new_text = expand_custom_includes(new_text, search_paths=[
                    "source/docs/includes",  # primary
                    "source/docs",           # fallback
                ], source_file=name)
            if new_text != original_text:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(new_text)
                replaced_files += 1
                print(f'RST Preprocessor: preprocessed {name}')

    print('--------------------------------------------------------------------')
    print('Preprocessing complete:')
    print(f"- Processed {total_files} .rst file(s), performed substitutions in {replaced_files} file(s).")

def main():
    print(sys.argv)
    if len(sys.argv) != 4:
        print("Usage: preprocess_rst.py <source_dir> <conf_py_path> <output_dir>")
        sys.exit(1)

    src_dir, conf_py_path, dst_dir = sys.argv[1], sys.argv[2], sys.argv[3]
    conf = load_conf_py(conf_py_path)

    if not hasattr(conf, "global_substitutions"):
        print("Error: conf.py must define a global_substitutions dict.")
        sys.exit(1)

    copy_and_replace(src_dir, dst_dir, conf.global_substitutions)
    print(f"- Processed {len(conf.global_substitutions)} substitutions from conf.py.")
    print('--------------------------------------------------------------------')

if __name__ == "__main__":
    main()
