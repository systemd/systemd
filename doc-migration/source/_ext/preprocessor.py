from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Dict, List

from docutils.parsers.rst import Directive
from docutils import nodes

from sphinx.util import logging

logger = logging.getLogger(__name__)

# This file does preprocessing before Sphinx parses the rst files.

# Preprocessing steps:

# 1. Global variable replacement. While there are several
# ways to achieve this in Sphinx (global_substitutions extension or the
# rst_prolog replacements feature of Sphinx), these cannot handle substitutions
# _within_ other formatting, because rst does not support nested inline markup.
# we take all global variables from the `global_substitutions` in
# conf.py and apply them to the rst files before they parsed by Sphinx.
# This way, we can have formatted, globally substituted variables.
#
# 2. Parse our custom include syntax:
# `%% include="standard-specifiers.rst" id="A" %%`
# This is used for block-level includes inside tables etc., which rst cannot do
# natively.

#  GLOBAL SUBSTITUTIONS

def apply_global_substitutions(app, docname, source):
    """
    Perform global string replacements BEFORE Sphinx parses the document.
    Equivalent to your old preprocessor's variable rewrite step.
    """

    old_text = source[0]
    new_text = old_text
    subs: Dict[str, str] = app.config.global_substitutions

    for key, value in subs.items():
        # same semantics as before: replace |KEY| with value
        new_text = new_text.replace(f"|{key}|", value)

    if new_text != old_text:
        source[0] = new_text


#  CUSTOM INLINE INCLUDE:  %% include="file" id="X" %%

INCLUDE_RE = re.compile(
    r'(?P<indent>[ \t]*)%%\s*include="(?P<file>[^"]+)"\s*id="(?P<id>[^"]+)"\s*%%'
)

START_RE = r"\.\. inclusion-marker-do-not-remove\s+{id}(?=\s|$)"
END_RE   = r"\.\. inclusion-end-marker-do-not-remove\s+{id}(?=\s|$)"


def extract_snippet(include_path: Path, snippet_id: str) -> str:
    """Extract between inclusion markers in the include file."""
    text = include_path.read_text(encoding="utf-8")

    start_pat = re.compile(START_RE.format(id=re.escape(snippet_id)))
    end_pat   = re.compile(END_RE.format(id=re.escape(snippet_id)))

    start_match = start_pat.search(text)
    if not start_match:
        logger.warning(
            f"Start marker for snippet id '{snippet_id}' not found in '{include_path}'"
        )
        return ""

    end_match = end_pat.search(text, start_match.end())
    if not end_match:
        logger.warning(
            f"End marker for snippet id '{snippet_id}' not found in '{include_path}'"
        )
        return ""

    snippet = text[start_match.end():end_match.start()]
    return snippet.strip("\n")



def inline_include_preprocessor(app, docname, source):
    """
    Replaces %% include="..." id="..." %% patterns inline before parsing.
    """

    srcdir: Path = Path(app.env.srcdir)
    old_text = source[0]
    new_text = old_text

    def repl(match):
        indent = match.group("indent")
        filename = match.group("file")
        snippet_id = match.group("id")

        # Search paths used by your script
        for rel in ["docs/includes", "docs"]:
            path = srcdir / rel / filename
            if path.exists():
                include_path = path
                break
        else:
            raise FileNotFoundError(
                f"Could not locate snippet include file '{filename}' "
                f"in expected search paths"
            )

        snippet_text = extract_snippet(include_path, snippet_id)

        # indent-preserving
        indented = "\n".join(indent + line for line in snippet_text.splitlines())
        return indented

    new_text  = INCLUDE_RE.sub(repl, new_text)
    # Only replace if something changed
    if new_text != old_text:
        source[0] = new_text



#  EXTENSION SETUP

def setup(app):
    app.add_config_value("global_substitutions", {}, "env")

    # Order matters: do substitutions first, then include-expansion
    app.connect("source-read", apply_global_substitutions)
    app.connect("source-read", inline_include_preprocessor)

    return {
        "version": "1.0",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
