#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: LGPL-2.1-or-later
"""
    DocBook to ReST converter
    =========================
    This script may not work out of the box, but is easy to extend.
    If you extend it, please send me a patch: wojdyr at gmail.

    Docbook has >400 elements, most of them are not supported (yet).
    ``pydoc db2rst`` shows the list of supported elements.

    In reST, inline markup can not be nested (major deficiency of reST).
    Since it is not clear what to do with, say,
    <subscript><emphasis>x</emphasis></subscript>
    the script outputs incorrect (nested) reST (:sub:`*x*`)
    and it is up to user to decide how to change it.

    Usage: db2rst.py file.xml > file.rst

    Ported to Python3 in 2024 by neighbourhood.ie

    :copyright: 2009 by Marcin Wojdyr.
    :license: BSD.
"""

# If this option is True, XML comment are discarded. Otherwise, they are
# converted to ReST comments.
# Note that ReST doesn't support inline comments. XML comments
# are converted to ReST comment blocks, what may break paragraphs.
from source import conf
import lxml.etree as ET
import re
import sys
import os
from pathlib import Path
import traceback

REMOVE_COMMENTS = False

# id attributes of DocBook elements are translated to ReST labels.
# If this option is False, only labels that are used in links are generated.
WRITE_UNUSED_LABELS = False


# The Files have sections that are used as includes in other files
FILES_USED_FOR_INCLUDES = [
    'bpf-delegate.xml',
    'cgroup-sandboxing.xml',
    'common-variables.xml',
    'hostname.xml',
    'importctl.xml',
    'libsystemd-pkgconfig.xml',
    'org.freedesktop.locale1.xml',
    'sd_bus_add_match.xml',
    'sd_bus_message_append_basic.xml',
    'sd_bus_message_read_basic.xml',
    'sd_journal_get_data.xml',
    'standard-conf.xml',
    'standard-options.xml',
    'standard-specifiers.xml',
    'supported-controllers.xml',
    'system-only.xml',
    'system-or-user-ns.xml',
    'system-or-user-ns-mountfsd.xml',
    'systemctl.xml',
    'systemd-resolved.service.xml',
    'systemd.link.xml',
    'systemd.mount.xml',
    'systemd.netdev.xml',
    'systemd.service.xml',
    'tc.xml',
    'threads-aware.xml',
    'timedatectl.xml',
    'unit-states.xml',
    'user-system-options.xml',
    'vpick.xml',
]

# These files are xml, but should not be parsed as they # are included as literal xml
SKIP_LITERAL_INCLUDES = [
    '../man/vtable-example.xml'
]

ALLOWED_EMPTY_TAGS = [
    'refname',
    'refpurpose'
]

# to avoid dupliate error reports
_not_handled_tags = set()

# to remember which id/labels are really needed
_linked_ids = set()

_indent_next_listItem_by = 0

_footnotes = []

# Used to improve logs
_current_filename = ''


WHITESPACE_SENSITIVE_TAGS = {
    'programlisting', 'screen', 'literallayout'
}

def local_name(elem):
    """Return the local name of an lxml element or tag (namespace-safe)."""
    if elem is None:
        return None
    tag = elem if isinstance(elem, str) else elem.tag
    try:
        return etree.QName(tag).localname
    except Exception:
        return tag

def collapse_preserve_boundaries(s):
    """
    Collapse runs of whitespace to a single space, preserving leading/trailing
    boundaries if they existed. Return None for None input.
    """
    if s is None:
        return None

    stripped = s.strip()
    if stripped == '':
        # whitespace-only text node → candidate for removal
        return None

    leading = s[0].isspace()
    trailing = s[-1].isspace()
    core = ' '.join(stripped.split())

    if leading and not core.startswith(' '):
        core = ' ' + core
    if trailing and not core.endswith(' '):
        core = core + ' '
    return core


def normalize_whitespace(elem):
    """
    Recursively normalize whitespace:
      - Collapse internal runs to single spaces.
      - Preserve word boundaries around inline tags.
      - Remove indentation-only text nodes, except keep a single space when
        needed between adjacent inline elements.
    """
    if elem is None:
        return

    tagname = local_name(elem)
    if tagname in WHITESPACE_SENSITIVE_TAGS:
        return

    # Normalize element text
    if elem.text is not None:
        elem.text = collapse_preserve_boundaries(elem.text)

    # Walk children
    for i, child in enumerate(list(elem)):
        normalize_whitespace(child)

        # Normalize tail
        if child.tail is not None:
            new_tail = collapse_preserve_boundaries(child.tail)
            if new_tail is None:
                # Check if removing this whitespace-only tail would glue inline elements together
                next_sibling = elem[i + 1] if i + 1 < len(elem) else None
                if next_sibling is not None:
                    # Add a single space to separate adjacent inline elements
                    child.tail = ' '
                else:
                    child.tail = None
            else:
                child.tail = new_tail

    # If the element’s text was only indentation, remove it
    if elem.text is not None and elem.text.strip() == '':
        # If first child is inline, keep a separating space
        if len(elem) > 0:
            elem.text = ' '
        else:
            elem.text = None


def _run(input_file, output_dir):
    global _current_filename
    if input_file in SKIP_LITERAL_INCLUDES:
        return
    _current_filename = input_file
    # sys.stderr.write("Parsing XML file `%s'...\n" % input_file)

    # Read the XML file content as string for preprocessing
    with open(input_file, 'r', encoding='utf-8') as f:
        xml_content = f.read()

    # Reformat variable syntax so we can later apply
    # the global_substitutions from conf.py.
    #
    # This means converting from `&UMOUNT_PATH;` to `|UMOUNT_PATH|`
    # We’re using these delimiters to match the syntax of Sphinx’s
    # rst_prolog replacement feature, see https://www.sphinx-doc.org/en/master/usage/configuration.html#confval-rst_prolog,
    # although we’re not actually using it. This is to future-proof the rst files
    # in case rst ever supports nested inline syntax or systemd
    # wants to move to rst_prolog for some other reason.
    # We’re playing it safe and only converting vars that are
    # actually defined, as opposed to using a regex.
    for key, value in conf.global_substitutions.items():
        xml_content = xml_content.replace(f'&{key};', f'|{key}|')

    parser = ET.XMLParser(remove_comments=REMOVE_COMMENTS, no_network=False)

    # Parse the preprocessed XML content
    tree = ET.fromstring(xml_content, parser=parser)
    # Convert back to ElementTree for compatibility with existing code
    tree = ET.ElementTree(tree)

    root = tree.getroot()
    normalize_whitespace(root)

    for elem in tree.iter():
        if elem.tag in ("xref", "link"):
            _linked_ids.add(elem.get("linkend"))

    output_file = os.path.join(output_dir, os.path.basename(
        input_file).replace('.xml', '.rst'))

    with open(output_file, 'w') as file:
        file.write(TreeRoot(tree.getroot()).encode('utf-8').decode('utf-8'))

def _warn(s):
    sys.stderr.write(f"WARNING ⎹ {_current_filename}:\n")
    sys.stderr.write(f"        ↳ {s}\n")


def _supports_only(el, tags):
    "print warning if there are unexpected children"
    for i in el:
        if i.tag not in tags:
            _warn("%s/%s skipped." % (el.tag, i.tag))


def _what(el):
    "returns string describing the element, such as <para> or Comment"
    if isinstance(el.tag, str):
        return "<%s>" % el.tag
    elif isinstance(el, ET._Comment):
        return "Comment"
    else:
        return str(el)


def _has_only_text(el):
    "print warning if there are any children"
    if list(el):
        _warn("children of %s are skipped: %s" % (_get_path(el),
                                                  ", ".join(_what(i) for i in el)))


def _has_no_text(el):
    "print warning if there is any non-blank text"
    if el.text is not None and not el.text.isspace():
        _warn("skipping text of <%s>: %s" % (_get_path(el), el.text))
    for i in el:
        # Skip complaining about these tails, we handle them elsewhere
        if i.tag == "replaceable":
            continue
        if i.tag == "emphasis":
            continue
        # The skipped tail here is usually a comma, we add that in simplelist
        if i.tag == 'member' and _is_inside_of(i, "simplelist"):
            continue
        # arg elements handle their tails themselves
        if i.tag == 'option':
            parent = i.getparent()
            choice = parent.get("choice")
            if parent.tag == 'arg' and choice == 'plain' and len(parent.getchildren()) > 0:
                continue
        if i.tail is not None and not i.tail.isspace():
            _warn("skipping tail of <%s>: %s" % (_get_path(i), i.tail))

# rst doesn’t do in-place footnotes, so we need to generate the actual
# include statement in the footnote section, while _include below
# replaces the xi:include statement with a footnote anchor link, [#]_
def _add_standard_conf_footnote():
    new_footnote = ET.Element('{http://www.w3.org/2001/XInclude}include', attrib={"href": "standard-conf.xml", "xpointer": "usr-local-footnote"})
    _footnotes.append(new_footnote)

def _includes(el):
    # There is a single file (standard-conf.xml) that includes bits of itself,
    # but this is actually a footnote… and rst doesn’t do inline footnotes.
    if not el.get('href'):
        return "[#]_"
    # Some files _just_ include the footnote, but not the surrounding section
    if el.get('xpointer') == "usr-local-footnote":
        _add_standard_conf_footnote()
        return "[#]_"
    file_path_pathlib = Path(el.get('href'))
    file_extension = file_path_pathlib.suffix
    # If th above standard-conf.xml include happens, also include the footnote # from that file to the footnotes section
    if file_path_pathlib.match("standard-conf.xml"):
        xpointer = el.get('xpointer')
        if xpointer in ['conf', 'confd', 'main-conf']:
            _add_standard_conf_footnote()
    include_files = FILES_USED_FOR_INCLUDES
    if file_extension == '.xml':
        if el.get('href') == 'version-info.xml':
            versionString = conf.global_substitutions.get(
                el.get("xpointer"))
            return f"\n\n.. only:: html\n\n   \n\n   .. versionadded:: {versionString}\n \n \n"
        elif not el.get("xpointer"):
            if el.get("parse") == 'text':
                # Handle literal xml includes
                return f".. literalinclude:: {el.get('href')}"
            return f".. include:: {el.get('href').replace('xml', 'rst')}"
        elif el.get('href') in include_files:
            return f""".. include:: {el.get('href').replace('xml', 'rst')}
    :start-after: .. inclusion-marker-do-not-remove {el.get("xpointer")}
    :end-before: .. inclusion-end-marker-do-not-remove {el.get("xpointer")}

"""

    elif file_extension == '.c':
        return f"""

.. literalinclude:: /code-examples/c/{el.get('href')}
    :language: c

"""
    elif file_extension == '.py':
        return f"""

.. literalinclude:: /code-examples/py/{el.get('href')}
    :language: python

"""
    elif file_extension == '.sh':
        return f"""

.. literalinclude:: /code-examples/sh/{el.get('href')}
    :language: shell

"""
    else:
        return f"""

.. literalinclude:: /code-examples/{el.get('href')}

"""
        return


def _conv(el):
    "element to string conversion; usually calls element_name() to do the job"
    if el.tag in globals():
        s = globals()[el.tag](el)
        if el.tag not in ALLOWED_EMPTY_TAGS:
            assert s, "Error: %s -> None\n" % _get_path(el)
        return s
    elif isinstance(el, ET._Comment):
        return Comment(el) if (el.text and not el.text.isspace()) else ""
    else:
        if el.tag not in _not_handled_tags:
            # TODO: this seems to happen more often than plausible
            if el.tag == "{http://www.w3.org/2001/XInclude}include":
                return _includes(el)
            else:
                _warn("Don't know how to handle <%s>" % el.tag)
                _warn(" ... from path: %s" % _get_path(el))
                _not_handled_tags.add(el.tag)
        return _concat(el)


def _no_special_markup(el):
    return _concat(el)


def _remove_indent_and_escape(s, tag):
    # return s
    if tag == "programlisting":
        return s
    # if tag != "para":
    #     return s
    "remove indentation from the string s, escape some of the special chars"
    s = "\n".join(i.lstrip().replace("\\", "\\\\") for i in s.splitlines())
    # escape inline mark-up start-string characters (even if there is no
    # end-string, docutils show warning if the start-string is not escaped)
    # TODO: handle also Unicode: ‘ “ ’ « ¡ ¿ as preceding chars
    s = re.sub(r"([\s'\"([{</:-])"  # start-string is preceded by one of these
               r"([|*`[])"  # the start-string
               r"(\S)",    # start-string is followed by non-whitespace
               r"\1\\\2\3",  # insert backslash
               s)
    return s


def _concat(el, prefix=""):
    "concatate .text with children (_conv'ed to text) and their tails"
    s = prefix
    id = el.get("id")
    if id is not None and (WRITE_UNUSED_LABELS or id in _linked_ids):
        s += "\n\n.. _%s:\n\n" % id
    if el.text is not None:
        s += _remove_indent_and_escape(el.text, el.tag)
    for i in el:
        s += _conv(i)
        if i.tail is not None:
            if len(s) > 0 and not s[-1].isspace() and i.tail[0] in " \t":
                s += i.tail[0]
            s += _remove_indent_and_escape(i.tail, el.tag)
    # return s.strip()
    return s


def _original_xml(el):
    return ET.tostring(el, with_tail=False).decode('utf-8')


def _no_markup(el):
    s = ET.tostring(el, with_tail=False).decode('utf-8')
    s = re.sub(r"<.+?>", " ", s)  # remove tags
    s = re.sub(r"\s+", " ", s)  # replace all blanks with single space
    return s


def _get_level(el):
    "return number of ancestors"
    return sum(1 for i in el.iterancestors())

def _get_title_level(el):
    "return number of title ancestors"
    return sum(1 for i in el.iterancestors("title"))


def _get_path(el):
    t = [el] + list(el.iterancestors())
    return "/".join(str(i.tag) for i in reversed(t))


def _make_title(t, level, indentLevel=0):
    t = t.replace('\n', ' ').strip()

    if level == 1:
        return "\n\n" + "=" * len(t) + "\n" + t + "\n" + "=" * len(t) + "\n\n"

    char = ["#", "=", "-", "~", "^", "."]
    underline = char[level-2] * len(t)
    indentation = " "*indentLevel
    return f"\n\n{indentation}{t}\n{indentation}{underline}"


def _join_children(el, sep):
    _has_no_text(el)
    return sep.join(_conv(i) for i in el)


def _block_separated_with_blank_line(el, stripInnerLinebreaks = False):
    s = ""
    id = el.get("id")
    if id is not None:
        s += f"\n\n.. inclusion-marker-do-not-remove {id}\n \n "
    if stripInnerLinebreaks:
        s += "\n\n" + _remove_line_breaks(_concat(el))
    else:
        s += "\n\n" + _concat(el)
    if id is not None:
        s += f"\n \n.. inclusion-end-marker-do-not-remove {id}\n\n"
    return s


def _indent(el, indent, first_line=None, suppress_blank_line=False):
    "returns indented block with exactly one blank line at the beginning"
    start = "\n\n"
    if suppress_blank_line:
        start = ""

    # lines = [" "*indent + i for i in _concat(el).splitlines()
    #         if i and not i.isspace()]
    # TODO: This variant above strips empty lines within elements. We don’t want that to happen, at least not always
    lines = [" "*indent + i for i in _concat(el).splitlines()
             if i]
    if first_line is not None:
        # replace indentation of the first line with prefix `first_line'
        lines[0] = first_line + lines[0][indent:]
    return start + "\n".join(lines)


def _normalize_whitespace(s):
    return " ".join(s.split())

def _is_inside_of(el, tagname):
    isInsideTag = False
    for ancestor in el.iterancestors(tag=tagname):
        isInsideTag = True
    return isInsideTag

def _remove_line_breaks(s):
    return s.replace('\n', ' ').replace('\r', '').strip()

def _get_listitem_depth(el):
    """Calculate the nesting depth of listitem ancestors for an element.
    Returns 0 if not inside any listitem, 1 for first-level list, 2 for nested, etc."""
    depth = 0
    # If the parent is a varlistentry, always indent
    if _is_inside_of(el, 'varlistentry'):
        depth = 1
    for ancestor in el.iterancestors():
        if ancestor.tag == 'listitem':
            depth += 1
    return depth

###################           DocBook elements        #####################

# special "elements"


def TreeRoot(el):
    output = _conv(el).lstrip()
    # add .. SPDX-License-Identifier: LGPL-2.1-or-later
    output = f'.. SPDX-License-Identifier: LGPL-2.1-or-later\n\n{output}'
    # remove trailing whitespace
    output = re.sub(r"[ \t]+\n", "\n", output)
    # leave only one blank line
    output = re.sub(r"\n{3,}", "\n\n", output)
    if len(_footnotes) > 0:
        output += "\n\n.. rubric:: Footnotes"
        for index, footnote in enumerate(_footnotes, start=1):
            # If this footnote is an include, convert to our custom
            # preprocessor include, since rst also has trouble with
            # these block level includes inside footnotes.
            if footnote.get('href'):
                output += f'\n\n.. [#] %% include="{footnote.get('href').replace('xml', 'rst')}" id="{footnote.get('xpointer')}" %%'
            else:
                # output += f"\n\n.. [#] {_remove_line_breaks(_conv(footnote))}"
                output += f"\n\n.. [#] {_conv(footnote)}"
    # Reset footnotes list after rendering them
    _footnotes.clear()
    return output + '\n'


def Comment(el):
    # Keep block-level comments, warn for inline comments, since
    # rst doesn’t have those.
    # These are tricky to keep apart. Since the only two inline
    # comments we found were ` no / ` in "standard-specifiers.xml",
    # we’re skipping those explicitly.
    if el.text == ' no / ':
        _warn(f"skipping inline comment in {_get_path(el)}, content: '{el.text}'")
        return "  "
    return _indent(el, 3, ".. COMMENT: ") + "\n\n"

# Meta refs


def refentry(el):
    return _concat(el)


def refentryinfo(el):
    # ignore
    return '  '


def refnamediv(el):
    # TODO: check man vs html, seems like this one is difficult to get right in both at the same time
    # TODO: needs more work:
    # - collect refnames and _join_children(el, ' —,')
    # - append refpurpose, separated by an em-dash, and strip line breaks
    #   beforehand with t.replace('\n', ' ').strip()
    # return '**Name** \n\n' + _make_title(_join_children(el, ' — '), 2)
    # return '.. only:: html\n\n' + _make_title(_join_children(el, ' — '), 2, 3)
    refnames = []
    for refname in el.iterchildren(tag='refname'):
        refnames.append(refname.text)
    purpose = el.find('refpurpose').text
    if refnames is None or purpose is None:
        return "  "
    return f"""
Name
####

{', '.join(refnames)} — {purpose}
"""


def refsynopsisdiv(el):
    # return '**Synopsis** \n\n' + _make_title(_join_children(el, ' '), 3)
    s = ""
    s += _make_title('Synopsis', 2, 0)
    s += '\n\n'
    # s += _join_children(el, ', ')
    # changed to accomodate man/systemd-dissect.xml
    # TODO: does this break anything anywhere else?
    s += _join_children(el, '\n\n')
    return s


def refname(el):
    _has_only_text(el)
    return "%s" % el.text


def refpurpose(el):
    return _concat(el)


def cmdsynopsis(el):
    return _join_children(el, ' ')


def arg(el):
    text = el.text
    if text is None:
        text = _join_children(el, '')
    # choice: req, opt, plain
    choice = el.get("choice")
    if choice == 'opt':
        if len(el.getchildren()) == 0:
        # This if there is only text inside and an optional ´rep="repeat"´
            return f"[%s{'...' if el.get('rep') == 'repeat' else ''}]" % text
        else:
            return "[%s]" % _concat(el).strip()
    elif choice == 'req':
        return "{%s}" % text
    elif choice == 'plain':
        if len(el.getchildren()) == 0:
            return text
        else:
            # join_children will swallow any text that is present alongside children tags e.g.
            # <arg choice="plain"><option>--unit</option>|<option>--user-unit</option></arg>
            # the | will get lost, so better to use concat()
            return "%s" % _concat(el).strip()
    else:
        if choice is None:
            return "[%s]" % text
        else:
            "print warning if there another choice"
            _warn("skipping arg with choice of: %s" % (choice))


def footnote(el):
    # TODO: handle footnotes with multiple children?
    id = el.get('id')
    output = ""
    # This is a special case that shouldn’t be rendered as a footnote
    if id == "usr-local-footnote":
        output += "\n\n.. inclusion-marker-do-not-remove %s\n\n" % id
        output += _conv(el.getchildren()[0])
        output += "\n\n.. inclusion-end-marker-do-not-remove %s\n\n" % id
        return output
    _footnotes.append(el.getchildren()[0])
    return f" [#]_ "

# general inline elements

# This might run into the rst limitation that inline syntax end delimiters
# must be followed by whitespace, so
# <emphasis>PATTERN</emphasis>s
# would result in *PATTERN*s and have Sphinx throw
# WARNING: Inline emphasis start-string without end-string.
# The workaround is *PATTERN*\s
def emphasis(el):
    result = f"*{_concat(el).strip()}*"
    if el.tail and re.match(r'^\S', el.tail):
        # tail starts with a non-whitespace char → needs escaping
        result += '\\' + el.tail
    else:
        result += el.tail or ''

    return result


phrase = emphasis
citetitle = emphasis


acronym = _no_special_markup
structname = _no_special_markup
type = _no_special_markup
property = _no_special_markup

def cmdsynopsis(el):
    return "``%s``" % _concat(el).strip()

def command(el):
    # Only enclose in backticks if it’s not part of a term
    # (which is already enclosed in backticks)
    if _is_inside_of(el, 'term') or _is_inside_of(el, 'cmdsynopsis') or _is_inside_of(el, 'programlisting'):
        return _concat(el).strip()
    return "``%s``" % _concat(el).strip()

token = command
interfacename = command
classname = command
uri = command
# structfield is italic inline code in the old docs, but we can’t do that in rst
structfield = command

def literal(el):
    return "\"%s\"" % _concat(el).strip()

def quote(el):
    return "“%s”" % _concat(el).strip()


def _nearest_varlist_class(el):
    """Return the nearest enclosing variablelist class, or '' if none."""
    for varlist in el.iterancestors(tag='variablelist'):
        c = varlist.attrib.get('class', '')
        if c:
            return c
    return ''

def _nearest_directive_group(el):
    """Return the nearest ancestor whose id matches a configured group id;
    if none, return the nearest variablelist@class that matches."""
    valid_ids = {d.get('id') for d in (conf.directives_data or []) if isinstance(d, dict)}
    for anc in el.iterancestors():
        # Prefer explicit ids first (any element)
        aid = anc.attrib.get('id', '')
        if aid and aid in valid_ids:
            return aid
        # Only consider class on variablelist elements
        if anc.tag == 'variablelist':
            cid = anc.attrib.get('class', '')
            if cid and cid in valid_ids:
                return cid
    return ''

def _infer_role_type_from_name(name: str):
    """Best-effort inference of directive role type from name."""
    n = (name or '').strip()
    if not n:
        return None
    if n.startswith('$'):
        return 'var'
    if n.endswith('=') or '--' in n or n.startswith('-'):
        return 'option'
    # Constants are commonly all-caps with underscores or known prefixes
    if n.startswith('SIG') or n.startswith('AF_'):
        return 'constant'
    letters = n.replace('_', '')
    if letters and letters.upper() == letters and any(ch.isalpha() for ch in letters):
        return 'constant'
    return None

def _make_id(name: str) -> str:
    """Generate a docutils-like id from a directive name."""
    s = (name or '').strip().lower()
    # remove trailing '=' and surrounding punctuation first
    s = re.sub(r'[=]+$', '', s)
    # replace any run of non-alphanumeric with a single hyphen
    s = re.sub(r'[^0-9a-z]+', '-', s)
    # strip leading/trailing hyphens
    s = s.strip('-')
    return s

def _collect_term_names(vle):
    """Collect plain text of all term children in a varlistentry."""
    names = []
    for term in vle.iterchildren(tag='term'):
        text = _concat(term).strip()
        if text:
            names.append(text)
    return names

def varname(el):
    if _is_inside_of(el, 'term'):
        return _concat(el).strip()

    classname = _nearest_varlist_class(el)
    if classname:
        return f":directive:{classname}:var:`%s`" % _concat(el).strip()
    return "``%s``" % _concat(el).strip()


def option(el):
    if _is_inside_of(el, 'term'):
        return _concat(el).strip()
    if _is_inside_of(el, 'arg'):
        result = ""
        if el.text and re.match(r'^\--', el.text):
            result += '\\' + el.text
        else:
            result = "%s" % _concat(el).strip()
        return result

    classname = _nearest_varlist_class(el)
    if classname:
        return f":directive:{classname}:option:`%s`" % _concat(el).strip()
    return "``%s``" % _concat(el).strip()


def constant(el):
    if _is_inside_of(el, 'term'):
        return _concat(el).strip()

    classname = _nearest_varlist_class(el)
    if classname:
        return f":directive:{classname}:constant:`%s`" % _concat(el).strip()
    return "``%s``" % _concat(el).strip()


filename = command


def optional(el):
    return "[%s]" % _concat(el).strip()

group = optional

# This might also run into the rst limitation that inline syntax end delimiters
# must be followed by whitespace, so
# <replaceable>PATTERN</replaceable>s
# would result in *<PATTERN>*s and have Sphinx throw
# WARNING: Inline emphasis start-string without end-string.
# The workaround is: *<PATTERN>*\s
def replaceable(el):
    # If it’s in an arg with `choice="opt"`, it should have brackets
    if el.text is None and len(el.getchildren()) == 0:
        return " "
    isInsideArg = False
    isRepeat = False
    result = ''
    isInsideTerm = _is_inside_of(el, 'term')
    isInsideProgramlisting = _is_inside_of(el, 'programlisting')
    for arg in el.iterancestors(tag='arg'):
        if arg.get("choice") == 'opt':
            isInsideArg = True
        if arg.get("rep") == 'repeat':
            isRepeat = True
    if isInsideArg or isInsideTerm or isInsideProgramlisting:
        result = f"{_concat(el).strip()}{'...' if isRepeat else ''}"
        # result = f"*[%s{'...' if isRepeat else ''}]*" % _concat(el).strip()
    else:
        # Otherwise < >
        result = "*<%s>*" % _concat(el).strip()

    # if el.tail and re.match(r'^\S', el.tail):
    #     # tail starts with a non-whitespace char → needs escaping
    #     result += '\\' + el.tail
    # else:
    #     result += el.tail or ''

    return result


def term(el):
    if el.getparent().index(el) != 0:
        return ' '

    level = _get_level(el)
    if level > 5:
        level = 5
    # Sometimes, there are multiple terms for one entry. We want those displayed in a single line, so we gather them all up and parse them together
    hasMultipleTerms = False
    titleStrings = [_concat(el).strip()]
    title = ''
    for term in el.itersiblings(tag='term'):
        # We only arrive here if there is more than one `<term>` in the `el`
        hasMultipleTerms = True
        titleStrings.append(_concat(term).strip())

    if hasMultipleTerms:
        title = ', '.join(titleStrings)
        # return _make_title(f"``{titleString}``", 4)
    else:
        title = _concat(el).strip()

    if level >= 5:
        global _indent_next_listItem_by
        _indent_next_listItem_by += 3
        return f".. option:: {title}\n\n   \n\n   "
    return _make_title(f"``{title}``", level) + '\n\n'

# links


def ulink(el):
    url = el.get("url")
    text = _concat(el).strip()
    if text.startswith(".. image::"):
        return "%s\n   :target: %s\n\n" % (text, url)
    elif url == text:
        return text
    elif not text:
        return "`<%s>`_" % (url)
    else:
        return "`%s <%s>`_" % (text, url)

# TODO: other elements are ignored


def xref(el):
    _has_no_text(el)
    id = el.get("linkend")
    return ":ref:`%s`" % id if id in _linked_ids else ":ref:`%s <%s>`" % (id, id)


def link(el):
    _has_no_text(el)
    return "`%s`_" % el.get("linkend")

def note(el):
    return f""".. note::

   {_concat(el)}

"""

# lists

def itemizedlist(el):
    return _concat(el)


def orderedlist(el):
    return _indent(el, 2, "1. ", True)


def simplelist(el):
    type = el.get("type")
    if type == "inline":
        return _join_children(el, ', ')
    else:
        return _concat(el)


def member(el):
    parentListType = el.getparent().get("type")
    listItemPrefix = "\n| "
    if parentListType == 'inline':
        listItemPrefix = ""

    return _concat(el, listItemPrefix)

# varlists


def variablelist(el):
    generated = el.get("generated")
    if generated == "True":
        # ignore
        # Autogenerated cross-references for systemd.directives
        # TODO: they shouldn't show up but the cross-referencing we need to solve
        return '  '
    else:
        return _concat(el)


def varlistentry(el):
    s = ""
    entry_id = el.get("id")
    if entry_id is not None:
        s += "\n\n.. inclusion-marker-do-not-remove %s\n\n" % entry_id

    # Determine group once for this entry (nearest id wins, then nearest variablelist@class)
    group = _nearest_directive_group(el)
    term_names = _collect_term_names(el)
    first_term_emitted = False

    for i in el:
        if i.tag == 'term':
            if not first_term_emitted:
                # Emit one canonical label and definition marker per term ABOVE the title
                if group and term_names:
                    # Compute composite heading id to match the actual section id
                    composite_anchor = "-".join(_make_id(n) for n in term_names)
                    # Emit one definition per term, carrying the composite anchor
                    for name in term_names:
                        role_type = _infer_role_type_from_name(name)
                        s += ".. directive-def::\n"
                        s += f"   :group: {group}\n"
                        s += f"   :name: {name}\n"
                        s += f"   :anchor: {composite_anchor}\n"
                        if role_type:
                            s += f"   :type: {role_type}\n"
                        s += "\n"
                # Render the visible heading/title (first term renders title for all terms)
                s += _conv(i) + '\n\n'
                first_term_emitted = True
            else:
                # Skip subsequent term nodes; the first one already rendered a combined title
                pass
        else:
            s += _conv(i)

    if entry_id is not None:
        s += "\n\n.. inclusion-end-marker-do-not-remove %s\n\n" % entry_id
    return s


def listitem(el):
    parent = el.getparent()
    listItemPrefix = ''
    if parent.tag == 'orderedlist':
        listItemPrefix = '1.'
    if parent.tag == 'itemizedlist':
        listItemPrefix = '* '

    # Use depth-aware indentation system
    depth = _get_listitem_depth(el)

    if depth >= 1:
        # For nested list items (depth >= 1), add indentation
        # Use depth directly since we want 2 spaces per nesting level
        indent_spaces = " " * (2 * depth)
        listItemPrefix = indent_spaces + listItemPrefix

    return _concat(el, listItemPrefix)

# sections


def example(el):
    # FIXME: too hacky?
    elements = [i for i in el]
    first, rest = elements[0], elements[1:]

    return _make_title(_concat(first), 4) + "\n\n" + "".join(_conv(i) for i in rest)


def sect1(el):
    return _block_separated_with_blank_line(el)


def sect2(el):
    return _block_separated_with_blank_line(el)


def sect3(el):
    return _block_separated_with_blank_line(el)


def sect4(el):
    return _block_separated_with_blank_line(el)


def section(el):
    return _block_separated_with_blank_line(el)


def title(el):
    return _make_title(_concat(el).strip(), _get_title_level(el) + 2) + "\n\n"

# bibliographic elements


def author(el):
    _has_only_text(el)
    return "\n\n.. _author:\n\n**%s**" % el.text


def date(el):
    _has_only_text(el)
    return "\n\n.. _date:\n\n%s" % el.text

# references


def citerefentry(el):
    project = el.get("project")
    refentrytitle = el.xpath("refentrytitle")[0].text
    manvolnum = el.xpath("manvolnum")[0].text

    extlink_formats = {
        'man-pages': f':man-pages:`{refentrytitle}({manvolnum})`',
        'die-net': f':die-net:`{refentrytitle}({manvolnum})`',
        'mankier': f':mankier:`{refentrytitle}({manvolnum})`',
        'archlinux': f':archlinux:`{refentrytitle}({manvolnum})`',
        'debian': f':debian:`{refentrytitle}({manvolnum})`',
        'freebsd': f':freebsd:`{refentrytitle}({manvolnum})`',
        'dbus': f':dbus:`{refentrytitle}({manvolnum})`',
        'openssl': f':openssl:`{refentrytitle}({manvolnum})`',
    }

    if project in extlink_formats:
        return extlink_formats[project]

    if project == 'url':
        refentry = el.xpath("refentrytitle")[0]
        url = refentry.get("url")
        return f"`{refentrytitle}({manvolnum}) <{url}>`_"

    return f":ref:`{refentrytitle}({manvolnum})`"


def refmeta(el):
    refentrytitle = el.find('refentrytitle').text
    manvolnum = el.find('manvolnum').text

    meta_title = f":title: {refentrytitle}"

    meta_manvolnum = f":manvolnum: {manvolnum}"

    doc_title = ".. _%s:" % _join_children(
        el, '') + '\n\n' + _make_title(_join_children(el, ''), 1)

    return '\n\n'.join([meta_title, meta_manvolnum, doc_title])


def refentrytitle(el):
    if el.get("url"):
        return ulink(el)
    else:
        return _concat(el)


def manvolnum(el):
    return "(%s)" % el.text

# media objects


def imageobject(el):
    return _indent(el, 3, ".. image:: ", True)


def imagedata(el):
    _has_no_text(el)
    return el.get("fileref")


def videoobject(el):
    return _indent(el, 3, ".. raw:: html\n\n", True)


def videodata(el):
    _has_no_text(el)
    src = el.get("fileref")
    return '    <video src="%s" controls>\n' % src + \
        '      Your browser does not support the <code>video</code> element.\n' + \
        '    </video>'

def informalexample(el):
    # This is only used once as a wrapper around a <programlisting>
    return _conv(el.getchildren()[0])

def programlisting(el):
    # TODO: newlines at the end aren't applied properly
    xi_include = el.find('.//{http://www.w3.org/2001/XInclude}include')
    # Systemd programlistings do include child elements, so just render them
    # if len(el.getchildren()) == 0:
    if xi_include is not None:
        return _includes(xi_include)
    else:
        # Use depth-aware indentation system
        depth = _get_listitem_depth(el)

        if depth > 0:
            # Inside list context: calculate indentation based on depth
            directive_indent = " " * (2 * depth)  # 2 spaces per nesting level
            code_indent = 3 + (2 * depth)  # 3 base + 2 per nesting level
        else:
            # Not in list context: no extra indentation
            directive_indent = ""
            code_indent = 3

        return f"\n\n{directive_indent}.. code-block:: sh\n \n{_indent(el, code_indent)}\n \n"
    # else:
    #     return _concat(el)


def screen(el):
    return _indent(el, 3, "::\n\n", False) + "\n\n"


def synopsis(el):
    return _indent(el, 3, "::\n\n", False) + "\n\n"


def funcsynopsis(el):
    return _concat(el)


def funcsynopsisinfo(el):
    return "``%s``" % _concat(el)


def funcprototype(el):
    funcdef = ''.join(el.find('.//funcdef').itertext())
    params = el.findall('.//paramdef')
    param_list = [''.join(param.itertext()) for param in params]
    s = ".. code-block:: \n\n   "
    s += f"{funcdef}("
    s += ",\n\t".join(param_list)
    s += ");"
    return s


def paramdef(el):
    return el


def funcdef(el):
    return el


def function(el):
    return "``%s``" % _concat(el).strip()


def parameter(el):
    return "``%s``" % _concat(el).strip()


def table(el):
    title = _concat(el.find('title'))
    headers = el.findall('.//thead/row/entry')
    # Table bodies can either have rows or xi:includes
    parseableChildren = el.xpath(".//tbody/xi:include | .//tbody/row", namespaces={'xi': 'http://www.w3.org/2001/XInclude'})

    # Collect header names
    header_texts = [_concat(header) for header in headers]

    # Collect row data
    row_data = []
    for row in parseableChildren:
        if row.tag == 'row':
            entries = row.findall('entry')
            row_data.append([_concat(entry) for entry in entries])
        if row.tag == '{http://www.w3.org/2001/XInclude}include':
            row_data.append(ET.tostring(row, encoding=str))

    # Create the table in reST list-table format
    rst_table = []
    rst_table.append(f".. list-table:: {title}")
    rst_table.append("   :header-rows: 1")
    rst_table.append("")

    # Add header row
    header_line = "   * - " + "\n     - ".join(header_texts)
    rst_table.append(header_line)

    # Add rows
    for row in row_data:
        # a row might be a parsed table row,
        # or a raw <xi:include> tag
        row_line = ''
        # Since rst can’t do block-level includes inside tables,
        # we use a Sphinx preprocessor to do this (since a Sphinx
        # Extension would also not be able to do this). For this, we
        # convert the xi:include into a custom include syntax
        # that is only understood by the preprocessor script, eg.:
        # `%% include="standard-specifiers.rst" id="A" %%`
        if 'xi:include' in row:
            row_line = "   "+ row.replace('<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href=', '%% include=').replace('xpointer', 'id').replace('/>', ' %%').replace('.xml', '.rst')
        else:
            row_line = "   * - " + "\n     - ".join(row)
        rst_table.append(row_line)

    return '\n'.join(rst_table)


# tbody tags outside of tables (See directly above) are only used as
# include libraries and will be included via the preprocessor script.
def tbody(el):
    rows = el.findall('.//row')
    # Collect row data
    output = []
    for row in rows:
        entries = row.findall('entry')
        id = row.get('id')
        # Even though these are generally consumed by the preprocessor and not
        # Sphinx itself, we still use the same inclusion-marker directive
        # syntax, in case someone wants to include these snippets somewhere else.
        output.append(f".. inclusion-marker-do-not-remove {id}")
        row_line = "* - " + "\n  - ".join([_concat(entry) for entry in entries])
        output.append(row_line)
        output.append(f".. inclusion-end-marker-do-not-remove {id}")
    return '\n'.join(output)

def userinput(el):
    return _indent(el, 3, "\n\n")


def computeroutput(el):
    return _indent(el, 3, "\n\n")


# miscellaneous
def keycombo(el):
    return _join_children(el, ' + ')


def keycap(el):
    return ":kbd:`%s`" % el.text


def warning(el):
    return f""".. warning::

    {_concat(el)}
"""

def caution(el):
    title = el.xpath("title")[0].text
    content = el.xpath("para")[0]
    output = ".. caution::"
    if title is not None:
        output += f"\n   **{title}**\n"
    output += _indent(content, 3)
    return output


def para(el):
    if _is_inside_of(el, 'listitem'):
        return _concat(el) + "\n \n"
    return _block_separated_with_blank_line(el, False) + '\n\n \n\n'


def simpara(el):
    return _block_separated_with_blank_line(el)


def important(el):
    return _indent(el, 3, ".. note:: ", True)

def refsect1(el):
    return _block_separated_with_blank_line(el)


def refsect2(el):
    return _block_separated_with_blank_line(el)


def refsect3(el):
    return _block_separated_with_blank_line(el)


def refsect4(el):
    return _block_separated_with_blank_line(el)


def refsect5(el):
    return _block_separated_with_blank_line(el)


def convert_xml_to_rst(xml_file_path, output_dir):
    try:
        _run(xml_file_path, output_dir)
        return list(_not_handled_tags), ''
    except Exception as e:
        _warn('Failed to convert file %s' % xml_file_path)
        _warn(e)
        # Uncomment for detailed traceback
        # print(traceback.format_exc())
        return [], str(e)
