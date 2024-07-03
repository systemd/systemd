#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
from pathlib import Path
REMOVE_COMMENTS = False

# id attributes of DocBook elements are translated to ReST labels.
# If this option is False, only labels that are used in links are generated.
WRITE_UNUSED_LABELS = False


# to avoid dupliate error reports
_not_handled_tags = set()

# to remember which id/labels are really needed
_linked_ids = set()

# buffer that is flushed after the end of paragraph,
# used for ReST substitutions
_buffer = ""


def _main():
    if len(sys.argv) != 2 or sys.argv[1] == '-h' or sys.argv[1] == '--help':
        sys.stderr.write(__doc__)
        sys.exit()
    input_file = sys.argv[1]
    sys.stderr.write("Parsing XML file `%s'...\n" % input_file)
    parser = ET.XMLParser(remove_comments=REMOVE_COMMENTS, no_network=False)
    tree = ET.parse(input_file, parser=parser)
    for elem in tree.iter():
        if elem.tag in ("xref", "link"):
            _linked_ids.add(elem.get("linkend"))
    print(TreeRoot(tree.getroot()).encode('utf-8').decode('utf-8'))


def _warn(s):
    sys.stderr.write("WARNING: %s\n" % s)


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
        if i.tail is not None and not i.tail.isspace():
            _warn("skipping tail of <%s>: %s" % (_get_path(i), i.tail))


def _includes(el):
    file_path_pathlib = Path(el.get('href'))
    file_extension = file_path_pathlib.suffix
    include_files = ['standard-options.xml', 'user-system-options.xml',
                     'sd_journal_get_data.xml', 'threads-aware.xml', 'libsystemd-pkgconfig.xml', 'common-variables.xml']
    if file_extension == '.xml':
        if el.get('href') == 'version-info.xml':
            versionString = conf.global_substitutions.get(
                el.get("xpointer"))
            return f".. versionadded:: {versionString}"
        elif not el.get("xpointer"):
            return f".. include:: ./includes/{el.get('href').replace('xml', 'rst')}"
        elif el.get('href') in include_files:
            return f""".. include:: ./includes/{el.get('href').replace('xml', 'rst')}
                    :start-after: .. inclusion-marker-do-not-remove {el.get("xpointer")}
                    :end-before: .. inclusion-end-marker-do-not-remove {el.get("xpointer")}
                    """

    elif file_extension == '.c':
        return f""".. literalinclude:: ./includes/{el.get('href')}
                    :language: c
                """
    elif file_extension == '.py':
        return f""".. literalinclude:: ./includes/{el.get('href')}
                    :language: python
                """
    elif file_extension == '.sh':
        return f""".. literalinclude:: ./includes/{el.get('href')}
                    :language: shell
                """


def _conv(el):
    "element to string conversion; usually calls element_name() to do the job"
    if el.tag in globals():
        s = globals()[el.tag](el)
        assert s, "Error: %s -> None\n" % _get_path(el)
        return s
    elif isinstance(el, ET._Comment):
        return Comment(el) if (el.text and not el.text.isspace()) else ""
    else:
        if el.tag not in _not_handled_tags:
            # Convert version references to `versionAdded` directives
            if el.tag == "{http://www.w3.org/2001/XInclude}include":
                return _includes(el)
            else:
                _warn("Don't know how to handle <%s>" % el.tag)
                # _warn(" ... from path: %s" % _get_path(el))
                # _not_handled_tags.add(el.tag)
        return _concat(el)


def _no_special_markup(el):
    return _concat(el)


def _remove_indent_and_escape(s, tag):
    if tag == "programlisting":
        return s
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


def _concat(el):
    "concatate .text with children (_conv'ed to text) and their tails"
    s = ""
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


def _get_path(el):
    t = [el] + list(el.iterancestors())
    return "/".join(str(i.tag) for i in reversed(t))


def _make_title(t, level):
    if level == 1:
        return "\n\n" + "=" * len(t) + "\n" + t + "\n" + "=" * len(t)
    char = ["#", "=", "-", "~", "^", "."]
    return "\n\n" + t + "\n" + char[level-2] * len(t)


def _join_children(el, sep):
    _has_no_text(el)
    return sep.join(_conv(i) for i in el)


def _block_separated_with_blank_line(el):
    s = "\n\n" + _concat(el)
    global _buffer
    if _buffer:
        s += "\n\n" + _buffer
        _buffer = ""
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

###################           DocBook elements        #####################

# special "elements"


def TreeRoot(el):
    output = _conv(el)
    # remove trailing whitespace
    output = re.sub(r"[ \t]+\n", "\n", output)
    # leave only one blank line
    output = re.sub(r"\n{3,}", "\n\n", output)
    return output


def Comment(el):
    return _indent(el, 12, ".. COMMENT: ")

# Meta refs


def refentry(el):
    return _concat(el)

# FIXME: how to ignore/delete a tag???


def refentryinfo(el):
    # ignore
    return '  '


def refnamediv(el):
    return '**Name** \n\n' + _make_title(_join_children(el, ' — '), 2)


def refsynopsisdiv(el):
    return '**Synopsis** \n\n' + _make_title(_join_children(el, ' '), 3)


def refname(el):
    _has_only_text(el)
    return "%s" % el.text


def refpurpose(el):
    _has_only_text(el)
    return "%s" % el.text


def cmdsynopsis(el):
    return _join_children(el, ' ')


def arg(el):
    text = el.text
    if text is None:
        text = _join_children(el, '')
    # choice: req, opt, plain
    choice = el.get("choice")
    if choice == 'opt':
        return f"[%s{'...' if el.get('rep') == 'repeat' else ''}]" % text
    elif choice == 'req':
        return "{%s}" % text
    elif choice == 'plain':
        return "%s" % text
    else:
        "print warning if there another choice"
        _warn("skipping arg with choice of: %s" % (choice))


# general inline elements

def emphasis(el):
    return "*%s*" % _concat(el).strip()


phrase = emphasis
citetitle = emphasis


def firstterm(el):
    _has_only_text(el)
    return ":dfn:`%s`" % el.text


acronym = _no_special_markup


def command(el):
    if el.getparent().tag == 'term':
        return _concat(el).strip()
    return "``%s``" % _concat(el).strip()


option = command
filename = command
constant = command
literal = command
varname = command
function = command


def optional(el):
    return "[%s]" % _concat(el).strip()


def replaceable(el):
    return "<%s>" % _concat(el).strip()


def term(el):
    if el.getparent().index(el) != 0:
        return ' '

    # Helper to extract the core of a term (eg. a command without all the options) for use as a title in the sidebar
    def getCommand(el):
        command = ''
        for child in el:
            # varname too?
            if child.tag in ['command', 'option', 'varname']:
                command = child.text.rstrip('=')
                break
        return command

    # Sometimes, there are multiple terms for one entry. We want those displayed in a single line, so we gather them all up and parse them together
    hasMultipleTerms = False
    titleStrings = [getCommand(el)]
    usageStrings = [_concat(el).strip()]
    for term in el.itersiblings(tag='term'):
        # We only arrive here if there is more than one `<term>` in the `el`
        hasMultipleTerms = True
        titleStrings.append(getCommand(term))
        usageStrings.append(_concat(term).strip())

    if hasMultipleTerms:
        titleString = ', '.join(titleStrings)
        usageString = ', '.join(usageStrings)
        s = ''
        s += _make_title(f"``{titleString}``", 4) + '\n\n'
        if titleString != usageString:
            s += f"*Usage:* ``{usageString}``"
        return s

    # If this contains a <command> or <option>, split that out as the title in a new line, then repeat it with the entire term in the next line
    command = getCommand(el)
    if command:
        usageString = _concat(el).strip()
        s = ''
        s += _make_title(f"``{command}``", 4) + '\n\n'
        if command != usageString:
            s += f"*Usage:* ``{usageString}``"
        return s
    else:
        return _make_title(_concat(el).strip(), 4)

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


# lists

def itemizedlist(el):
    return _indent(el, 2, "* ", True)


def orderedlist(el):
    return _indent(el, 2, "1. ", True)


def simplelist(el):
    type = el.get("type")
    if type == "inline":
        return _join_children(el, ', ')
    else:
        return _concat(el)


def member(el):
    return _concat(el)

# varlists


def variablelist(el):
    return _concat(el)


def varlistentry(el):
    s = ""
    for i in el:
        if i.tag == 'term':
            s += _conv(i) + '\n\n'
        else:
            s += _indent(i, 3, None, True)
    return s


def listitem(el):
    _supports_only(
        el, ["para", "simpara", "{http://www.w3.org/2001/XInclude}include"])
    return _block_separated_with_blank_line(el)

# sections


def example(el):
    # FIXME: too hacky?
    elements = [i for i in el]
    first, rest = elements[0], elements[1:]

    return _make_title(_concat(first), 3) + "\n\n" + "".join(_conv(i) for i in rest)


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
    return _make_title(_concat(el).strip(), _get_level(el) + 1)

# bibliographic elements


def author(el):
    _has_only_text(el)
    return "\n\n.. _author:\n\n**%s**" % el.text


def date(el):
    _has_only_text(el)
    return "\n\n.. _date:\n\n%s" % el.text

# references


def citerefentry(el):
    # Handles all external URl conversions from man/custom-html.xsl
    project = el.get("project")
    refentrytitle = el.xpath("refentrytitle")[0].text
    manvolnum = el.xpath("manvolnum")[0].text
    if project == 'man-pages' or manvolnum == 2 or manvolnum == 4:
        return f"`{refentrytitle}({manvolnum}) <https://man7.org/linux/man-pages/man{manvolnum}/{refentrytitle}.{manvolnum}.html>`_"
    if project == 'die-net':
        return f"`{refentrytitle}({manvolnum}) <http://linux.die.net/man/ {manvolnum}/{refentrytitle}>`_"
    if project == 'mankier':
        return f"`{refentrytitle}({manvolnum}) <https://www.mankier.com/{manvolnum}/{refentrytitle}>`_"
    if project == 'archlinux':
        return f"`{refentrytitle}({manvolnum}) <https://man.archlinux.org/man/{refentrytitle}.{manvolnum}.en.html>`_"
    if project == 'debian':
        return f"`{refentrytitle}({manvolnum}) <https://manpages.debian.org/unstable/{refentrytitle}/{refentrytitle}.{manvolnum}.en.html>`_"
    if project == 'freebsd':
        return f"`{refentrytitle}({manvolnum}) <https://www.freebsd.org/cgi/man.cgi?{refentrytitle}({manvolnum})>`_"
    if project == 'dbus':
        return f"`{refentrytitle}({manvolnum}) <https://dbus.freedesktop.org/doc/{refentrytitle}.{manvolnum}.html>`_"
    if project == 'url':
        url = el.get("url")
        return f"`{refentrytitle}({manvolnum}) <{url}>`_"

    return f":ref:`{refentrytitle}({manvolnum})`"


def refmeta(el):
    refentrytitle = el.find('refentrytitle').text
    manvolnum = el.find('manvolnum').text

    meta_title = f"""..meta::
    :title: {refentrytitle}
            """

    meta_manvolnum = f"""..meta::
    :manvolnum: {manvolnum}
            """

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


def programlisting(el):
    xi_include = el.find('.//{http://www.w3.org/2001/XInclude}include')
    if xi_include is not None:
        return _includes(xi_include)
    else:
        return f"\n\n.. code-block:: sh \n\n{_indent(el, 3)}\n\n"


def screen(el):
    return _indent(el, 3, "::\n\n", False) + "\n\n"


def synopsis(el):
    return _indent(el, 3, "::\n\n", False) + "\n\n"


def userinput(el):
    return _indent(el, 3, "\n\n")


def computeroutput(el):
    return _indent(el, 3, "\n\n")


# miscellaneous
def keycombo(el):
    return _join_children(el, ' + ')


def keycap(el):
    return ":kbd:`%s`" % el.text


def para(el):
    return _block_separated_with_blank_line(el) + '\n\n \n\n'


def simpara(el):
    return _block_separated_with_blank_line(el)


def important(el):
    return _indent(el, 3, ".. note:: ", True)


def itemizedlist(el):
    return _indent(el, 2, "* ", True)


def orderedlist(el):
    return _indent(el, 2, "1. ", True)


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


if __name__ == "__main__":
    _main()
