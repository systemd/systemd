from typing import List, Dict, Tuple, Any
from docutils import nodes
from docutils.parsers.rst import roles, states
import re

# Define the extlink_formats dictionary with type annotations
extlink_formats: Dict[str, str] = {
    'man-pages': 'https://man7.org/linux/man-pages/man{manvolnum}/{refentrytitle}.{manvolnum}.html',
    'die-net': 'http://linux.die.net/man/{manvolnum}/{refentrytitle}',
    'mankier': 'https://www.mankier.com/{manvolnum}/{refentrytitle}',
    'archlinux': 'https://man.archlinux.org/man/{refentrytitle}.{manvolnum}.en.html',
    'debian': 'https://manpages.debian.org/unstable/{refentrytitle}/{refentrytitle}.{manvolnum}.en.html',
    'freebsd': 'https://www.freebsd.org/cgi/man.cgi?query={refentrytitle}&sektion={manvolnum}',
    'dbus': 'https://dbus.freedesktop.org/doc/dbus-specification.html#{refentrytitle}',
}


def man_role(
    name: str,
    rawtext: str,
    text: str,
    lineno: int,
    inliner: states.Inliner,
    options: Dict[str, Any] = {}
) -> Tuple[List[nodes.reference], List[nodes.system_message]]:
    # Regex to match text like 'locale(7)'
    pattern = re.compile(r'(.+)\((\d+)\)')
    match = pattern.match(text)
    if not match:
        msg = inliner.reporter.error(
            f'Invalid man page format {text}, expected format "name(section)"',
            nodes.literal_block(rawtext, rawtext),
            line=lineno
        )
        return [inliner.problematic(rawtext, rawtext, msg)], [msg]

    refentrytitle, manvolnum = match.groups()

    if name not in extlink_formats:
        msg = inliner.reporter.error(
            f'Unknown man page role {name}',
            nodes.literal_block(rawtext, rawtext),
            line=lineno
        )
        return [inliner.problematic(rawtext, rawtext, msg)], [msg]

    url = extlink_formats[name].format(
        manvolnum=manvolnum, refentrytitle=refentrytitle
    )
    node = nodes.reference(
        rawtext, f'{refentrytitle}({manvolnum})', refuri=url, **options
    )
    return [node], []


def setup(app: Any) -> Dict[str, bool]:
    for role in extlink_formats.keys():
        roles.register_local_role(role, man_role)
    return {'parallel_read_safe': True, 'parallel_write_safe': True}
