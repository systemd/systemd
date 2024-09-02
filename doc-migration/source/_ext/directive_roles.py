from __future__ import annotations
from typing import List, Dict, Any
from docutils import nodes

from sphinx.locale import _
from sphinx.application import Sphinx
from sphinx.util.docutils import SphinxRole, SphinxDirective
from sphinx.util.typing import ExtensionMetadata
from docutils.parsers.rst.roles import set_classes
# Existing lists of directive groups
directives_data = [
    {
        "id": "unit-directives",
        "title": "Unit directives",
        "description": "Directives for configuring units, used in unit files."
    },
    {
        "id": "kernel-commandline-options",
        "title": "Options on the kernel command line",
        "description": "Kernel boot options for configuring the behaviour of the systemd process."
    },
    {
        "id": "smbios-type-11-options",
        "title": "SMBIOS Type 11 Variables",
        "description": "Data passed from VMM to system via SMBIOS Type 11."
    },
    {
        "id": "environment-variables",
        "title": "Environment variables",
        "description": "Environment variables understood by the systemd manager and other programs and environment variable-compatible settings."
    },
    {
        "id": "system-credentials",
        "title": "System Credentials",
        "description": "System credentials understood by the system and service manager and various other components:"
    },
    {
        "id": "efi-variables",
        "title": "EFI variables",
        "description": "EFI variables understood by\n    "
    },
    {
        "id": "home-directives",
        "title": "Home Area/User Account directives",
        "description": "Directives for configuring home areas and user accounts via\n    "
    },
    {
        "id": "udev-directives",
        "title": "UDEV directives",
        "description": "Directives for configuring systemd units through the udev database."
    },
    {
        "id": "network-directives",
        "title": "Network directives",
        "description": "Directives for configuring network links through the net-setup-link udev builtin and networks\n    through systemd-networkd."
    },
    {
        "id": "journal-directives",
        "title": "Journal fields",
        "description": "Fields in the journal events with a well known meaning."
    },
    {
        "id": "pam-directives",
        "title": "PAM configuration directives",
        "description": "Directives for configuring PAM behaviour."
    },
    {
        "id": "fstab-options",
        "title": 'fstab-options',
        "description": "Options which influence mounted filesystems and encrypted volumes."
    },
    {
        "id": "nspawn-directives",
        "title": 'nspawn-directives',
        "description": "Directives for configuring systemd-nspawn containers."
    },
    {
        "id": "config-directives",
        "title": "Program configuration options",
        "description": "Directives for configuring the behaviour of the systemd process and other tools through\n    configuration files."
    },
    {
        "id": "options",
        "title": "Command line options",
        "description": "Command-line options accepted by programs in the systemd suite."
    },
    {
        "id": "constants",
        "title": "Constants",
        "description": "Various constants used and/or defined by systemd."
    },
    {
        "id": "dns",
        "title": "DNS resource record types",
        "description": "No description available"
    },
    {
        "id": "miscellaneous",
        "title": "Miscellaneous options and directives",
        "description": "Other configuration elements which don't fit in any of the above groups."
    },
    {
        "id": "specifiers",
        "title": "Specifiers",
        "description": "Short strings which are substituted in configuration directives."
    },
    {
        "id": "filenames",
        "title": "Files and directories",
        "description": "Paths and file names referred to in the documentation."
    },
    {
        "id": "dbus-interface",
        "title": "D-Bus interfaces",
        "description": "Interfaces exposed over D-Bus."
    },
    {
        "id": "dbus-method",
        "title": "D-Bus methods",
        "description": "Methods exposed in the D-Bus interface."
    },
    {
        "id": "dbus-property",
        "title": "D-Bus properties",
        "description": "Properties exposed in the D-Bus interface."
    },
    {
        "id": "dbus-signal",
        "title": "D-Bus signals",
        "description": "Signals emitted in the D-Bus interface."
    }
]

role_types = [
    'const',
    'var',
]


class directive_list(nodes.General, nodes.Element):
    pass


class InlineDirectiveRole(SphinxRole):
    def run(self) -> tuple[list[nodes.Node], list[nodes.system_message]]:
        target_id = f'directive-{self.env.new_serialno("directive")}-{
            self.text}'

        target_node = nodes.target('', self.text, ids=[target_id])

        if not hasattr(self.env, 'directives'):
            self.env.directives = []

        self.env.directives.append({
            'name': self.name,
            'text': self.text,
            'docname': self.env.docname,
            'lineno': self.lineno,
            'target_id': target_id,
        })

        return [target_node], []


class ListDirectiveRoles(SphinxDirective):
    def run(self) -> list[nodes.Node]:
        return [directive_list('')]


def register_directive_roles(app: Sphinx):
    for directive in directives_data:
        dir_id = directive['id']
        for role_type in role_types:
            role_name = f'directive:{dir_id}:{role_type}'
            app.add_role(role_name, InlineDirectiveRole())


def get_directive_metadata() -> Dict[str, Dict[str, Any]]:
    return {directive['id']: directive for directive in directives_data}


def group_directives_by_id(env) -> Dict[str, List[Dict[str, Any]]]:
    grouped_directives = {}
    for dir_info in getattr(env, 'directives', []):
        dir_id = dir_info['name'].split(':')[1]
        if dir_id not in grouped_directives:
            grouped_directives[dir_id] = []
        grouped_directives[dir_id].append(dir_info)
    return grouped_directives


def create_reference_node(app, dir_info, from_doc_name):
    ref_node = nodes.reference('', '')
    ref_node['refdocname'] = dir_info['docname']
    ref_node['refuri'] = app.builder.get_relative_uri(
        from_doc_name, dir_info['docname']) + '#' + dir_info['target_id']

    metadata = app.builder.env.metadata.get(dir_info['docname'], {})
    title = metadata.get('title', 'Unknown Title')
    manvolnum = metadata.get('manvolnum', 'Unknown Volume')

    ref_node.append(nodes.Text(f'{title}({manvolnum})'))
    return ref_node


def process_items(app: Sphinx, doctree: nodes.document, from_doc_name: str):
    env = app.builder.env
    directive_lookup = get_directive_metadata()
    grouped_directives = group_directives_by_id(env)

    for node in doctree.findall(directive_list):
        content = []

        for dir_id, directives in grouped_directives.items():
            directive_meta = directive_lookup.get(
                dir_id, {'title': 'Unknown', 'description': 'No description available.'})
            section = nodes.section(ids=[dir_id])
            section += nodes.title(text=directive_meta['title'])
            section += nodes.paragraph(text=directive_meta['description'])

            directive_references = {}

            for dir_info in directives:
                directive_text = dir_info['text']
                if directive_text not in directive_references:
                    directive_references[directive_text] = []

                ref_node = create_reference_node(app, dir_info, from_doc_name)
                directive_references[directive_text].append(ref_node)

            for directive_text, references in directive_references.items():
                para = nodes.paragraph()
                description = _('%s=') % directive_text
                para += nodes.Text(description)

                for i, ref_node in enumerate(references):
                    para += ref_node
                    if i < len(references) - 1:
                        para += nodes.Text(", ")

                section += para

            content.append(section)
        node.replace_self(content)


def setup(app: Sphinx) -> ExtensionMetadata:
    register_directive_roles(app)
    app.add_directive('list_directive_roles', ListDirectiveRoles)
    app.connect('doctree-resolved', process_items)
    return {
        'version': '0.1',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
