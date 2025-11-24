# SPDX-License-Identifier: LGPL-2.1-or-later
from __future__ import annotations
from typing import List, Dict, Any
from docutils import nodes

from sphinx.locale import _
from sphinx.application import Sphinx
from sphinx.util.docutils import SphinxRole, SphinxDirective
from sphinx.util.typing import ExtensionMetadata


class directive_list(nodes.General, nodes.Element):
    pass


class InlineDirectiveRole(SphinxRole):
    def run(self) -> tuple[List[nodes.Node], List[nodes.system_message]]:
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
    def run(self) -> List[nodes.Node]:
        return [directive_list('')]


def register_directive_roles(app: Sphinx) -> None:
    directives_data: List[Dict[str, Any]] = app.config.directives_data
    role_types: List[str] = app.config.role_types

    for directive in directives_data:
        dir_id: str = directive['id']
        for role_type in role_types:
            role_name = f'directive:{dir_id}:{role_type}'
            app.add_role(role_name, InlineDirectiveRole())


def get_directive_metadata(app: Sphinx) -> Dict[str, Dict[str, Any]]:
    directives_data: List[Dict[str, Any]] = app.config.directives_data
    return {directive['id']: directive for directive in directives_data}


def group_directives_by_id(env) -> Dict[str, List[Dict[str, Any]]]:
    grouped_directives: Dict[str, List[Dict[str, Any]]] = {}
    for dir_info in getattr(env, 'directives', []):
        dir_id = dir_info['name'].split(':')[1]
        if dir_id not in grouped_directives:
            grouped_directives[dir_id] = []
        grouped_directives[dir_id].append(dir_info)
    return grouped_directives


def create_reference_node(app: Sphinx, dir_info: Dict[str, Any], from_doc_name: str) -> nodes.reference:
    ref_node = nodes.reference('', '')
    ref_node['refdocname'] = dir_info['docname']
    ref_node['refuri'] = app.builder.get_relative_uri(
        from_doc_name, dir_info['docname']) + '#' + dir_info['target_id']

    metadata: Dict[str, Any] = app.builder.env.metadata.get(
        dir_info['docname'], {})
    title: str = metadata.get('title', 'Unknown Title')
    manvolnum: str = metadata.get('manvolnum', 'Unknown Volume')

    ref_node.append(nodes.Text(f'{title}({manvolnum})'))
    return ref_node


def render_reference_node(references: List[nodes.reference]) -> nodes.paragraph:
    para = nodes.inline()

    for i, ref_node in enumerate(references):
        para += ref_node
        if i < len(references) - 1:
            para += nodes.Text(", ")

    return para


def render_option(directive_text: str, references: List[nodes.reference]) -> nodes.section:
    section = nodes.section()

    title = nodes.title(text=directive_text, classes=['directive-header'])
    title_id = nodes.make_id(directive_text)
    title['ids'] = [title_id]
    title['names'] = [directive_text]
    section['ids'] = [title_id]
    section += title

    node = render_reference_node(references)
    section += node

    return section


def render_variable(directive_text: str, references: List[nodes.reference]) -> nodes.section:
    section = nodes.section()

    title = nodes.title(text=directive_text, classes=['directive-header'])
    title_id = nodes.make_id(directive_text)
    title['ids'] = [title_id]
    title['names'] = [directive_text]
    section['ids'] = [title_id]
    section += title

    node = render_reference_node(references)
    section += node

    return section


def render_constant(directive_text: str, references: List[nodes.reference]) -> nodes.section:
    section = nodes.section()

    title = nodes.title(text=directive_text, classes=['directive-header'])
    title_id = nodes.make_id(directive_text)
    title['ids'] = [title_id]
    title['names'] = [directive_text]
    section['ids'] = [title_id]
    section += title

    node = render_reference_node(references)
    section += node

    return section


def process_items(app: Sphinx, doctree: nodes.document, from_doc_name: str) -> None:
    env = app.builder.env
    directive_lookup: Dict[str, Dict[str, Any]] = get_directive_metadata(app)
    grouped_directives: Dict[str, List[Dict[str, Any]]
                             ] = group_directives_by_id(env)

    render_map = {
        'option': render_option,
        'var': render_variable,
        'constant': render_constant,
    }

    for node in doctree.findall(directive_list):
        content: List[nodes.section] = []

        for dir_id, directives in grouped_directives.items():
            directive_meta = directive_lookup.get(
                dir_id, {'title': 'Unknown', 'description': 'No description available.'})
            section = nodes.section(ids=[dir_id])
            section += nodes.title(text=directive_meta['title'])
            section += nodes.paragraph(text=directive_meta['description'])

            directive_references: Dict[str, List[nodes.reference]] = {}

            for dir_info in directives:
                directive_text: str = dir_info['text']
                role_type: str = dir_info['name'].split(':')[-1]

                if directive_text not in directive_references:
                    directive_references[directive_text] = []

                ref_node = create_reference_node(app, dir_info, from_doc_name)
                directive_references[directive_text].append(ref_node)

            for directive_text, references in directive_references.items():
                render_fn = render_map.get(role_type, render_option)
                rendered_section = render_fn(directive_text, references)
                section += rendered_section

            content.append(section)
        node.replace_self(content)


def setup(app: Sphinx) -> ExtensionMetadata:
    app.add_config_value('directives_data', [], 'env')
    app.add_config_value('role_types', [], 'env')

    register_directive_roles(app)
    app.add_directive('list_directive_roles', ListDirectiveRoles)
    app.connect('doctree-resolved', process_items)
    return {
        'version': '0.1',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
