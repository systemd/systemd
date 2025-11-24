# SPDX-License-Identifier: LGPL-2.1-or-later
from __future__ import annotations

from typing import List, Dict, Any, Tuple, Optional, Set
from docutils import nodes

from sphinx.application import Sphinx
from sphinx.domains import Domain
from sphinx.util.docutils import SphinxRole, SphinxDirective
from sphinx.util.typing import ExtensionMetadata
from sphinx.util import logging

logger = logging.getLogger(__name__)
logger.info('Custom Directive/Roles Extension loaded')


class directive_list(nodes.General, nodes.Element):
    pass


class InlineDirectiveRole(SphinxRole):
    def run(self) -> tuple[List[nodes.Node], List[nodes.system_message]]:
        # self.name is either:
        # - "dir_id:role_type" when invoked through the "directive" domain, or
        # - "directive:dir_id:role_type" if ever registered globally (legacy)
        full_name = self.name
        dir_id: Optional[str] = None
        role_type: Optional[str] = None

        if full_name.startswith('directive:'):
            # Legacy one-piece role name, split after "directive:"
            try:
                _, dir_id, role_type = full_name.split(':', 2)
            except ValueError:
                logger.warning('InlineDirectiveRole: unexpected legacy role name "%s"', full_name)
        else:
            # Domain-based role name: "<id>:<type>"
            parts = full_name.split(':', 1)
            if len(parts) == 2:
                dir_id, role_type = parts[0], parts[1]
            else:
                logger.warning('InlineDirectiveRole: unexpected domain role name "%s"', full_name)

        # Create a stable, safe anchor id
        safe_text = nodes.make_id(self.text)
        serial = self.env.new_serialno('directive')
        target_id = f'directive-{serial}-{safe_text}'
        target_node = nodes.target('', self.text, ids=[target_id])

        if not hasattr(self.env, 'directives'):
            self.env.directives = []

        self.env.directives.append({
            'name': full_name,
            'dir_id': dir_id,
            'role_type': role_type,
            'text': self.text,
            'docname': self.env.docname,
            'lineno': self.lineno,
            'target_id': target_id,
        })

        logger.debug('InlineDirectiveRole: recorded %s text="%s" at %s:%s -> %s',
                     full_name, self.text, self.env.docname, self.lineno, target_id)

        # Pure anchor marker; no visible inline text returned intentionally.
        return [target_node], []


class ListDirectiveRoles(SphinxDirective):
    def run(self) -> List[nodes.Node]:
        return [directive_list('')]


def get_directive_metadata(app: Sphinx) -> Dict[str, Dict[str, Any]]:
    directives_data: List[Dict[str, Any]] = app.config.directives_data
    return {directive['id']: directive for directive in directives_data}


def register_global_roles(app: Sphinx) -> None:
    """Register fallback global roles 'directive:<id>:<type>' so that even if
    domain dispatch is bypassed, roles still resolve."""
    directives_data: List[Dict[str, Any]] = app.config.directives_data or []
    role_types: List[str] = app.config.role_types or []
    count = 0
    for directive in directives_data:
        dir_id = directive.get('id')
        if not dir_id:
            continue
        for role_type in role_types:
            role_name = f'directive:{dir_id}:{role_type}'
            try:
                app.add_role(role_name, InlineDirectiveRole())
                count += 1
            except Exception as e:
                logger.warning("directive extension: add_role('%s') failed: %s", role_name, e)
    logger.info("directive extension: registered %d global fallback roles", count)


def group_directives_by_id(env) -> Dict[str, List[Dict[str, Any]]]:
    grouped_directives: Dict[str, List[Dict[str, Any]]] = {}
    for dir_info in getattr(env, 'directives', []):
        dir_id = dir_info.get('dir_id')
        name = dir_info.get('name', '')
        if not dir_id:
            # Fallback for legacy name "directive:<id>:<type>"
            if name.startswith('directive:'):
                parts = name.split(':')
                if len(parts) >= 3:
                    dir_id = parts[1]
        if not dir_id:
            logger.debug('group_directives_by_id: skipping entry with no dir_id: %r', dir_info)
            continue
        grouped_directives.setdefault(dir_id, []).append(dir_info)
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
    para = nodes.paragraph()
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
    grouped_directives: Dict[str, List[Dict[str, Any]]] = group_directives_by_id(env)

    logger.debug('process_items: collected %d occurrences across %d groups',
                 len(getattr(env, 'directives', [])), len(grouped_directives))

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

            section_id = f'directive-{nodes.make_id(dir_id)}'
            section = nodes.section(ids=[section_id])
            section += nodes.title(text=directive_meta['title'])
            section += nodes.paragraph(text=directive_meta['description'])

            # Group by (directive_text, role_type)
            directive_references: Dict[Tuple[str, str], List[nodes.reference]] = {}

            for dir_info in directives:
                directive_text: str = dir_info['text']
                role_type: str = dir_info.get('role_type') or 'option'
                key = (directive_text, role_type)

                ref_node = create_reference_node(app, dir_info, from_doc_name)
                directive_references.setdefault(key, []).append(ref_node)

            for (directive_text, role_type), references in sorted(directive_references.items()):
                render_fn = render_map.get(role_type, render_option)
                rendered_section = render_fn(directive_text, references)
                section += rendered_section

            content.append(section)

        node.replace_self(content)

    logger.debug('process_items: finished generating directive listings')


class DirectiveDomain(Domain):
    """Sphinx domain to resolve :directive:<id>:<type>:`...` roles.

    Sphinx treast the first segment as a domain, so we provide a 'directive'
    domain and handle dynamic role names of the form '<id>:<type>'.
    """
    name = 'directive'
    label = 'Directive'
    roles: Dict[str, Any] = {}  # dynamic; resolved via role()

    def get_role(self, name: str):
        """Return the role handler for a role name like '<id>:<type>'."""
        # Validate and log; always return our SphinxRole so parsing continues,
        # but surface configuration mismatches in logs.
        dir_id: Optional[str] = None
        role_type: Optional[str] = None

        parts = name.split(':', 1)
        if len(parts) == 2:
            dir_id, role_type = parts[0], parts[1]
        else:
            logger.warning("directive domain: invalid role name '%s' (expected '<id>:<type>')", name)
            return InlineDirectiveRole()

        cfg_ids: Set[str] = {d.get('id') for d in self.env.config.directives_data or [] if isinstance(d, dict)}
        cfg_types: Set[str] = set(self.env.config.role_types or [])

        if dir_id not in cfg_ids:
            logger.warning("directive domain: unknown id '%s' in role '%s' (known ids: %s%s)",
                           dir_id, name,
                           ', '.join(sorted(list(cfg_ids))[:10]),
                           '…' if len(cfg_ids) > 10 else '')
        if role_type not in cfg_types:
            logger.warning("directive domain: unknown role type '%s' for id '%s' in role '%s' (known types: %s)",
                           role_type, dir_id, name, ', '.join(sorted(cfg_types)) or '(none)')

        logger.debug("directive domain: resolved role '%s' (id=%s, type=%s)", name, dir_id, role_type)
        return InlineDirectiveRole()


def on_config_inited(app: Sphinx, config) -> None:
    ids = [d.get('id') for d in (config.directives_data or []) if isinstance(d, dict)]
    logger.info("directive extension: config loaded: %d ids, %d role types",
                len(ids), len(config.role_types or []))
    logger.debug("directive extension: ids=%s", ', '.join(ids[:10]) + ('…' if len(ids) > 10 else ''))
    logger.debug("directive extension: role_types=%s", ', '.join(config.role_types or []))
    # Also register global fallback roles so docutils can resolve them even without domain dispatch
    register_global_roles(app)


def on_builder_inited(app: Sphinx) -> None:
    # Sanity log to confirm domain is active
    domain = app.env.domains.get('directive') if hasattr(app, 'env') and app.env else None
    logger.info("directive extension: builder inited (domain active=%s)", bool(domain))


def on_env_before_read_docs(app: Sphinx, env, docnames) -> None:
    # Reset per-build collection of directives to avoid stale state
    env.directives = []
    logger.debug("directive extension: env.directives reset")


def on_env_purge_doc(app: Sphinx, env, docname: str) -> None:
    # Remove entries belonging to a document that is being purged
    if hasattr(env, 'directives'):
        before = len(env.directives)
        env.directives = [d for d in env.directives if d.get('docname') != docname]
        after = len(env.directives)
        logger.debug("directive extension: purged %d entries for %s", before - after, docname)


def setup(app: Sphinx) -> ExtensionMetadata:
    app.add_config_value('directives_data', [], 'env')
    app.add_config_value('role_types', [], 'env')

    # Add our custom domain; it will dynamically resolve roles like '<id>:<type>'
    app.add_domain(DirectiveDomain)

    app.add_directive('list_directive_roles', ListDirectiveRoles)
    app.connect('doctree-resolved', process_items)

    # Diagnostics and lifecycle
    app.connect('config-inited', on_config_inited)
    app.connect('builder-inited', on_builder_inited)
    app.connect('env-before-read-docs', on_env_before_read_docs)
    app.connect('env-purge-doc', on_env_purge_doc)

    return {
        'version': '0.2',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
