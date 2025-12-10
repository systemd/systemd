# SPDX-License-Identifier: LGPL-2.1-or-later
from __future__ import annotations

from typing import Dict, List, Tuple, Any, Optional
import re

from docutils import nodes
from docutils.parsers.rst import directives as rst_directives

from sphinx.application import Sphinx
from sphinx.util import logging
from sphinx.util.docutils import SphinxDirective, SphinxRole
from sphinx.domains import Domain, ObjType
from sphinx.roles import XRefRole
from sphinx.environment import BuildEnvironment
from sphinx.util.nodes import make_refnode
from sphinx.util.typing import ExtensionMetadata
from sphinx import addnodes
from sphinx.directives import ObjectDescription
from sphinx.util.nodes import nested_parse_with_titles
from docutils.statemachine import ViewList

logger = logging.getLogger(__name__)


def _normalize_name(name: str) -> str:
    s = (name or '').strip().lower()
    s = re.sub(r'[=]+$', '', s)           # drop trailing '='
    s = re.sub(r'[^0-9a-z]+', '-', s)     # non-alnum -> -
    s = s.strip('-')
    return s


def _doc_slug(docname: str) -> str:
    # docname like 'docs/systemd.exec' (no extension)
    base = docname.split('/')[-1] if '/' in docname else docname
    return base.replace('.', '-')


def _composite_anchor(kind: str, docname: str, names: List[str]) -> str:
    norm = [_normalize_name(n) for n in names if n]
    return "systemd-{kind}-{slug}-{suffix}".format(
        kind=kind, slug=_doc_slug(docname), suffix='-'.join(norm)
    )


class SystemdObjectDirective(SphinxDirective):
    """
    Define one or more systemd objects (env/option/constant) at the current location.

    Usage:
      .. systemd:env:: $SYSTEMD_LOG_LEVEL
         :group: environment-variables

      .. systemd:option:: --copy-locale, --copy-keymap, --copy-timezone
         :group: unit-directives

    Behavior:
      - Registers N objects in the domain registry (one per name) with a single shared anchor.
      - Emits an invisible target and a visible non-title “name line” (inline literals joined by commas).
    """
    has_content = True
    required_arguments = 1  # CSV list of names
    optional_arguments = 0
    final_argument_whitespace = True
    option_spec = {
        'group': rst_directives.unchanged,
    }

    def run(self) -> List[nodes.Node]:
        domain: SystemdDomain = self.env.get_domain('systemd')  # type: ignore
        kind = self.name.split(':')[-1]  # env|option|constant

        raw = self.arguments[0]
        # Split on commas but preserve names with internal spaces (rare)
        names = [n.strip() for n in raw.split(',') if n.strip()]
        if not names:
            logger.warning("systemd:%s: no names parsed at %s:%s", kind, self.env.docname, self.lineno)
            return []

        group = (self.options.get('group') or 'miscellaneous').strip()

        # Build a single composite anchor for this definition site
        anchor = _composite_anchor(kind, self.env.docname, names)

        target = nodes.target('', '', ids=[anchor])

        # Visible name line (not a heading). Make each name a self-link to the anchor.
        para = nodes.paragraph()
        para['classes'].append('systemd-object-header')
        for i, n in enumerate(names):
            lit = nodes.literal(text=n)
            link = nodes.reference('', '', internal=True)
            # Use refid for intra-document anchor
            link['refid'] = anchor
            link += lit
            para += link
            if i < len(names) - 1:
                para += nodes.Text(", ")

        # Register each individual name in domain registry
        for n in names:
            norm = _normalize_name(n)
            domain.add_object(kind, norm, {
                'docname': self.env.docname,
                'anchor': anchor,
                'group': group,
                'name': n,
            })

        # If the directive block contains content, parse it as the body/description
        if self.content:
            body = nodes.container()
            self.state.nested_parse(self.content, self.content_offset, body)
            return [target, para, body]

        return [target, para]


class SystemdObject(ObjectDescription[str]):
    """
    ObjectDescription-based directive so Furo renders like native domains.

    Supports CSV of names in a single directive block:
      .. systemd:option:: --copy-locale, --copy-keymap
         :group: unit-directives

    This produces one signature (dt) per name and a shared content (dd).
    """
    has_content = True
    required_arguments = 1
    final_argument_whitespace = True
    option_spec = {
        'group': rst_directives.unchanged,
    }

    def get_signatures(self) -> List[str]:
        raw = self.arguments[0] if self.arguments else ''
        names = [n.strip() for n in raw.split(',') if n.strip()]
        if not names:
            logger.warning("systemd:%s: no names parsed at %s:%s",
                           self.name.split(':')[-1], getattr(self.env, 'docname', '?'), getattr(self, 'lineno', '?'))
        return names

    def handle_signature(self, sig: str, signode: addnodes.desc_signature) -> str:
        # Literal render of the visible name for the signature line. Left as a fallback in case there are issues with the more ambitious code below
        # signode += addnodes.desc_name(text=sig)
        # return sig  # returned value is passed to add_target_and_index as "name"

        # Render inline styles like :kbd: inside systemd role lines
        # Create a temporary container to parse roles
        vl = ViewList()
        vl.append(sig, '<signature>')
        temp_container = nodes.inline()
        nested_parse_with_titles(self.state, vl, temp_container)

        # Flatten paragraphs to inline nodes
        name_node = addnodes.desc_name()
        for child in temp_container:
            if isinstance(child, nodes.paragraph):
                name_node += child.children
            else:
                name_node += child

        signode += name_node
        return sig

    def add_target_and_index(self, name: str, sig: str, signode: addnodes.desc_signature) -> None:
        # Register target/anchor and domain object entry with de-duplication
        kind = self.name.split(':')[-1]  # env|option|constant
        group = (self.options.get('group') or 'miscellaneous').strip()

        # Base anchor computed from this signature
        base = _composite_anchor(kind, self.env.docname, [sig])

        # Track per-directive CSV duplicates
        if not hasattr(self, '_systemd_seen_bases'):
            self._systemd_seen_bases = set()
            self._systemd_primary_anchor_for_base = {}

        # Track per-document usage to ensure uniqueness across the whole page
        try:
            counts = self.env.temp_data.setdefault('systemd_anchor_counts', {})  # type: ignore[attr-defined]
        except Exception:
            # If env.temp_data is not available for any reason, fall back to a local counter
            if not hasattr(self.env, '_systemd_anchor_counts'):
                self.env._systemd_anchor_counts = {}  # type: ignore[attr-defined]
            counts = self.env._systemd_anchor_counts  # type: ignore[attr-defined]

        assign_id = True
        if base in getattr(self, '_systemd_seen_bases', set()):
            # Duplicate alias within the same directive block — reuse first anchor
            anchor = self._systemd_primary_anchor_for_base.get(base, base)
            assign_id = False
        else:
            # First time we see this base in this directive
            n = counts.get(base, 0)
            anchor = base if n == 0 else f"{base}-{n+1}"
            counts[base] = n + 1
            self._systemd_seen_bases.add(base)
            self._systemd_primary_anchor_for_base[base] = anchor

        if assign_id:
            signode['ids'].append(anchor)
            try:
                # mark as explicit target so headerlink is emitted
                self.state.document.note_explicit_target(signode)
            except Exception:
                pass

        domain: SystemdDomain = self.env.get_domain('systemd')  # type: ignore
        domain.add_object(kind, _normalize_name(sig), {
            'docname': self.env.docname,
            'anchor': anchor,
            'group': group,
            'name': sig,
        })
        # Optional: add index entry if desired. Keeping minimal for now.

class DirectiveCompatRole(SphinxRole):
    """
    Compatibility role handler for legacy :directive:<group-id>:<type>:`NAME` inline roles.

    It resolves to the corresponding systemd domain object anchor using the
    same-doc-first strategy, then first available definition.
    """
    def run(self):
        try:
            # self.name is like 'directive:<group-id>:<type>'
            parts = (self.name or '').split(':')
            # For domain roles the name is '<group-id>:<type>'; for global it may be 'directive:<group-id>:<type>'
            role_type = parts[-1] if len(parts) >= 2 else 'option'
            target_text = (self.text or '').strip()
            if not target_text:
                return [nodes.literal(text='')], []

            # Use our domain registry to find candidates
            domain: SystemdDomain = self.env.get_domain('systemd')  # type: ignore
            candidates = domain._find_candidates(role_type, target_text)

            # Cross-kind fallback: try other kinds if no direct match
            if not candidates:
                kinds = []
                try:
                    kinds = (self.env.app.config.role_types or ['var', 'option', 'constant'])
                except Exception:
                    kinds = ['var', 'option', 'constant']
                for k in kinds:
                    if k == role_type:
                        continue
                    candidates = domain._find_candidates(k, target_text)
                    if candidates:
                        break

            if candidates:
                fromdocname = self.env.docname
                chosen = None
                for c in candidates:
                    if c.get('docname') == fromdocname:
                        chosen = c
                        break
                if not chosen:
                    chosen = candidates[0]

                builder = getattr(self.env.app, 'builder', None)
                ref = nodes.reference('', '', internal=True)
                if builder is not None:
                    ref['refuri'] = builder.get_relative_uri(fromdocname, chosen['docname']) + '#' + chosen['anchor']
                ref.append(nodes.literal(text=target_text))
                return [ref], []

            # Fallback: literal text if no match
            return [nodes.literal(text=target_text)], []
        except Exception:
            # Be resilient — don't break the build on compat handler errors
            return [nodes.literal(text=self.text or '')], []



class SystemdDomain(Domain):
    """
    Sphinx domain to model systemd documentation objects:
      - env (environment variables)
      - option (command-line options or configuration options)
      - constant (named constants)
    """
    name = 'systemd'
    label = 'Systemd'

    initial_data: Dict[str, Any] = {
        'objects': {},
    }

    roles = {
        'var': XRefRole(),       # :systemd:var:`$SYSTEMD_LOG_LEVEL`
        'env': XRefRole(),       # alias if used anywhere
        'option': XRefRole(),    # :systemd:option:`--copy-locale`
        'constant': XRefRole(),  # :systemd:constant:`SIGTERM`
    }

    directives = {
        'var': SystemdObject,
        'env': SystemdObject,       # alias if used anywhere
        'option': SystemdObject,
        'constant': SystemdObject,
    }

    object_types = {
        'var': ObjType('var', 'var'),
        'env': ObjType('env', 'env'),
        'option': ObjType('option', 'option'),
        'constant': ObjType('constant', 'constant'),
    }

    @property
    def objects(self) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
        return self.data.setdefault('objects', {})  # type: ignore

    def add_object(self, kind: str, normalized_name: str, entry: Dict[str, Any]) -> None:
        key = (kind, normalized_name)
        lst = self.objects.setdefault(key, [])
        lst.append(entry)
        logger.debug("systemd domain: add_object kind=%s name=%s at %s -> %s",
                     kind, normalized_name, entry.get('docname'), entry.get('anchor'))

    def _find_candidates(self, kind: str, target: str) -> List[Dict[str, Any]]:
        norm = _normalize_name(target)
        return list(self.objects.get((kind, norm), []))

    def resolve_xref(self, env: BuildEnvironment, fromdocname: str, builder,
                     typ: str, target: str, node: nodes.Element, contnode: nodes.Node) -> Optional[nodes.reference]:
        """
        Resolve :systemd:<kind>:`target` with same-doc-first; if none, try other kinds.
        Supports optional doc qualifier in the form "docname:Target" for disambiguation.
        """
        # Parse optional doc qualifier before ':'.
        # For the 'option' role we treat the prefix before ':' as a doc qualifier unconditionally.
        # For other roles we apply heuristics to avoid breaking targets that legitimately contain ':'.
        doc_qual = None
        name_target = target
        if ':' in target:
            q, rest = target.split(':', 1)
            if q.strip() and rest.strip():
                if typ == 'option':
                    doc_qual = q.strip()
                    name_target = rest.strip()
                else:
                    # Decide if q looks like a docname by matching against env.found_docs
                    def _looks_like_doc_qual(qual: str) -> bool:
                        try:
                            found = getattr(env, 'found_docs', set()) or set()
                        except Exception:
                            found = set()
                        base = (qual or '').strip()
                        if found:
                            for dn in found:
                                if dn == base:
                                    return True
                                if dn.endswith('/' + base):
                                    return True
                                if '/' not in base and dn.split('/')[-1] == base:
                                    return True
                                try:
                                    if _doc_slug(dn) == base:
                                        return True
                                except Exception:
                                    pass
                        # Fallback heuristics if env.found_docs is not available
                        return base.startswith('docs/') or ('.' in base) or ('-' in base)
                    if _looks_like_doc_qual(q.strip()):
                        doc_qual = q.strip()
                        name_target = rest.strip()
        candidates = self._find_candidates(typ, name_target)

        # Cross-kind fallback if none found for requested typ
        if not candidates:
            kinds = []
            try:
                kinds = (env.config.role_types or ['var', 'option', 'constant'])
            except Exception:
                kinds = ['var', 'option', 'constant']
            for k in kinds:
                if k == typ:
                    continue
                candidates = self._find_candidates(k, name_target)
                if candidates:
                    break


        if not candidates:
            logger.debug("systemd domain: no candidates for %s:%s", typ, name_target)
            return None

        # If a doc qualifier was provided, prefer entries from that doc
        def _docname_matches(docname: str, qual: str) -> bool:
            base = (qual or '').strip()
            if not base:
                return True
            if docname == base:
                return True
            if docname.endswith('/' + base):
                return True
            # Compare against basename only
            if '/' not in base and docname.split('/')[-1] == base:
                return True
            # Allow matching on slug form (dots -> dashes)
            try:
                if _doc_slug(docname) == base:
                    return True
            except Exception:
                pass
            # Common prefix used in this project
            if base.startswith('docs/') and docname == base:
                return True
            return False

        if doc_qual:
            filtered = [e for e in candidates if _docname_matches(e.get('docname', ''), doc_qual)]
            if filtered:
                candidates = filtered

        # Selection and destination calculation
        chosen = None
        dest_docname: Optional[str] = None
        dest_anchor: Optional[str] = None

        if doc_qual:
            # Prefer an entry from the qualified document if any
            try:
                has_match = any(_docname_matches(e.get('docname', ''), doc_qual) for e in candidates)
            except Exception:
                has_match = False

            if has_match:
                for e in candidates:
                    if _docname_matches(e.get('docname', ''), doc_qual):
                        chosen = e
                        break
                dest_docname = chosen.get('docname')  # type: ignore[union-attr]
                dest_anchor = chosen.get('anchor')    # type: ignore[union-attr]
            else:
                # No object defined in the qualified doc.
                # Fallback: link to the qualified document itself (top of page), if it exists.
                def _resolve_docname(qual: str) -> Optional[str]:
                    base = (qual or '').strip()
                    try:
                        found = getattr(env, 'found_docs', set()) or set()
                    except Exception:
                        found = set()
                    # If Sphinx provided found_docs, try to match against it
                    if found:
                        # Exact
                        for dn in found:
                            if dn == base:
                                return dn
                        # Suffix (…/basename)
                        for dn in found:
                            if dn.endswith('/' + base):
                                return dn
                        # Basename
                        if '/' not in base:
                            for dn in found:
                                if dn.split('/')[-1] == base:
                                    return dn
                        # Slug (dots -> dashes)
                        for dn in found:
                            try:
                                if _doc_slug(dn) == base:
                                    return dn
                            except Exception:
                                pass
                    # Fallback guesses when found_docs is empty or no match found
                    guesses: List[str] = []
                    if base.startswith('docs/'):
                        guesses.append(base)
                    else:
                        guesses.append(f"docs/{base}")
                        guesses.append(base)
                        # slug-like "systemd-unit" -> "systemd.unit"
                        if ('-' in base) and ('.' not in base):
                            guesses.append(f"docs/{base.replace('-', '.')}")
                            guesses.append(base.replace('-', '.'))
                    # Prefer guesses that are known in metadata if available
                    try:
                        meta_keys = set(getattr(env, 'metadata', {}).keys())
                    except Exception:
                        meta_keys = set()
                    for g in guesses:
                        if not meta_keys or g in meta_keys:
                            return g
                    # As last resort return the first guess
                    return guesses[0] if guesses else None

                dest_docname = _resolve_docname(doc_qual)
                if not dest_docname:
                    # Ultimate fallback: use first available candidate
                    chosen = candidates[0]
                    dest_docname = chosen.get('docname')
                    dest_anchor = chosen.get('anchor')
                    logger.debug("systemd domain: doc-qualified target %s:%s not found; falling back to %s",
                                 doc_qual, name_target, dest_docname)
        else:
            # Same-doc-first selection
            for c in candidates:
                if c.get('docname') == fromdocname:
                    chosen = c
                    break
            if not chosen:
                chosen = candidates[0]
            dest_docname = chosen.get('docname')
            dest_anchor = chosen.get('anchor')

        # Build the final reference URI
        refuri = builder.get_relative_uri(fromdocname, dest_docname or chosen.get('docname'))  # type: ignore[union-attr]
        if dest_anchor:
            refuri += '#' + dest_anchor

        refnode = nodes.reference('', '', internal=True)
        refnode['refuri'] = refuri
        label = contnode
        try:
            if not node.get('refexplicit'):
                label = nodes.literal(text=name_target)
        except Exception:
            if not label:
                label = nodes.literal(text=name_target)
        refnode.append(label)
        return refnode

    def get_objects(self):
        """
        Optional: allow generic index roles to enumerate our objects.
        """
        for (kind, norm), entries in self.objects.items():
            # yield one representative tuple per 'object key'
            if not entries:
                continue
            # Choose a primary name (first recorded spelling)
            name = entries[0].get('name') or norm
            # dispname, typ, docname, anchor, prio
            for e in entries:
                yield (name, name, kind, e['docname'], e['anchor'], 0)

    # Purge data for a doc being removed
    def clear_doc(self, docname: str) -> None:
        to_delete = []
        for key, entries in self.objects.items():
            self.objects[key] = [e for e in entries if e.get('docname') != docname]
            if not self.objects[key]:
                to_delete.append(key)
        for key in to_delete:
            del self.objects[key]
        logger.debug("systemd domain: cleared objects for %s", docname)

    def merge_domaindata(self, docnames, otherdata):
        """Merge parallel build data produced by workers."""
        my_objects = self.data.setdefault('objects', {})
        worker_objects = otherdata.get('objects', {})

        for key, entries in worker_objects.items():
            if key not in my_objects:
                # Just take the whole list of objects from the worker
                my_objects[key] = list(entries)
            else:
                # Append objects from the worker
                # (Sphinx ensures no duplicates across workers)
                my_objects[key].extend(entries)


class SystemdDirectiveIndexGroup(nodes.General, nodes.Element):
    """Placeholder node inside each group section where the definition list will be inserted."""
    pass


class SystemdDirectiveIndex(SphinxDirective):
    """
    .. systemd:directiveindex::

    Create real section nodes immediately so they are registered in the section tree/TOC.
    The contents are populated later at doctree-resolved,
    once the domain has collected all objects.
    """
    has_content = False

    def run(self) -> List[nodes.Node]:
        sections: List[nodes.Node] = []

        # Groups configured in conf.py: directives_data = [{id, title, description}, ...]
        try:
            directives_data: List[Dict[str, Any]] = list(self.env.app.config.directives_data or [])
        except Exception:
            directives_data = []

        # Emit one section per configured group
        for g in directives_data:
            gid = (g.get('id') or '').strip()
            if not gid:
                continue

            section_id = f"systemd-group-{nodes.make_id(gid)}"
            sec = nodes.section(ids=[section_id])

            # Title and optional description paragraph
            sec += nodes.title(text=g.get('title', gid))
            desc = (g.get('description') or '').strip()
            if desc:
                sec += nodes.paragraph(text=desc)

            # Placeholder where we will insert the definition list later
            placeholder = SystemdDirectiveIndexGroup()
            placeholder['group_id'] = gid
            sec += placeholder

            sections.append(sec)

        # Always include a catch-all "Miscellaneous" section for unconfigured groups
        misc_gid = 'miscellaneous'
        section_id = f"systemd-group-{nodes.make_id(misc_gid)}"
        sec = nodes.section(ids=[section_id])
        sec += nodes.title(text='Miscellaneous')
        placeholder = SystemdDirectiveIndexGroup()
        placeholder['group_id'] = misc_gid
        sec += placeholder
        sections.append(sec)

        return sections


def process_systemd_directive_index(app: Sphinx, doctree, from_doc_name: str) -> None:
    """
    Populate dls inside pre-created group sections of the directive index.

    Sections are created early by the directive's run() to ensure TOC/section registration, otherwise the titles won’t show up in the HTML sidebar
    Here we only fill the per-group contents with links.
    """
    try:
        domain: SystemdDomain = app.builder.env.get_domain('systemd')  # type: ignore
    except Exception:
        return

    directives_data: List[Dict[str, Any]] = app.config.directives_data or []
    configured_groups = [d.get('id') for d in directives_data if d.get('id')]

    # Build grouping: group_id -> ( (kind, norm_name) -> [entries] )
    grouped: Dict[str, Dict[Tuple[str, str], List[Dict[str, Any]]]] = {}
    for (kind, norm), entries in domain.objects.items():
        grp = entries[0].get('group') or 'miscellaneous'
        grouped.setdefault(grp, {}).setdefault((kind, norm), []).extend(entries)

    # Helper to render one group's list
    def make_group_dlist(group_id: str) -> Optional[nodes.definition_list]:
        entries_by_obj: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

        if group_id == 'miscellaneous':
            # Put everything not in configured_groups into miscellaneous
            extras = {gid: eb for gid, eb in grouped.items() if gid not in configured_groups}
            for eb in extras.values():
                for k, v in eb.items():
                    entries_by_obj.setdefault(k, []).extend(v)
        else:
            entries_by_obj = grouped.get(group_id, {})

        if not entries_by_obj:
            return None

        dlist = nodes.definition_list()
        for (kind, norm_name), entries in sorted(entries_by_obj.items(), key=lambda x: (x[0][0], x[0][1])):
            title_text = entries[0].get('name') or norm_name

            term = nodes.term()
            term += nodes.Text(title_text)

            dd = nodes.definition()
            links_para = nodes.paragraph()
            linked_docs: List[str] = []
            for e in entries:
                dn = e['docname']
                if dn in linked_docs:
                    continue
                linked_docs.append(dn)
                ref = nodes.reference('', '', internal=True)
                ref['refuri'] = app.builder.get_relative_uri(from_doc_name, dn) + '#' + e['anchor']
                meta = app.builder.env.metadata.get(dn, {})
                meta_title = meta.get('title', 'Unknown Title')
                meta_vol = meta.get('manvolnum', 'Unknown Volume')
                ref.append(nodes.Text(f"{meta_title}({meta_vol})"))
                if len(links_para):
                    links_para += nodes.Text(", ")
                links_para += ref
            dd += links_para

            dli = nodes.definition_list_item('', term, dd)
            dlist += dli

        return dlist

    # Replace placeholders with actual content
    for placeholder in list(doctree.traverse(SystemdDirectiveIndexGroup)):  # type: ignore[name-defined]
        gid = placeholder.get('group_id', 'miscellaneous')
        dlist = make_group_dlist(gid)
        placeholder.replace_self([dlist] if dlist is not None else [])
    # If not found, nothing to replace in this doctree





def setup(app: Sphinx) -> ExtensionMetadata:
    # Ensure our config values exist with sensible defaults
    app.add_config_value('directives_data', [], 'env')
    app.add_config_value('role_types', ['var', 'option', 'constant'], 'env')

    app.add_domain(SystemdDomain)

    app.add_directive('systemd:directiveindex', SystemdDirectiveIndex)

    # Populate the directive index contents late enough to resolve cross-doc links,
    # but sections themselves are created in the directive's run().
    app.connect('doctree-resolved', process_systemd_directive_index)

    logger.info("Systemd domain extension loaded")
    return {
        'version': '0.1',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
