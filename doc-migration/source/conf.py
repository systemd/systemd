# SPDX-License-Identifier: LGPL-2.1-or-later
# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import sys
import os
from pathlib import Path
from docutils import nodes

project = 'systemd'
copyright = '2024, systemd'
author = 'systemd'

language = 'en'

src_dir = Path(__file__).parent
docs_dir = src_dir / "docs"
cache_file = src_dir / "_man_pages_cache.json"

sys.path.append(os.path.abspath("./_ext"))

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ['systemd_domain', 'external_man_links', 'autogen_index', 'preprocessor', 'sphinx_reredirects']

templates_path = ['_templates']
include_patterns = ['index.rst', 'directives.rst', 'docs/*.rst']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store', 'includes/*.rst']


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'furo'
html_static_path = ['_static']
html_title = ''
html_css_files = [
    'css/custom.css',
]
html_js_files = [
    'js/custom.js',
]
html_theme_options = {
    # TODO: update these `source`-options with the proper values
    "source_repository": "https://github.com/neighbourhoodie/nh-systemd",
    "source_branch": "man_pages_in_sphinx",
    "source_directory": "doc-migration/source/",
    "sidebar_hide_name": True,
    "light_logo": "systemd-logo.svg",
    "dark_logo": "systemd-logo-dark.svg",
    "light_css_variables": {
        "color-brand-primary": "#35a764",
        "color-brand-content": "#35a764",
        "color-brand-visited": "#197b43"
    },
    "dark_css_variables": {
        "color-brand-primary": "#2fd576",
        "color-brand-content": "#2fd576",
        "color-brand-visited": "#b3efcd"
    }
}

redirects = {}

# Global alias map to be used by the patched ref role
alias_map = {}

def extract_manpage_metadata(text: str):
    title = summary = manvol = aliases = None
    for line in text.splitlines()[:10]:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("..") and not stripped.startswith(".. :"):
            continue

        if stripped.startswith(":title:"):
            title = stripped[len(":title:"):].strip()
        elif stripped.startswith(":summary:"):
            summary = stripped[len(":summary:"):].strip()
        elif stripped.startswith(":manvolnum:"):
            manvol = stripped[len(":manvolnum:"):].strip()
        elif stripped.startswith(":aliases:"):
            aliases = [
                a.strip() for a in stripped[len(":aliases:"):].split(",")
                if a.strip()
            ]
        elif not stripped.startswith(":"):
            break

    if title and summary and manvol:
        meta = {"title": title, "summary": summary, "manvolnum": manvol}
        if aliases:
            meta["aliases"] = aliases
        return meta
    return None

def generate_man_pages():
    man_pages = []
    for root, _, files in os.walk("."):
        for f in files:
            if f.endswith(".rst") and f not in ("index.rst",):
                path = os.path.join(root, f)
                docname = path[:-4]
                name = os.path.basename(docname)

                with open(path, encoding="utf-8") as fd:
                    meta = extract_manpage_metadata(fd.read())

                if meta is None:
                    continue

                canonical_name = f"{name}({meta["manvolnum"]})"

                man_pages.append((f"docs/{name}", meta["title"], meta["summary"], [], meta["manvolnum"]))

                if "aliases" in meta:
                    for alias in meta["aliases"]:
                        # Side effect 1: record aliases for use in :ref:
                        alias_map[f"{alias}({meta["manvolnum"]})"] = canonical_name
                        # TODO: Actually, the aliases can't be in man_pages,
                        # than only takes real pages. This might be fixable
                        # with an extension, but the intent needs to be
                        # clarified first.
                        # man_pages.append((alias, alias, meta["summary"], [], meta["manvolnum"]))

                        # Side effect 2: register http redirects for aliases
                        redirects[f"docs/{alias}"] = f"{name}.html"

    man_pages.append(('index', 'systemd.index', 'List all manpages from the systemd project', None, 7))
    man_pages.append(('directives', 'systemd.directives', 'Index of configuration directives', None, 7))
    return man_pages

def setup_alias_rewriter(app):
    from sphinx.addnodes import pending_xref

    def rewrite_aliases(app, doctree):
        for node in doctree.traverse(pending_xref):
            target = node.get('reftarget')
            if target in alias_map:
                original_label = ''.join(child.astext() for child in node.children)
                new_target = alias_map[target]
                node['reftarget'] = new_target
                # tell Sphinx not to auto-generate the label
                node['refexplicit'] = True

                # replace children with our preserved label
                node.children = [nodes.Text(original_label)]

    app.connect("doctree-read", rewrite_aliases)

def setup(app):
    setup_alias_rewriter(app)

def needs_regen(cache_file, docs_dir):
    if not cache_file.exists():
        return True
    cached_mtime = os.path.getmtime(cache_file)
    return any(f.stat().st_mtime > cached_mtime for f in docs_dir.glob("*.rst"))

man_pages = generate_man_pages()

# The function at the start generates version number substitutions, eg.
# {'v183': '183', 'v184': '184', etc…}
# These don't seem to be used, but we’re leaving them in just in case.
global_substitutions = {f'v{n}': f'{n}' for n in range(183, 300)} | {
    # Custom Entities
    'MOUNT_PATH': '{{MOUNT_PATH}}',
    'UMOUNT_PATH': '{{UMOUNT_PATH}}',
    'SYSTEM_GENERATOR_DIR': '{{SYSTEM_GENERATOR_DIR}}',
    'USER_GENERATOR_DIR': '{{USER_GENERATOR_DIR}}',
    'SYSTEM_ENV_GENERATOR_DIR': '{{SYSTEM_ENV_GENERATOR_DIR}}',
    'USER_ENV_GENERATOR_DIR': '{{USER_ENV_GENERATOR_DIR}}',
    'CERTIFICATE_ROOT': '{{CERTIFICATE_ROOT}}',
    'FALLBACK_HOSTNAME': '{{FALLBACK_HOSTNAME}}',
    'MEMORY_ACCOUNTING_DEFAULT': "{{ 'yes' if MEMORY_ACCOUNTING_DEFAULT else 'no' }}",
    'KILL_USER_PROCESSES': "{{ 'yes' if KILL_USER_PROCESSES else 'no' }}",
    'DEBUGTTY': '{{DEBUGTTY}}',
    'RC_LOCAL_PATH': '{{RC_LOCAL_PATH}}',
    'HIGH_RLIMIT_NOFILE': '{{HIGH_RLIMIT_NOFILE}}',
    'DEFAULT_DNSSEC_MODE': '{{DEFAULT_DNSSEC_MODE_STR}}',
    'DEFAULT_DNS_OVER_TLS_MODE': '{{DEFAULT_DNS_OVER_TLS_MODE_STR}}',
    'DEFAULT_TIMEOUT_SEC': '{{DEFAULT_TIMEOUT_SEC}} s',
    'DEFAULT_USER_TIMEOUT_SEC': '{{DEFAULT_USER_TIMEOUT_SEC}} s',
    'DEFAULT_KEYMAP': '{{SYSTEMD_DEFAULT_KEYMAP}}',
    'fedora_latest_version': '40',
    'fedora_cloud_release': '1.10',
    'SYSTEM_SYSVRCLOCAL_PATH': '{{SYSTEM_SYSVRCLOCAL_PATH}}',
    'SYSTEMD_DEFAULT_KEYMAP': '{{SYSTEMD_DEFAULT_KEYMAP}}',
    'JOURNAL_STORAGE_DEFAULT': '{{JOURNAL_STORAGE_DEFAULT}}',
}

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
        "title": '/etc/crypttab, /etc/veritytab and /etc/fstab options',
        "description": "Options which influence mounted filesystems and encrypted volumes."
    },
    {
        "id": "nspawn-directives",
        "title": 'systemd.nspawn(5)-directives',
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
    'constant',
    'var',
    'option'
]
