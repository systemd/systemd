# SPDX-License-Identifier: LGPL-2.1-or-later
# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import sys
import os
project = 'systemd'
copyright = '2024, systemd'
author = 'systemd'


sys.path.append(os.path.abspath("./_ext"))


# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ['sphinxcontrib.globalsubs', 'directive_roles']

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'furo'
html_static_path = ['_static']
html_title = ''
html_css_files = [
    'css/custom.css',
]
html_theme_options = {
    # TODO: update these `source`-options with the proper values
    "source_repository": "https://github.com/neighbourhoodie/nh-systemd",
    "source_branch": "man_pages_in_sphinx",
    "source_directory": "doc-migration/source/",
    "light_logo": "systemd-logo.svg",
    "dark_logo": "systemd-logo.svg",
    "light_css_variables": {
        "color-brand-primary": "#35a764",
        "color-brand-content": "#35a764",
    },
}


man_pages = [
    ('busctl', 'busctl', 'Introspect the bus', None, '1'),
    ('journalctl', 'journalctl', 'Print log entries from the systemd journal', None, '1'),
    ('os-release', 'os-release', 'Operating system identification', None, '5'),
    ('systemd', 'systemd, init', 'systemd system and service manager', None, '1'),
]

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
    'DEFAULT_TIMEOUT': '{{DEFAULT_TIMEOUT_SEC}} s',
    'DEFAULT_USER_TIMEOUT': '{{DEFAULT_USER_TIMEOUT_SEC}} s',
    'DEFAULT_KEYMAP': '{{SYSTEMD_DEFAULT_KEYMAP}}',
    'fedora_latest_version': '40',
    'fedora_cloud_release': '1.10',
}
