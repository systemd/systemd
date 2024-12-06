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

extensions = ['sphinxcontrib.globalsubs',
              'directive_roles', 'external_man_links', 'autogen_index']

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
    'constant',
    'var',
    'option'
]
