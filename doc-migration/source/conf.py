# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'systemd'
copyright = '2024, systemd'
author = 'systemd'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ['sphinxcontrib.globalsubs']

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

global_substitutions = {
  'v183': '183',
  'v184': '184',
  'v185': '185',
  'v186': '186',
  'v187': '187',
  'v188': '188',
  'v189': '189',
  'v190': '190',
  'v191': '191',
  'v192': '192',
  'v193': '193',
  'v194': '194',
  'v195': '195',
  'v196': '196',
  'v197': '197',
  'v198': '198',
  'v199': '199',
  'v200': '200',
  'v201': '201',
  'v202': '202',
  'v203': '203',
  'v204': '204',
  'v205': '205',
  'v206': '206',
  'v207': '207',
  'v208': '208',
  'v209': '209',
  'v210': '210',
  'v211': '211',
  'v212': '212',
  'v213': '213',
  'v214': '214',
  'v215': '215',
  'v216': '216',
  'v217': '217',
  'v218': '218',
  'v219': '219',
  'v220': '220',
  'v221': '221',
  'v222': '222',
  'v223': '223',
  'v224': '224',
  'v225': '225',
  'v226': '226',
  'v227': '227',
  'v228': '228',
  'v229': '229',
  'v230': '230',
  'v231': '231',
  'v232': '232',
  'v233': '233',
  'v234': '234',
  'v235': '235',
  'v236': '236',
  'v237': '237',
  'v238': '238',
  'v239': '239',
  'v240': '240',
  'v241': '241',
  'v242': '242',
  'v243': '243',
  'v244': '244',
  'v245': '245',
  'v246': '246',
  'v247': '247',
  'v248': '248',
  'v249': '249',
  'v250': '250',
  'v251': '251',
  'v252': '252',
  'v253': '253',
  'v254': '254',
  'v255': '255',
  'v256': '256',
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
