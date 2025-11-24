import os
from sphinx.application import Sphinx
from sphinx.util.console import bold
from sphinx.util.typing import ExtensionMetadata
from sphinx.util import logging

logger = logging.getLogger(__name__)
logger.info('AutoTOC Extension running…')

FILES_USED_ONLY_FOR_INCLUDES = [
  'docs/cgroup-sandboxing',
  'docs/common-variables',
  'docs/ethtool-link-mode',
  'docs/libsystemd-pkgconfig',
  'docs/standard-conf',
  'docs/standard-options',
  'docs/standard-specifiers',
  'docs/supported-controllers',
  'docs/system-only',
  'docs/system-or-user-ns',
  'docs/system-or-user-ns-mountfsd',
  'docs/tc',
  'docs/threads-aware',
  'docs/unit-states',
  'docs/user-system-options',
  'docs/version-info',
  'docs/vpick'
]

def find_files(root_dir):
    for subdir, _, files in os.walk(root_dir + '/docs'):
        if subdir == root_dir:
            continue
        for file in files:
            if file.endswith('.rst'):
                file_path = os.path.relpath(os.path.join(subdir, file), root_dir)
                # remove the .rst extension
                yield file_path[:-4]

def generate_toctree(app: Sphinx):
    root_dir = app.srcdir

    index_path = os.path.join(root_dir, 'index.rst')
    if not os.path.exists(index_path):
        logger.warning(
            f"{index_path} does not exist, skipping generation.")
        return

    with open(index_path, 'w') as index_file:
        index_file.write(""".. SPDX-License-Identifier: LGPL-2.1-or-later

systemd — System and Service Manager
===================================

.. toctree::
   :maxdepth: 1\n
""")

        # Implement a christmas-tree-style order
        for file in sorted(find_files(root_dir),
                           key=lambda x: (len(x.split('/')), x)):
            if file not in FILES_USED_ONLY_FOR_INCLUDES:
                index_file.write(f"   {file}\n")

        index_file.write("""
Indices and tables
==================

* :ref:`genindex`""")


def setup(app: Sphinx) -> ExtensionMetadata:
    app.connect('builder-inited', generate_toctree)
    return {'version': '0.1', 'parallel_read_safe': True, 'parallel_write_safe': True, }
