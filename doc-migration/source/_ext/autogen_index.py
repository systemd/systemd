import os
from sphinx.application import Sphinx
from sphinx.util.console import bold
from sphinx.util.typing import ExtensionMetadata


def generate_toctree(app: Sphinx):
    root_dir = app.srcdir

    index_path = os.path.join(root_dir, 'index.rst')
    if not os.path.exists(index_path):
        app.logger.warning(
            f"{index_path} does not exist, skipping generation.")
        return

    with open(index_path, 'w') as index_file:
        index_file.write(""".. SPDX-License-Identifier: LGPL-2.1-or-later
.. systemd documentation master file, created by
   sphinx-quickstart on Wed Jun 26 16:24:13 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

systemd — System and Service Manager
===================================

.. manual reference to a doc by its reference label
   see: https://www.sphinx-doc.org/en/master/usage/referencing.html#cross-referencing-arbitrary-locations
.. Manual links
.. ------------
.. :ref:`busctl(1)`
.. :ref:`systemd(1)`
.. OR using the toctree to pull in files
   https://www.sphinx-doc.org/en/master/usage/restructuredtext/directives.html#directive-toctree
.. This only works if we restructure our headings to match
   https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html#sections
   and then only have single top-level heading with the command name

.. toctree::
   :maxdepth: 1\n
""")

        for subdir, _, files in os.walk(root_dir + '/docs'):
            if subdir == root_dir:
                continue
            for file in files:
                if file.endswith('.rst'):
                    file_path = os.path.relpath(
                        os.path.join(subdir, file), root_dir)
                    # remove the .rst extension
                    index_file.write(f"   {file_path[:-4]}\n")

        index_file.write("""
Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search` """)


def setup(app: Sphinx) -> ExtensionMetadata:
    app.connect('builder-inited', generate_toctree)
    return {'version': '0.1', 'parallel_read_safe': True, 'parallel_write_safe': True, }
