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

def extract_manpage_metadata(text: str):
    """
    Extract :title:, :summary:, and :manvolnum: from the first 10 lines of an RST file.
    Returns a dict with keys 'title', 'summary', 'manvolnum' or None if any is missing.
    """
    title = summary = manvol = None
    for line in text.splitlines()[:10]:
        stripped = line.strip()
        if not stripped:
            continue
        # Skip comment lines, e.g. '.. something', but allow '.. :field:' just in case
        if stripped.startswith("..") and not (
            stripped.startswith(".. :title:")
            or stripped.startswith(".. :summary:")
            or stripped.startswith(".. :manvolnum:")
        ):
            continue
        if stripped.startswith(":title:"):
            title = stripped[len(":title:"):].strip()
            continue
        if stripped.startswith(":summary:"):
            summary = stripped[len(":summary:"):].strip()
            continue
        if stripped.startswith(":manvolnum:"):
            manvol = stripped[len(":manvolnum:"):].strip()
            continue
        # Stop when we reach real content
        if not stripped.startswith(":"):
            break
    if title and summary and manvol:
        return {"title": title, "summary": summary, "manvolnum": manvol}
    return None

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
        html_output = """.. SPDX-License-Identifier: LGPL-2.1-or-later

systemd — System and Service Manager
====================================

.. only:: html

    * :doc:`directives`

"""
        man_output = """
.. only:: man

"""
        current_index_letter = ''
        for file in sorted(find_files(root_dir),
                           key=lambda x: (os.path.basename(x).lower(), x)):
            if file not in FILES_USED_ONLY_FOR_INCLUDES:
                filename = os.path.basename(file)
                first_letter = filename[0].upper()
                if current_index_letter != first_letter:
                    current_index_letter = first_letter
                    letter_output = f"""
   {first_letter}
   #

"""
                    html_output += letter_output
                    man_output += letter_output
                    html_output += f"""
   .. toctree::
      :maxdepth: 1
      :caption: {current_index_letter}
      :titlesonly:

"""
                display_name = filename
                meta = None
                with open(os.path.join(root_dir, f"{file}.rst"), "r", encoding="utf-8") as file_content:
                    meta = extract_manpage_metadata(file_content.read())

                if meta is not None:
                    html_output += f"      {meta['title']}({meta['manvolnum']}) — {meta['summary']} <{file}>\n"
                    man_output += f"   * **{meta['title']}**\({meta['manvolnum']}) — {meta['summary']}\n"
                else:
                    html_output += f"      {display_name}\n"
                    man_output += f"   * {display_name}\n"
        index_file.write(html_output + "\n\n" + man_output)

def setup(app: Sphinx) -> ExtensionMetadata:
    app.connect('builder-inited', generate_toctree)
    return {'version': '0.1', 'parallel_read_safe': True, 'parallel_write_safe': True, }
