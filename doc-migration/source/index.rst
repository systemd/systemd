.. systemd documentation master file, created by
   sphinx-quickstart on Wed Jun 26 16:24:13 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.
Welcome to systemd's documentation!
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
   :maxdepth: 1

   busctl
   journalctl
   systemd
   os-release

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
