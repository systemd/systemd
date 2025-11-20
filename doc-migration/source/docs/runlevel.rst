.. SPDX-License-Identifier: LGPL-2.1-or-later:

:title: runlevel

:manvolnum: 8

.. _runlevel(8):

===========
runlevel(8)
===========

.. only:: html

   runlevel — Print previous and current SysV runlevel
   ###################################################

   Synopsis
   ########

``runlevel`` [options...]

Overview
========

"Runlevels" are an obsolete way to start and stop groups of
services used in SysV init. systemd provides a compatibility layer
that maps runlevels to targets, and associated binaries like
``runlevel``. Nevertheless, only one runlevel can
be "active" at a given time, while systemd can activate multiple
targets concurrently, so the mapping to runlevels is confusing
and only approximate. Runlevels should not be used in new code,
and are mostly useful as a shorthand way to refer the matching
systemd targets in kernel boot parameters.

.. list-table:: Mapping between runlevels and systemd targets
   :header-rows: 1

   * - Runlevel
     - Target
   * - 0
     - ``poweroff.target``
   * - 1
     - ``rescue.target``
   * - 2, 3, 4
     - ``multi-user.target``
   * - 5
     - ``graphical.target``
   * - 6
     - ``reboot.target``

Description
===========

``runlevel`` prints the previous and current
SysV runlevel if they are known.

The two runlevel characters are separated by a single space
character. If a runlevel cannot be determined, N is printed
instead. If neither can be determined, the word "unknown" is
printed.

Unless overridden in the environment, this will check the
utmp database for recent runlevel changes.

Options
=======

The following option is understood:

``--help``
----------

Exit status
===========

If one or both runlevels could be determined, 0 is returned,
a non-zero failure code otherwise.

Environment
===========

``$RUNLEVEL``
-------------

If :directive:environment-variables:var:`$RUNLEVEL` is set,
``runlevel`` will print this value as current
runlevel and ignore utmp.

``$PREVLEVEL``
--------------

If :directive:environment-variables:var:`$PREVLEVEL` is set,
``runlevel`` will print this value as previous
runlevel and ignore utmp.

Files
=====

``/run/utmp``
-------------

The utmp database ``runlevel`` reads the previous and current runlevel
from.

.. only:: html

   .. versionadded:: 237

See Also
========

:ref:`systemd(1)`, :ref:`systemd.target(5)`, :ref:`systemctl(1)`