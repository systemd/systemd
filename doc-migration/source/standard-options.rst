:orphan:
.. inclusion-marker-do-not-remove help

``-h, --help``
--------------

   Print a short help text and exit.

.. inclusion-end-marker-do-not-remove help

.. inclusion-marker-do-not-remove version

``--version``
-------------

   Print a short version string and exit.

.. inclusion-end-marker-do-not-remove version

.. inclusion-marker-do-not-remove no-pager

``--no-pager``
--------------

   Do not pipe output into a pager.

.. inclusion-end-marker-do-not-remove no-pager

.. inclusion-marker-do-not-remove no-ask-password

``--no-ask-password``
---------------------

   Do not query the user for authentication for privileged operations.

.. inclusion-end-marker-do-not-remove no-ask-password

.. inclusion-marker-do-not-remove legend

``--legend``
------------

*Usage:* ``--legend=<BOOL>``

   Enable or disable printing of the legend, i.e. column headers and the footer with hints. The
   legend is printed by default, unless disabled with ``--quiet`` or similar.

.. inclusion-end-marker-do-not-remove legend

.. inclusion-marker-do-not-remove no-legend

``--no-legend``
---------------

   Do not print the legend, i.e. column headers and the
   footer with hints.

.. inclusion-end-marker-do-not-remove no-legend

.. inclusion-marker-do-not-remove cat-config

``--cat-config``
----------------

   Copy the contents of config files to standard output.
   Before each file, the filename is printed as a comment.

.. inclusion-end-marker-do-not-remove cat-config

.. inclusion-marker-do-not-remove tldr

``--tldr``
----------

   Copy the contents of config files to standard output. Only the "interesting" parts of the
   configuration files are printed, comments and empty lines are skipped. Before each file, the filename
   is printed as a comment.

.. inclusion-end-marker-do-not-remove tldr

.. inclusion-marker-do-not-remove json

``--json``
----------

*Usage:* ``--json=<MODE>``

   Shows output formatted as JSON. Expects one of ``short`` (for the
   shortest possible output without any redundant whitespace or line breaks), ``pretty``
   (for a pretty version of the same, with indentation and line breaks) or ``off`` (to turn
   off JSON output, the default).

.. inclusion-end-marker-do-not-remove json

.. inclusion-marker-do-not-remove j

``-j``
------

   Equivalent to ``--json=pretty`` if running on a terminal, and
   ``--json=short`` otherwise.

.. inclusion-end-marker-do-not-remove j

.. inclusion-marker-do-not-remove signal

``-s, --signal``
----------------

*Usage:* ``-s, --signal=``

   When used with ``kill``, choose which signal to send to selected processes. Must
   be one of the well-known signal specifiers such as ``SIGTERM``,
   ``SIGINT`` or ``SIGSTOP``. If omitted, defaults to
   ``SIGTERM``.

   The special value ``help`` will list the known values and the program will exit
   immediately, and the special value ``list`` will list known values along with the
   numerical signal numbers and the program will exit immediately.

.. inclusion-end-marker-do-not-remove signal

.. inclusion-marker-do-not-remove image-policy-open

``--image-policy``
------------------

*Usage:* ``--image-policy=<policy>``

   Takes an image policy string as argument, as per
   :ref:`systemd.image-policy(7)`. The
   policy is enforced when operating on the disk image specified via ``--image=``, see
   above. If not specified defaults to the ``*`` policy, i.e. all recognized file systems
   in the image are used.

.. inclusion-end-marker-do-not-remove image-policy-open

.. inclusion-marker-do-not-remove esp-path

``--esp-path``
--------------

*Usage:* ``--esp-path=``

   Path to the EFI System Partition (ESP). If not specified, ``/efi/``,
   ``/boot/``, and ``/boot/efi/`` are checked in turn. It is
   recommended to mount the ESP to ``/efi/``, if possible.

.. inclusion-end-marker-do-not-remove esp-path

.. inclusion-marker-do-not-remove boot-path

``--boot-path``
---------------

*Usage:* ``--boot-path=``

   Path to the Extended Boot Loader partition, as defined in the
   `Boot Loader Specification <https://uapi-group.org/specifications/specs/boot_loader_specification>`_.
   If not specified, ``/boot/`` is checked. It is recommended to mount the Extended Boot
   Loader partition to ``/boot/``, if possible.

.. inclusion-end-marker-do-not-remove boot-path

.. inclusion-marker-do-not-remove option-P

``-P``
------

   Equivalent to ``--value`` ``--property=``, i.e. shows the value of the
   property without the property name or ``=``. Note that using ``-P`` once
   will also affect all properties listed with ``-p``/``--property=``.

.. inclusion-end-marker-do-not-remove option-P
