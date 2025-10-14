.. SPDX-License-Identifier: LGPL-2.1-or-later

:orphan:

.. inclusion-marker-do-not-remove user

``--user``
----------

   Talk to the service manager of the calling user,
   rather than the service manager of the system.

.. inclusion-end-marker-do-not-remove user

.. inclusion-marker-do-not-remove system

``--system``
------------

   Talk to the service manager of the system. This is the
   implied default.

.. inclusion-end-marker-do-not-remove system

.. inclusion-marker-do-not-remove host

``-H, --host=``
---------------

   Execute the operation remotely. Specify a hostname, or a
   username and hostname separated by ``@``, to
   connect to. The hostname may optionally be suffixed by a
   port ssh is listening on, separated by ``:``, and then a
   container name, separated by ``/``, which
   connects directly to a specific container on the specified
   host. This will use SSH to talk to the remote machine manager
   instance. Container names may be enumerated with
   ``machinectl -H
   <HOST>``. Put IPv6 addresses in brackets.

.. inclusion-end-marker-do-not-remove host

.. inclusion-marker-do-not-remove machine

``-M, --machine=``
------------------

   Execute operation on a local container. Specify a container name to connect to, optionally
   prefixed by a user name to connect as and a separating ``@`` character. If the special
   string ``.host`` is used in place of the container name, a connection to the local
   system is made (which is useful to connect to a specific user's user bus: ``--user
   --machine=lennart@.host``). If the ``@`` syntax is not used, the connection is
   made as root user. If the ``@`` syntax is used either the left hand side or the right hand
   side may be omitted (but not both) in which case the local user name and ``.host`` are
   implied.

.. inclusion-end-marker-do-not-remove machine

.. inclusion-marker-do-not-remove capsule

``-C, --capsule=``
------------------

   Execute operation on a capsule. Specify a capsule name to connect to. See
   :ref:`capsule@.service(5)` for
   details about capsules.

   .. versionadded:: 256

.. inclusion-end-marker-do-not-remove capsule
