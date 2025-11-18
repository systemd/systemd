.. SPDX-License-Identifier: LGPL-2.1-or-later:

.. inclusion-marker-do-not-remove strict

All functions listed here are thread-agnostic and only a single specific thread may operate on a
given object during its entire lifetime. It's safe to allocate multiple independent objects and use each from a
specific thread in parallel. However, it's not safe to allocate such an object in one thread, and operate or free it
from any other, even if locking is used to ensure these threads don't operate on it at the very same time.

.. inclusion-end-marker-do-not-remove strict

.. inclusion-marker-do-not-remove safe

All functions listed here are thread-safe and may be called in parallel from multiple threads.

.. inclusion-end-marker-do-not-remove safe

.. inclusion-marker-do-not-remove getenv

The code described here uses
:man-pages:`getenv(3)`,
which is declared to be not multi-thread-safe. This means that the code calling the functions described
here must not call
:man-pages:`setenv(3)`
from a parallel thread. It is recommended to only do calls to ``setenv()``
from an early phase of the program when no other threads have been started.

.. inclusion-end-marker-do-not-remove getenv