:orphan:

All functions listed here are thread-agnostic and only a single specific thread may operate on a
given object during its entire lifetime. It's safe to allocate multiple independent objects and use each from a
specific thread in parallel. However, it's not safe to allocate such an object in one thread, and operate or free it
from any other, even if locking is used to ensure these threads don't operate on it at the very same time.

All functions listed here are thread-safe and may be called in parallel from multiple threads.

The code described here uses
`getenv(3) <https://man7.org/linux/man-pages/man3/getenv.3.html>`_,
which is declared to be not multi-thread-safe. This means that the code calling the functions described
here must not call
`setenv(3) <https://man7.org/linux/man-pages/man3/setenv.3.html>`_
from a parallel thread. It is recommended to only do calls to ``setenv()``
from an early phase of the program when no other threads have been started.


