`systemd.journal` module
========================

.. automodule:: systemd.journal
   :members: send, sendv, stream, stream_fd
   :undoc-members:

`JournalHandler` class
----------------------

.. autoclass:: JournalHandler

Accessing the Journal
---------------------

.. autoclass:: _Reader
   :undoc-members:
   :inherited-members:

.. autoclass:: Reader
   :undoc-members:
   :inherited-members:

   .. automethod:: __init__

.. autofunction:: _get_catalog
.. autofunction:: get_catalog

.. autoclass:: Monotonic

.. autoattribute:: systemd.journal.DEFAULT_CONVERTERS

Example: polling for journal events
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example shows that journal events can be waited for (using
e.g. `poll`). This makes it easy to integrate Reader in an external
event loop:

  >>> import select
  >>> from systemd import journal
  >>> j = journal.Reader()
  >>> j.seek_tail()
  >>> p = select.poll()
  >>> p.register(j, j.get_events())
  >>> p.poll()
  [(3, 1)]
  >>> j.get_next()


Journal access types
~~~~~~~~~~~~~~~~~~~~

.. autoattribute:: systemd.journal.LOCAL_ONLY
.. autoattribute:: systemd.journal.RUNTIME_ONLY
.. autoattribute:: systemd.journal.SYSTEM
.. autoattribute:: systemd.journal.CURRENT_USER

Journal event types
~~~~~~~~~~~~~~~~~~~

.. autoattribute:: systemd.journal.NOP
.. autoattribute:: systemd.journal.APPEND
.. autoattribute:: systemd.journal.INVALIDATE
