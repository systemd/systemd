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

.. autoclass:: Monotonic

.. autoattribute:: systemd.journal.DEFAULT_CONVERTERS



Journal access types
~~~~~~~~~~~~~~~~~~~~

.. autoattribute:: systemd.journal.LOCAL_ONLY
.. autoattribute:: systemd.journal.RUNTIME_ONLY
.. autoattribute:: systemd.journal.SYSTEM_ONLY

Journal event types
~~~~~~~~~~~~~~~~~~~

.. autoattribute:: systemd.journal.NOP
.. autoattribute:: systemd.journal.APPEND
.. autoattribute:: systemd.journal.INVALIDATE
