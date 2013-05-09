`systemd.login` module
=======================

.. automodule:: systemd.login
   :members:

.. autoclass:: Monitor
   :undoc-members:
   :inherited-members:

Example: polling for events
~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example shows that session/uid/seat/machine events can be waited
for (using e.g. `poll`). This makes it easy to integrate Monitor in an
external event loop:

  >>> import select
  >>> from systemd import login
  >>> m = login.Monitor("machine")
  >>> p = select.poll()
  >>> p.register(m, m.get_events())
  >>> login.machine_names()
  []
  >>> p.poll()
  [(3, 1)]
  >>> login.machine_names()
  ['fedora-19.nspawn']
