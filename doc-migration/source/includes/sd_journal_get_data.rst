

.. _sd_journal_get_data(3):

======================
sd_journal_get_data(3)
======================

**Name**

sd_journal_get_data — sd_journal_enumerate_data — sd_journal_enumerate_available_data — sd_journal_restart_data — SD_JOURNAL_FOREACH_DATA — sd_journal_set_data_threshold — sd_journal_get_data_threshold — Read data fields from the current journal entry
###########################################################################################################################################################################################################################################################

**Synopsis**

#include <systemd/sd-journal.h>

int ``sd_journal_get_data``
sd_journal *j
const char *field
const void \**data
size_t *length

int ``sd_journal_enumerate_data``
sd_journal *j
const void \**data
size_t *length

int ``sd_journal_enumerate_available_data``
sd_journal *j
const void \**data
size_t *length

void ``sd_journal_restart_data``
sd_journal *j

``SD_JOURNAL_FOREACH_DATA``
sd_journal *j
const void *data
size_t length

int ``sd_journal_set_data_threshold``
sd_journal *j
size_t sz

int ``sd_journal_get_data_threshold``
sd_journal *j
size_t *sz

=======================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================

Description
===========

``sd_journal_get_data()`` gets the data object associated with a specific field
from the current journal entry. It takes four arguments: the journal context object, a string with the
field name to request, plus a pair of pointers to pointer/size variables where the data object and its
size shall be stored in. The field name should be an entry field name. Well-known field names are listed in
:ref:`systemd.journal-fields(7)`,
but any field can be specified. The returned data is in a read-only memory map and is only valid until
the next invocation of ``sd_journal_get_data()``,
``sd_journal_enumerate_data()``,
``sd_journal_enumerate_available_data()``, or when the read pointer is altered. Note
that the data returned will be prefixed with the field name and ``=``. Also note that, by
default, data fields larger than 64K might get truncated to 64K. This threshold may be changed and turned
off with ``sd_journal_set_data_threshold()`` (see below).

``sd_journal_enumerate_data()`` may be used
to iterate through all fields of the current entry. On each
invocation the data for the next field is returned. The order of
these fields is not defined. The data returned is in the same
format as with ``sd_journal_get_data()`` and also
follows the same life-time semantics.

``sd_journal_enumerate_available_data()`` is similar to
``sd_journal_enumerate_data()``, but silently skips any fields which may be valid, but
are too large or not supported by current implementation.

``sd_journal_restart_data()`` resets the
data enumeration index to the beginning of the entry. The next
invocation of ``sd_journal_enumerate_data()``
will return the first field of the entry again.

Note that the ``SD_JOURNAL_FOREACH_DATA()`` macro may be used as a handy wrapper
around ``sd_journal_restart_data()`` and
``sd_journal_enumerate_available_data()``.

Note that these functions will not work before
:ref:`sd_journal_next(3)`
(or related call) has been called at least once, in order to
position the read pointer at a valid entry.

``sd_journal_set_data_threshold()`` may be
used to change the data field size threshold for data returned by
``sd_journal_get_data()``,
``sd_journal_enumerate_data()`` and
``sd_journal_enumerate_unique()``. This threshold
is a hint only: it indicates that the client program is interested
only in the initial parts of the data fields, up to the threshold
in size — but the library might still return larger data objects.
That means applications should not rely exclusively on this
setting to limit the size of the data fields returned, but need to
apply an explicit size limit on the returned data as well. This
threshold defaults to 64K by default. To retrieve the complete
data fields this threshold should be turned off by setting it to
0, so that the library always returns the complete data objects.
It is recommended to set this threshold as low as possible since
this relieves the library from having to decompress large
compressed data objects in full.

``sd_journal_get_data_threshold()`` returns
the currently configured data field size threshold.

Return Value
============

``sd_journal_get_data()`` returns 0 on success or a negative errno-style error
code. ``sd_journal_enumerate_data()`` and
``sd_journal_enumerate_available_data()`` return a positive integer if the next field
has been read, 0 when no more fields remain, or a negative errno-style error code.
``sd_journal_restart_data()`` doesn't return anything.
``sd_journal_set_data_threshold()`` and ``sd_journal_get_threshold()``
return 0 on success or a negative errno-style error code.

Errors
------

Returned errors may indicate the following problems:

-EINVAL
-------

   One of the required parameters is ``NULL`` or invalid.

   .. versionadded:: 246

-ECHILD
-------

   The journal object was created in a different process, library or module instance.

   .. versionadded:: 246

-EADDRNOTAVAIL
--------------

   The read pointer is not positioned at a valid entry;
   :ref:`sd_journal_next(3)`
   or a related call has not been called at least once.

   .. versionadded:: 246

-ENOENT
-------

   The current entry does not include the specified field.

   .. versionadded:: 246

-ENOMEM
-------

   Memory allocation failed.

   .. versionadded:: 246

-ENOBUFS
--------

   A compressed entry is too large.

   .. versionadded:: 246

-E2BIG
------

   The data field is too large for this computer architecture (e.g. above 4 GB on a
   32-bit architecture).

   .. versionadded:: 246

-EPROTONOSUPPORT
----------------

   The journal is compressed with an unsupported method or the journal uses an
   unsupported feature.

   .. versionadded:: 246

-EBADMSG
--------

   The journal is corrupted (possibly just the entry being iterated over).

   .. versionadded:: 246

-EIO
----

   An I/O error was reported by the kernel.

   .. versionadded:: 246

Notes
=====

.. include:: ./includes/threads-aware.rst
                    :start-after: .. inclusion-marker-do-not-remove strict
                    :end-before: .. inclusion-end-marker-do-not-remove strict

.. include:: ./includes/libsystemd-pkgconfig.rst
                    :start-after: .. inclusion-marker-do-not-remove pkgconfig-text
                    :end-before: .. inclusion-end-marker-do-not-remove pkgconfig-text

Examples
========

See
:ref:`sd_journal_next(3)`
for a complete example how to use
``sd_journal_get_data()``.

Use the
``SD_JOURNAL_FOREACH_DATA()`` macro to
iterate through all fields of the current journal
entry:

.. code-block:: sh

   …
   int print_fields(sd_journal *j) {
     const void *data;
     size_t length;
     SD_JOURNAL_FOREACH_DATA(j, data, length)
       printf("%.*s\n", (int) length, data);
   }
   …

History
=======

``sd_journal_get_data()``,
``sd_journal_enumerate_data()``,
``sd_journal_restart_data()``, and
``SD_JOURNAL_FOREACH_DATA()`` were added in version 187.

``sd_journal_set_data_threshold()`` and
``sd_journal_get_data_threshold()`` were added in version 196.

``sd_journal_enumerate_available_data()`` was added in version 246.

See Also
========

:ref:`systemd(1)`, :ref:`systemd.journal-fields(7)`, :ref:`sd-journal(3)`, :ref:`sd_journal_open(3)`, :ref:`sd_journal_next(3)`, :ref:`sd_journal_get_realtime_usec(3)`, :ref:`sd_journal_query_unique(3)`


