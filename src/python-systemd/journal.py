#  -*- Mode: python; coding:utf-8; indent-tabs-mode: nil -*- */
#
#  This file is part of systemd.
#
#  Copyright 2012 David Strauss <david@davidstrauss.net>
#  Copyright 2012 Zbigniew Jędrzejewski-Szmek <zbyszek@in.waw.pl>
#  Copyright 2012 Marti Raudsepp <marti@juffo.org>
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

from __future__ import division

import sys as _sys
import datetime as _datetime
import uuid as _uuid
import traceback as _traceback
import os as _os
import logging as _logging
if _sys.version_info >= (3,3):
    from collections import ChainMap as _ChainMap
from syslog import (LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR,
                    LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG)
from ._journal import __version__, sendv, stream_fd
from ._reader import (_Reader, NOP, APPEND, INVALIDATE,
                      LOCAL_ONLY, RUNTIME_ONLY,
                      SYSTEM, SYSTEM_ONLY, CURRENT_USER,
                      _get_catalog)
from . import id128 as _id128

if _sys.version_info >= (3,):
    from ._reader import Monotonic
else:
    Monotonic = tuple

def _convert_monotonic(m):
    return Monotonic((_datetime.timedelta(microseconds=m[0]),
                      _uuid.UUID(bytes=m[1])))

def _convert_source_monotonic(s):
    return _datetime.timedelta(microseconds=int(s))

def _convert_realtime(t):
    return _datetime.datetime.fromtimestamp(t / 1000000)

def _convert_timestamp(s):
    return _datetime.datetime.fromtimestamp(int(s) / 1000000)

def _convert_trivial(x):
    return x

if _sys.version_info >= (3,):
    def _convert_uuid(s):
        return _uuid.UUID(s.decode())
else:
    _convert_uuid = _uuid.UUID

DEFAULT_CONVERTERS = {
    'MESSAGE_ID': _convert_uuid,
    '_MACHINE_ID': _convert_uuid,
    '_BOOT_ID': _convert_uuid,
    'PRIORITY': int,
    'LEADER': int,
    'SESSION_ID': int,
    'USERSPACE_USEC': int,
    'INITRD_USEC': int,
    'KERNEL_USEC': int,
    '_UID': int,
    '_GID': int,
    '_PID': int,
    'SYSLOG_FACILITY': int,
    'SYSLOG_PID': int,
    '_AUDIT_SESSION': int,
    '_AUDIT_LOGINUID': int,
    '_SYSTEMD_SESSION': int,
    '_SYSTEMD_OWNER_UID': int,
    'CODE_LINE': int,
    'ERRNO': int,
    'EXIT_STATUS': int,
    '_SOURCE_REALTIME_TIMESTAMP': _convert_timestamp,
    '__REALTIME_TIMESTAMP': _convert_realtime,
    '_SOURCE_MONOTONIC_TIMESTAMP': _convert_source_monotonic,
    '__MONOTONIC_TIMESTAMP': _convert_monotonic,
    '__CURSOR': _convert_trivial,
    'COREDUMP': bytes,
    'COREDUMP_PID': int,
    'COREDUMP_UID': int,
    'COREDUMP_GID': int,
    'COREDUMP_SESSION': int,
    'COREDUMP_SIGNAL': int,
    'COREDUMP_TIMESTAMP': _convert_timestamp,
}

_IDENT_LETTER = set('ABCDEFGHIJKLMNOPQRTSUVWXYZ_')

def _valid_field_name(s):
    return not (set(s) - _IDENT_LETTER)

class Reader(_Reader):
    """Reader allows the access and filtering of systemd journal
    entries. Note that in order to access the system journal, a
    non-root user must be in the `systemd-journal` group.

    Example usage to print out all informational or higher level
    messages for systemd-udevd for this boot:

    >>> j = journal.Reader()
    >>> j.this_boot()
    >>> j.log_level(journal.LOG_INFO)
    >>> j.add_match(_SYSTEMD_UNIT="systemd-udevd.service")
    >>> for entry in j:
    ...    print(entry['MESSAGE'])

    See systemd.journal-fields(7) for more info on typical fields
    found in the journal.
    """
    def __init__(self, flags=0, path=None, files=None, converters=None):
        """Create an instance of Reader, which allows filtering and
        return of journal entries.

        Argument `flags` sets open flags of the journal, which can be one
        of, or ORed combination of constants: LOCAL_ONLY (default) opens
        journal on local machine only; RUNTIME_ONLY opens only
        volatile journal files; and SYSTEM_ONLY opens only
        journal files of system services and the kernel.

        Argument `path` is the directory of journal files. Note that
        `flags` and `path` are exclusive.

        Argument `converters` is a dictionary which updates the
        DEFAULT_CONVERTERS to convert journal field values. Field
        names are used as keys into this dictionary. The values must
        be single argument functions, which take a `bytes` object and
        return a converted value. When there's no entry for a field
        name, then the default UTF-8 decoding will be attempted. If
        the conversion fails with a ValueError, unconverted bytes
        object will be returned. (Note that ValueEror is a superclass
        of UnicodeDecodeError).

        Reader implements the context manager protocol: the journal
        will be closed when exiting the block.
        """
        super(Reader, self).__init__(flags, path, files)
        if _sys.version_info >= (3,3):
            self.converters = _ChainMap()
            if converters is not None:
                self.converters.maps.append(converters)
            self.converters.maps.append(DEFAULT_CONVERTERS)
        else:
            self.converters = DEFAULT_CONVERTERS.copy()
            if converters is not None:
                self.converters.update(converters)

    def _convert_field(self, key, value):
        """Convert value using self.converters[key]

        If `key` is not present in self.converters, a standard unicode
        decoding will be attempted.  If the conversion (either
        key-specific or the default one) fails with a ValueError, the
        original bytes object will be returned.
        """
        convert = self.converters.get(key, bytes.decode)
        try:
            return convert(value)
        except ValueError:
            # Leave in default bytes
            return value

    def _convert_entry(self, entry):
        """Convert entire journal entry utilising _covert_field"""
        result = {}
        for key, value in entry.items():
            if isinstance(value, list):
                result[key] = [self._convert_field(key, val) for val in value]
            else:
                result[key] = self._convert_field(key, value)
        return result

    def __iter__(self):
        """Part of iterator protocol.
        Returns self.
        """
        return self

    def __next__(self):
        """Part of iterator protocol.
        Returns self.get_next() or raises StopIteration.
        """
        ans = self.get_next()
        if ans:
            return ans
        else:
            raise StopIteration()

    if _sys.version_info < (3,):
        next = __next__

    def add_match(self, *args, **kwargs):
        """Add one or more matches to the filter journal log entries.
        All matches of different field are combined in a logical AND,
        and matches of the same field are automatically combined in a
        logical OR.
        Matches can be passed as strings of form "FIELD=value", or
        keyword arguments FIELD="value".
        """
        args = list(args)
        args.extend(_make_line(key, val) for key, val in kwargs.items())
        for arg in args:
            super(Reader, self).add_match(arg)

    def get_next(self, skip=1):
        """Return the next log entry as a mapping type, currently
        a standard dictionary of fields.

        Optional skip value will return the `skip`\-th log entry.

        Entries will be processed with converters specified during
        Reader creation.
        """
        if super(Reader, self)._next(skip):
            entry = super(Reader, self)._get_all()
            if entry:
                entry['__REALTIME_TIMESTAMP'] =  self._get_realtime()
                entry['__MONOTONIC_TIMESTAMP']  = self._get_monotonic()
                entry['__CURSOR']  = self._get_cursor()
                return self._convert_entry(entry)
        return dict()

    def get_previous(self, skip=1):
        """Return the previous log entry as a mapping type,
        currently a standard dictionary of fields.

        Optional skip value will return the -`skip`\-th log entry.

        Entries will be processed with converters specified during
        Reader creation.

        Equivalent to get_next(-skip).
        """
        return self.get_next(-skip)

    def query_unique(self, field):
        """Return unique values appearing in the journal for given `field`.

        Note this does not respect any journal matches.

        Entries will be processed with converters specified during
        Reader creation.
        """
        return set(self._convert_field(field, value)
            for value in super(Reader, self).query_unique(field))

    def wait(self, timeout=None):
        """Wait for a change in the journal. `timeout` is the maximum
        time in seconds to wait, or None, to wait forever.

        Returns one of NOP (no change), APPEND (new entries have been
        added to the end of the journal), or INVALIDATE (journal files
        have been added or removed).
        """
        us = -1 if timeout is None else int(timeout * 1000000)
        return super(Reader, self).wait(us)

    def seek_realtime(self, realtime):
        """Seek to a matching journal entry nearest to `realtime` time.

        Argument `realtime` must be either an integer unix timestamp
        or datetime.datetime instance.
        """
        if isinstance(realtime, _datetime.datetime):
            realtime = float(realtime.strftime("%s.%f")) * 1000000
        return super(Reader, self).seek_realtime(int(realtime))

    def seek_monotonic(self, monotonic, bootid=None):
        """Seek to a matching journal entry nearest to `monotonic` time.

        Argument `monotonic` is a timestamp from boot in either
        seconds or a datetime.timedelta instance. Argument `bootid`
        is a string or UUID representing which boot the monotonic time
        is reference to. Defaults to current bootid.
        """
        if isinstance(monotonic, _datetime.timedelta):
            monotonic = monotonic.totalseconds()
        monotonic = int(monotonic * 1000000)
        if isinstance(bootid, _uuid.UUID):
            bootid = bootid.hex
        return super(Reader, self).seek_monotonic(monotonic, bootid)

    def log_level(self, level):
        """Set maximum log `level` by setting matches for PRIORITY.
        """
        if 0 <= level <= 7:
            for i in range(level+1):
                self.add_match(PRIORITY="%d" % i)
        else:
            raise ValueError("Log level must be 0 <= level <= 7")

    def messageid_match(self, messageid):
        """Add match for log entries with specified `messageid`.

        `messageid` can be string of hexadicimal digits or a UUID
        instance. Standard message IDs can be found in systemd.id128.

        Equivalent to add_match(MESSAGE_ID=`messageid`).
        """
        if isinstance(messageid, _uuid.UUID):
            messageid = messageid.hex
        self.add_match(MESSAGE_ID=messageid)

    def this_boot(self, bootid=None):
        """Add match for _BOOT_ID equal to current boot ID or the specified boot ID.

        If specified, bootid should be either a UUID or a 32 digit hex number.

        Equivalent to add_match(_BOOT_ID='bootid').
        """
        if bootid is None:
            bootid = _id128.get_boot().hex
        else:
            bootid = getattr(bootid, 'hex', bootid)
        self.add_match(_BOOT_ID=bootid)

    def this_machine(self, machineid=None):
        """Add match for _MACHINE_ID equal to the ID of this machine.

        If specified, machineid should be either a UUID or a 32 digit hex number.

        Equivalent to add_match(_MACHINE_ID='machineid').
        """
        if machineid is None:
            machineid = _id128.get_machine().hex
        else:
            machineid = getattr(machineid, 'hex', machineid)
        self.add_match(_MACHINE_ID=machineid)


def get_catalog(mid):
    if isinstance(mid, _uuid.UUID):
        mid = mid.hex
    return _get_catalog(mid)

def _make_line(field, value):
        if isinstance(value, bytes):
                return field.encode('utf-8') + b'=' + value
        elif isinstance(value, int):
                return field + '=' + str(value)
        else:
                return field + '=' + value

def send(MESSAGE, MESSAGE_ID=None,
         CODE_FILE=None, CODE_LINE=None, CODE_FUNC=None,
         **kwargs):
        r"""Send a message to the journal.

        >>> journal.send('Hello world')
        >>> journal.send('Hello, again, world', FIELD2='Greetings!')
        >>> journal.send('Binary message', BINARY=b'\xde\xad\xbe\xef')

        Value of the MESSAGE argument will be used for the MESSAGE=
        field. MESSAGE must be a string and will be sent as UTF-8 to
        the journal.

        MESSAGE_ID can be given to uniquely identify the type of
        message. It must be a string or a uuid.UUID object.

        CODE_LINE, CODE_FILE, and CODE_FUNC can be specified to
        identify the caller. Unless at least on of the three is given,
        values are extracted from the stack frame of the caller of
        send(). CODE_FILE and CODE_FUNC must be strings, CODE_LINE
        must be an integer.

        Additional fields for the journal entry can only be specified
        as keyword arguments. The payload can be either a string or
        bytes. A string will be sent as UTF-8, and bytes will be sent
        as-is to the journal.

        Other useful fields include PRIORITY, SYSLOG_FACILITY,
        SYSLOG_IDENTIFIER, SYSLOG_PID.
        """

        args = ['MESSAGE=' + MESSAGE]

        if MESSAGE_ID is not None:
                id = getattr(MESSAGE_ID, 'hex', MESSAGE_ID)
                args.append('MESSAGE_ID=' + id)

        if CODE_LINE == CODE_FILE == CODE_FUNC == None:
                CODE_FILE, CODE_LINE, CODE_FUNC = \
                        _traceback.extract_stack(limit=2)[0][:3]
        if CODE_FILE is not None:
                args.append('CODE_FILE=' + CODE_FILE)
        if CODE_LINE is not None:
                args.append('CODE_LINE={:d}'.format(CODE_LINE))
        if CODE_FUNC is not None:
                args.append('CODE_FUNC=' + CODE_FUNC)

        args.extend(_make_line(key, val) for key, val in kwargs.items())
        return sendv(*args)

def stream(identifier, priority=LOG_DEBUG, level_prefix=False):
        r"""Return a file object wrapping a stream to journal.

        Log messages written to this file as simple newline sepearted
        text strings are written to the journal.

        The file will be line buffered, so messages are actually sent
        after a newline character is written.

        >>> stream = journal.stream('myapp')
        >>> stream
        <open file '<fdopen>', mode 'w' at 0x...>
        >>> stream.write('message...\n')

        will produce the following message in the journal::

          PRIORITY=7
          SYSLOG_IDENTIFIER=myapp
          MESSAGE=message...

        Using the interface with print might be more convinient:

        >>> from __future__ import print_function
        >>> print('message...', file=stream)

        priority is the syslog priority, one of `LOG_EMERG`,
        `LOG_ALERT`, `LOG_CRIT`, `LOG_ERR`, `LOG_WARNING`,
        `LOG_NOTICE`, `LOG_INFO`, `LOG_DEBUG`.

        level_prefix is a boolean. If true, kernel-style log priority
        level prefixes (such as '<1>') are interpreted. See
        sd-daemon(3) for more information.
        """

        fd = stream_fd(identifier, priority, level_prefix)
        return _os.fdopen(fd, 'w', 1)

class JournalHandler(_logging.Handler):
        """Journal handler class for the Python logging framework.

        Please see the Python logging module documentation for an
        overview: http://docs.python.org/library/logging.html.

        To create a custom logger whose messages go only to journal:

        >>> log = logging.getLogger('custom_logger_name')
        >>> log.propagate = False
        >>> log.addHandler(journal.JournalHandler())
        >>> log.warn("Some message: %s", detail)

        Note that by default, message levels `INFO` and `DEBUG` are
        ignored by the logging framework. To enable those log levels:

        >>> log.setLevel(logging.DEBUG)

        To redirect all logging messages to journal regardless of where
        they come from, attach it to the root logger:

        >>> logging.root.addHandler(journal.JournalHandler())

        For more complex configurations when using `dictConfig` or
        `fileConfig`, specify `systemd.journal.JournalHandler` as the
        handler class.  Only standard handler configuration options
        are supported: `level`, `formatter`, `filters`.

        To attach journal MESSAGE_ID, an extra field is supported:

        >>> import uuid
        >>> mid = uuid.UUID('0123456789ABCDEF0123456789ABCDEF')
        >>> log.warn("Message with ID", extra={'MESSAGE_ID': mid})

        Fields to be attached to all messages sent through this
        handler can be specified as keyword arguments. This probably
        makes sense only for SYSLOG_IDENTIFIER and similar fields
        which are constant for the whole program:

        >>> journal.JournalHandler(SYSLOG_IDENTIFIER='my-cool-app')

        The following journal fields will be sent:
        `MESSAGE`, `PRIORITY`, `THREAD_NAME`, `CODE_FILE`, `CODE_LINE`,
        `CODE_FUNC`, `LOGGER` (name as supplied to getLogger call),
        `MESSAGE_ID` (optional, see above), `SYSLOG_IDENTIFIER` (defaults
        to sys.argv[0]).
        """

        def __init__(self, level=_logging.NOTSET, **kwargs):
                super(JournalHandler, self).__init__(level)

                for name in kwargs:
                        if not _valid_field_name(name):
                                raise ValueError('Invalid field name: ' + name)
                if 'SYSLOG_IDENTIFIER' not in kwargs:
                        kwargs['SYSLOG_IDENTIFIER'] = _sys.argv[0]
                self._extra = kwargs

        def emit(self, record):
                """Write record as journal event.

                MESSAGE is taken from the message provided by the
                user, and PRIORITY, LOGGER, THREAD_NAME,
                CODE_{FILE,LINE,FUNC} fields are appended
                automatically. In addition, record.MESSAGE_ID will be
                used if present.
                """
                try:
                        msg = self.format(record)
                        pri = self.mapPriority(record.levelno)
                        mid = getattr(record, 'MESSAGE_ID', None)
                        send(msg,
                             MESSAGE_ID=mid,
                             PRIORITY=format(pri),
                             LOGGER=record.name,
                             THREAD_NAME=record.threadName,
                             CODE_FILE=record.pathname,
                             CODE_LINE=record.lineno,
                             CODE_FUNC=record.funcName,
                             **self._extra)
                except Exception:
                        self.handleError(record)

        @staticmethod
        def mapPriority(levelno):
                """Map logging levels to journald priorities.

                Since Python log level numbers are "sparse", we have
                to map numbers in between the standard levels too.
                """
                if levelno <= _logging.DEBUG:
                        return LOG_DEBUG
                elif levelno <= _logging.INFO:
                        return LOG_INFO
                elif levelno <= _logging.WARNING:
                        return LOG_WARNING
                elif levelno <= _logging.ERROR:
                        return LOG_ERR
                elif levelno <= _logging.CRITICAL:
                        return LOG_CRIT
                else:
                        return LOG_ALERT
