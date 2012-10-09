#  -*- Mode: python; indent-tabs-mode: nil -*- */
#
#  This file is part of systemd.
#
#  Copyright 2012 David Strauss
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

import traceback as _traceback
import os as _os
import logging as _logging
from syslog import (LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR,
                    LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG)
from ._journal import sendv, stream_fd

def _make_line(field, value):
        if isinstance(value, bytes):
                return field.encode('utf-8') + b'=' + value
        else:
                return field + '=' + value

def send(MESSAGE, MESSAGE_ID=None,
         CODE_FILE=None, CODE_LINE=None, CODE_FUNC=None,
         **kwargs):
        r"""Send a message to journald.

        >>> journal.send('Hello world')
        >>> journal.send('Hello, again, world', FIELD2='Greetings!')
        >>> journal.send('Binary message', BINARY=b'\xde\xad\xbe\xef')

        Value of the MESSAGE argument will be used for the MESSAGE=
        field.

        MESSAGE_ID can be given to uniquely identify the type of
        message.

        Other parts of the message can be specified as keyword
        arguments.

        Both MESSAGE and MESSAGE_ID, if present, must be strings, and
        will be sent as UTF-8 to journal. Other arguments can be
        bytes, in which case they will be sent as-is to journal.

        CODE_LINE, CODE_FILE, and CODE_FUNC can be specified to
        identify the caller. Unless at least on of the three is given,
        values are extracted from the stack frame of the caller of
        send(). CODE_FILE and CODE_FUNC must be strings, CODE_LINE
        must be an integer.

        Other useful fields include PRIORITY, SYSLOG_FACILITY,
        SYSLOG_IDENTIFIER, SYSLOG_PID.
        """

        args = ['MESSAGE=' + MESSAGE]

        if MESSAGE_ID is not None:
                args.append('MESSAGE_ID=' + MESSAGE_ID)

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

        will produce the following message in the journal:

        PRIORITY=7
        SYSLOG_IDENTIFIER=myapp
        MESSAGE=message...

        Using the interface with print might be more convinient:

        >>> from __future__ import print_function
        >>> print('message...', file=stream)

        priority is the syslog priority, one of LOG_EMERG, LOG_ALERT,
        LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG.

        level_prefix is a boolean. If true, kernel-style log priority
        level prefixes (such as '<1>') are interpreted. See
        sd-daemon(3) for more information.
        """

        fd = stream_fd(identifier, priority, level_prefix)
        return _os.fdopen(fd, 'w', 1)

class JournalHandler(_logging.Handler):
        """Journal handler class for the Python logging framework.

        Please see the Python logging module documentation for an
        overview: http://docs.python.org/library/logging.html

        To create a custom logger whose messages go only to journal:

        >>> log = logging.getLogger('custom_logger_name')
        >>> log.propagate = False
        >>> log.addHandler(journal.JournalHandler())
        >>> log.warn("Some message: %s", detail)

        Note that by default, message levels INFO and DEBUG are ignored
        by the logging framework. To enable those log levels:

        >>> log.setLevel(logging.DEBUG)

        To attach journal MESSAGE_ID, an extra field is supported:

        >>> log.warn("Message with ID",
        >>>     extra={'MESSAGE_ID': '22bb01335f724c959ac4799627d1cb61'})

        To redirect all logging messages to journal regardless of where
        they come from, attach it to the root logger:

        >>> logging.root.addHandler(journal.JournalHandler())

        For more complex configurations when using dictConfig or
        fileConfig, specify 'systemd.journal.JournalHandler' as the
        handler class.  Only standard handler configuration options
        are supported: level, formatter, filters.

        The following journal fields will be sent:

        MESSAGE, PRIORITY, THREAD_NAME, CODE_FILE, CODE_LINE,
        CODE_FUNC, LOGGER (name as supplied to getLogger call),
        MESSAGE_ID (optional, see above).
        """

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
                             CODE_FUNC=record.funcName)
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
