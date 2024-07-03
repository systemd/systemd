:orphan:

Environment
###########

.. inclusion-marker-do-not-remove log-level

``$SYSTEMD_LOG_LEVEL``
----------------------
.. inclusion-marker-do-not-remove log-level-body

   The maximum log level of emitted messages (messages with a higher
   log level, i.e. less important ones, will be suppressed). Takes a comma-separated list of values. A
   value may be either one of (in order of decreasing importance) ``emerg``,
   ``alert``, ``crit``, ``err``,
   ``warning``, ``notice``, ``info``,
   ``debug``, or an integer in the range 0…7. See
   `syslog(3) <https://man7.org/linux/man-pages/man3/syslog.3.html>`_
   for more information. Each value may optionally be prefixed with one of ``console``,
   ``syslog``, ``kmsg`` or ``journal`` followed by a
   colon to set the maximum log level for that specific log target (e.g.
   ``SYSTEMD_LOG_LEVEL=debug,console:info`` specifies to log at debug level except when
   logging to the console which should be at info level). Note that the global maximum log level takes
   priority over any per target maximum log levels.

.. inclusion-end-marker-do-not-remove log-level-body

.. inclusion-end-marker-do-not-remove log-level

.. inclusion-marker-do-not-remove log-color

``$SYSTEMD_LOG_COLOR``
----------------------
.. inclusion-marker-do-not-remove log-color-body

   A boolean. If true, messages written to the tty will be colored
   according to priority.

   This setting is only useful when messages are written directly to the terminal, because
   :ref:`journalctl(1)` and
   other tools that display logs will color messages based on the log level on their own.

.. inclusion-end-marker-do-not-remove log-color-body

.. inclusion-end-marker-do-not-remove log-color

.. inclusion-marker-do-not-remove log-time

``$SYSTEMD_LOG_TIME``
---------------------
.. inclusion-marker-do-not-remove log-time-body

   A boolean. If true, console log messages will be prefixed with a
   timestamp.

   This setting is only useful when messages are written directly to the terminal or a file, because
   :ref:`journalctl(1)` and
   other tools that display logs will attach timestamps based on the entry metadata on their own.

.. inclusion-end-marker-do-not-remove log-time-body

.. inclusion-end-marker-do-not-remove log-time

.. inclusion-marker-do-not-remove log-location

``$SYSTEMD_LOG_LOCATION``
-------------------------

.. inclusion-marker-do-not-remove log-location-body

   A boolean. If true, messages will be prefixed with a filename
   and line number in the source code where the message originates.

   Note that the log location is often attached as metadata to journal entries anyway. Including it
   directly in the message text can nevertheless be convenient when debugging programs.

.. inclusion-end-marker-do-not-remove log-location-body

.. inclusion-end-marker-do-not-remove log-location

.. inclusion-marker-do-not-remove log-tid

``$SYSTEMD_LOG_TID``
--------------------
.. inclusion-marker-do-not-remove log-tid-body

   A boolean. If true, messages will be prefixed with the current
   numerical thread ID (TID).

   Note that the this information is attached as metadata to journal entries anyway. Including it
   directly in the message text can nevertheless be convenient when debugging programs.

.. inclusion-end-marker-do-not-remove log-tid-body

.. inclusion-end-marker-do-not-remove log-tid

.. inclusion-marker-do-not-remove log-target

``$SYSTEMD_LOG_TARGET``
-----------------------
.. inclusion-marker-do-not-remove log-target-body

   The destination for log messages. One of
   ``console`` (log to the attached tty), ``console-prefixed`` (log to
   the attached tty but with prefixes encoding the log level and "facility", see `syslog(3) <https://man7.org/linux/man-pages/man3/syslog.3.html>`_,
   ``kmsg`` (log to the kernel circular log buffer), ``journal`` (log to
   the journal), ``journal-or-kmsg`` (log to the journal if available, and to kmsg
   otherwise), ``auto`` (determine the appropriate log target automatically, the default),
   ``null`` (disable log output).

   .. COMMENT: <constant>syslog</constant>, <constant>syslog-or-kmsg</constant> are deprecated

.. inclusion-end-marker-do-not-remove log-target-body

.. inclusion-end-marker-do-not-remove log-target

.. inclusion-marker-do-not-remove log-ratelimit-kmsg

``$SYSTEMD_LOG_RATELIMIT_KMSG``
-------------------------------
.. inclusion-marker-do-not-remove log-ratelimit-kmsg-body

   Whether to ratelimit kmsg or not. Takes a boolean.
   Defaults to ``true``. If disabled, systemd will not ratelimit messages written to kmsg.

.. inclusion-end-marker-do-not-remove log-ratelimit-kmsg-body

.. inclusion-end-marker-do-not-remove log-ratelimit-kmsg

.. inclusion-marker-do-not-remove pager

``$SYSTEMD_PAGER``
------------------
.. inclusion-marker-do-not-remove pager-body

   Pager to use when ``--no-pager`` is not given; overrides
   ``$PAGER``. If neither ``$SYSTEMD_PAGER`` nor ``$PAGER`` are set, a
   set of well-known pager implementations are tried in turn, including
   `less(1) <https://man7.org/linux/man-pages/man1/less.1.html>`_ and
   `more(1) <https://man7.org/linux/man-pages/man1/more.1.html>`_, until one is found. If
   no pager implementation is discovered no pager is invoked. Setting this environment variable to an empty string
   or the value ``cat`` is equivalent to passing ``--no-pager``.

   Note: if ``$SYSTEMD_PAGERSECURE`` is not set, ``$SYSTEMD_PAGER``
   (as well as ``$PAGER``) will be silently ignored.

.. inclusion-end-marker-do-not-remove pager-body

.. inclusion-end-marker-do-not-remove pager

.. inclusion-marker-do-not-remove less

``$SYSTEMD_LESS``
-----------------
.. inclusion-marker-do-not-remove less-body

   Override the options passed to ``less`` (by default
   ``FRSXMK``).

   Users might want to change two options in particular:

   ``K``
   -----
      This option instructs the pager to exit immediately when
      :kbd:`Ctrl` + :kbd:`C` is pressed. To allow
      ``less`` to handle :kbd:`Ctrl` + :kbd:`C`
      itself to switch back to the pager command prompt, unset this option.

      If the value of ``$SYSTEMD_LESS`` does not include ``K``,
      and the pager that is invoked is ``less``,
      :kbd:`Ctrl` + :kbd:`C` will be ignored by the
      executable, and needs to be handled by the pager.

   ``X``
   -----
      This option instructs the pager to not send termcap initialization and deinitialization
      strings to the terminal. It is set by default to allow command output to remain visible in the
      terminal even after the pager exits. Nevertheless, this prevents some pager functionality from
      working, in particular paged output cannot be scrolled with the mouse.

   Note that setting the regular ``$LESS`` environment variable has no effect
   for ``less`` invocations by systemd tools.

   See
   `less(1) <https://man7.org/linux/man-pages/man1/less.1.html>`_
   for more discussion.

.. inclusion-end-marker-do-not-remove less-body

.. inclusion-end-marker-do-not-remove less

.. inclusion-marker-do-not-remove lesscharset

``$SYSTEMD_LESSCHARSET``
------------------------

   Override the charset passed to ``less`` (by default ``utf-8``, if
   the invoking terminal is determined to be UTF-8 compatible).

   Note that setting the regular ``$LESSCHARSET`` environment variable has no effect
   for ``less`` invocations by systemd tools.

.. inclusion-end-marker-do-not-remove lesscharset

.. inclusion-marker-do-not-remove lesssecure

``$SYSTEMD_PAGERSECURE``
------------------------

   Takes a boolean argument. When true, the "secure" mode of the pager is enabled; if
   false, disabled. If ``$SYSTEMD_PAGERSECURE`` is not set at all, secure mode is enabled
   if the effective UID is not the same as the owner of the login session, see
   `geteuid(2) <https://man7.org/linux/man-pages/man2/geteuid.2.html>`_
   and :ref:`sd_pid_get_owner_uid(3)`.
   In secure mode, ``LESSSECURE=1`` will be set when invoking the pager, and the pager shall
   disable commands that open or create new files or start new subprocesses. When
   ``$SYSTEMD_PAGERSECURE`` is not set at all, pagers which are not known to implement
   secure mode will not be used. (Currently only
   `less(1) <https://man7.org/linux/man-pages/man1/less.1.html>`_
   implements secure mode.)

   Note: when commands are invoked with elevated privileges, for example under `sudo(8) <https://man7.org/linux/man-pages/man8/sudo.8.html>`_ or
   `pkexec(1) <http://linux.die.net/man/ 1/pkexec>`_, care
   must be taken to ensure that unintended interactive features are not enabled. "Secure" mode for the
   pager may be enabled automatically as describe above. Setting ``SYSTEMD_PAGERSECURE=0``
   or not removing it from the inherited environment allows the user to invoke arbitrary commands. Note
   that if the ``$SYSTEMD_PAGER`` or ``$PAGER`` variables are to be
   honoured, ``$SYSTEMD_PAGERSECURE`` must be set too. It might be reasonable to completely
   disable the pager using ``--no-pager`` instead.

.. inclusion-end-marker-do-not-remove lesssecure

.. inclusion-marker-do-not-remove colors

``$SYSTEMD_COLORS``
-------------------

   Takes a boolean argument. When true, ``systemd`` and related utilities
   will use colors in their output, otherwise the output will be monochrome. Additionally, the variable can
   take one of the following special values: ``16``, ``256`` to restrict the use
   of colors to the base 16 or 256 ANSI colors, respectively. This can be specified to override the automatic
   decision based on ``$TERM`` and what the console is connected to.

.. COMMENT: This is not documented on purpose, because it is not clear if $NO_COLOR will become supported
            widely enough. So let's provide support, but without advertising this.
            <varlistentry id='no-color'>
            <term><varname>$NO_COLOR</varname></term>
            <listitem><para>If set (to any value), and <varname>$SYSTEMD_COLORS</varname> is not set, equivalent to
            <option>SYSTEMD_COLORS=0</option>. See <ulink url="https://no-color.org/">no-color.org</ulink>.</para>
            </listitem>
            </varlistentry>

.. inclusion-end-marker-do-not-remove colors

.. inclusion-marker-do-not-remove urlify

``$SYSTEMD_URLIFY``
-------------------

   The value must be a boolean. Controls whether clickable links should be generated in
   the output for terminal emulators supporting this. This can be specified to override the decision that
   ``systemd`` makes based on ``$TERM`` and other conditions.

.. inclusion-end-marker-do-not-remove urlify
