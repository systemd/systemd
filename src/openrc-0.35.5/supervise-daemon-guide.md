Using supervise-daemon
======================

Beginning with OpenRC-0.21 we have our own daemon supervisor,
supervise-daemon., which can start a daemon and restart it if it
terminates unexpectedly.

The following is a brief guide on using this capability.

## Use Default start, stop and status functions

If you write your own start, stop and status functions in your service
script, none of this will work. You must allow OpenRC to use the default
functions.

## Daemons must not fork

Any deamon that you would like to have monitored by supervise-daemon
must not fork. Instead, it must stay in the foreground. If the daemon
itself forks, the supervisor will be unable to monitor it.

If the daemon can be configured to not fork, this should be done in the
daemon's configuration file, or by adding a command line option that
instructs it not to fork to the command_args_foreground variable shown
below.

## Variable Settings

The most important setting is the supervisor variable. At the top of
your service script, you should set this variable as follows:

supervisor=supervise-daemon

Several other variables affect the way services behave under
supervise-daemon. They are documented on the  openrc-run man page, but I
will list them here for convenience:

pidfile=/pid/of/supervisor.pid

If you are using start-stop-daemon to monitor your scripts, the pidfile
is the path to the pidfile the daemon creates. If, on the other hand,
you are using supervise-daemon, this is the path to the pidfile the
supervisor creates.

command_args_foreground should be used if the daemon you want to monitor
forks and goes to the background by default. This should be set to the
command line option that instructs the daemon to stay in the foreground.

This is very early support, so feel free to file bugs if you have
issues.
