Using runit with OpenRC
=======================

Beginning with OpenRC-0.21, we support using runit [1] in place of
start-stop-daemon for monitoring and restarting daemons.

## Setup

Documenting runit in detail is beyond the scope of this guide. It will
document how to set up OpenRC services to communicate with runit.

### Use Default start, stop and status functions

If you write your own start, stop and status functions in your service
script, none of this will work. You must allow OpenRC to use the default
functions.

### Dependencies

All OpenRC service scripts that want their daemons monitored by runit
should have the following line added to their dependencies to make sure
the runit scan directory is being monitored.

need runsvdir

### Variable Settings

The most important setting is the supervisor variable. At the top of
your service script, you should set this variable as follows:

supervisor=runit

The second variable you need is runit_service. This is the path to the
runit service you wish to control via OpenRC. The default is
/etc/sv/${RC_SVCNAME}. This means that for an OpenRC service
/etc/init.d/foo, you will need to create the same runit service in
/etc/sv/foo.

This is very early support, so feel free to file bugs if you have
issues.

[1] http://www.smarden.org/runit
