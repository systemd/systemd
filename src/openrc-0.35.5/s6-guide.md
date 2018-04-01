Using S6 with OpenRC
====================

Beginning with OpenRC-0.16, we support using the s6 supervision suite
from Skarnet Software in place of start-stop-daemon for monitoring
daemons [1].

## Setup

Documenting s6 in detail is beyond the scope of this guide. It will
document how to set up OpenRC services to communicate with s6.

### Use Default start, stop and status functions

If you write your own start, stop and status functions in your service
script, none of this will work. You must allow OpenRC to use the default
functions.

### Dependencies

All OpenRC service scripts that want their daemons monitored by s6
should have the following line added to their dependencies to make sure
the s6 scan directory is being monitored.

need s6-svscan

### Variable Settings

The most important setting is the supervisor variable. At the top of
your service script, you should set this variable as follows:

supervisor=s6

Several other variables affect s6 services. They are documented on the
openrc-run man page, but I will list them here for convenience:

s6_service_path - the path to the s6 service directory. The default is
/var/svc.d/$RC_SVCNAME.

s6_svwait_options_start - the options to pass to s6-svwait when starting
the service. If this is not set, s6-svwait will not be called.

s6_force_kill - Should we try to force kill this service if the
s6_service_timeout_stop timeout expires when shutting down this service?
The default is yes.

s6_service_timeout_stop - the amount of time, in milliseconds, s6-svc
should wait for a service to go down when stopping.

This is very early support, so feel free to file bugs if you have
issues.

[1] http://www.skarnet.org/software/s6
