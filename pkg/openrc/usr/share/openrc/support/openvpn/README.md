Example OpenVPN Scripts
=======================

These handy scripts setup any dns information that OpenVPN may push.
They also handle the interaction with OpenRC so that the OpenVPN service
can become "inactive". This means that when it starts, it goes inactive and
OpenRC continues on its merry way booting the system. When OpenVPN connects
to an endpoint it then re-starts the OpenVPN service and starts up any
services that depend on us. A similar thing happens when we shut down.

Of course, this is all optional.
