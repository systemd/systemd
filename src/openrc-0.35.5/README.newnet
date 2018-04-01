OpenRC Network Ideals
---------------------

The new style networking for OpenRC is very simplistic - provide a basic means
of configuring static interface address and routes whilst allowing the
possibility to run any command at any point.

In a nutshell, init.d/network is a wrapper around ifconfig(8) and
init.d/staticroute is wrapper around route(8).

In the Perfect World (TM) ifconfig should be able to configure everything
about the interface easily * . The BSD family almost get this right and Linux
epically fails.

* Only static configuration, including link setup.
For dynamic, static, IPv4LL, arping and per ssid IPv4 setup dhcpcd-5.x
provides your needs.

It fails because there are many tools to do the same job and often have
vastly different syntax where they could be similar. In other words, there
is no coherence.

OpenRC-0.4.x and older (inc Gentoo baselayout-1) had a collection of scripts
for each tool and allowed a script per interface. Over the years, this design
has proven very hard to maintain as each user has their own idea of how
things should work. Also, there were (and still are) race conditions.

So where do we go from here?
Well, it's possible to use the new network scripts using the tools
currently available. It's just harder as you have to know them and their
documentation can be lacking at times.
The correct end goal is a BSD style ifconfig tool.
I've started work on it, but the project has stalled somewhat.
It's display only right now and the source is not yet publicly available.
If you have the skills and share the vision then contact me privately and
we'll take it from there.
