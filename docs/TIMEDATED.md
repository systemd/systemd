---
title: On timedated
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

**This page has been obsoleted and replaced:** [ https://www.freedesktop.org/software/systemd/man/org.freedesktop.timedate1.html](https://www.freedesktop.org/software/systemd/man/org.freedesktop.timedate1.html).

# timedated

systemd 30 and newer include systemd-timedated. This is a tiny daemon that can be used to control the system time and related settings. It currently offers access to four settings:

- The system time
- The system timezone
- A boolean controlling whether the system RTC is in local or UTC timezone
- Whether the [systemd-timesyncd.service(8)](http://www.freedesktop.org/software/systemd/man/systemd-timesyncd.service.html) (NTP) services is enabled/started or disabled/stopped.
  See [systemd-timedated.service(8)](http://www.freedesktop.org/software/systemd/man/systemd-timedated.service.html) for more information.

The daemon is accessible via D-Bus:

```
$ gdbus introspect --system --dest org.freedesktop.timedate1 --object-path /org/freedesktop/timedate1
node /org/freedesktop/timedate1 {
  interface org.freedesktop.timedate1 {
    methods:
      SetTime(in  x usec_utc,
              in  b relative,
              in  b user_interaction);
      SetTimezone(in  s timezone,
                  in  b user_interaction);
      SetLocalRTC(in  b local_rtc,
                  in  b fix_system,
                  in  b user_interaction);
      SetNTP(in  b use_ntp,
             in  b user_interaction);
    signals:
    properties:
      readonly s Timezone = 'Europe/Berlin';
      readonly b LocalRTC = false;
      readonly b NTP = true;
  };
  interface org.freedesktop.DBus.Properties {
  };
  interface org.freedesktop.DBus.Introspectable {
  };
  interface org.freedesktop.DBus.Peer {
  };
};
```

Use **SetTime()** to change the system clock. Pass a value of microseconds since 1 Jan 1970 UTC. If "relative" is true the passed usec value will be added to the current system time, if it is false the current system time will be set to the passed usec value. If the system time is set with this call the RTC will be updated as well.

Use **SetTimezone()** to set the system timezone. Pass a value like "Europe/Berlin" to set the timezone. Valid timezones you may parse from /usr/share/zoneinfo/zone.tab. If the RTC is configured to be maintained in local time it will be updated accordingly.

Use **SetLocalRTC()** to control whether the RTC is in local time or UTC. It is strongly recommended to maintain the RTC in UTC. Some OSes (Windows) however maintain the RTC in local time which might make it necessary to enable this feature. However, this creates various problems as daylight changes might be missed. If fix_system is passed "true" the time from the RTC is read again and the system clock adjusted according to the new setting. If fix_system is passed "false" the system time is written to the RTC taking the new setting into account. Use fix_system=true in installers and livecds where the RTC is probably more reliable than the system time. Use fix_system=false in configuration UIs that are run during normal operation and where the system clock is probably more reliable than the RTC.

Use **SetNTP()** to control whether the system clock is synchronized with the network using systemd-timesyncd. This will enable/start resp. disable/stop the systemd-timesyncd service.

Whenever the timezone and local_rtc settings are changed via the daemon PropertyChanged signals are sent out to which clients can subscribe. Changing the time settings using this interface is authenticated via PolicyKit.

Note that this service will not inform you about system time changes. Use timerfd() with CLOCK_REALTIME and TFD_TIMER_CANCEL_ON_SET for that.

The user_interaction boolean parameters can be used to control whether PolicyKit should interactively ask the user for authentication credentials if it needs to.

The PolicyKit action for SetTimezone() is _org.freedesktop.timedate1.set-timezone_. For SetLocalRTC() it is _org.freedesktop.timedate1.set-local-rtc_, for SetTime() it is _org.freedesktop.timedate1.set-time_ and for SetNTP() it is _org.freedesktop.timedate1.set-ntp_.

The sources for timedated are available in git for review: [http://cgit.freedesktop.org/systemd/systemd/tree/src/timedate/timedated.c](http://cgit.freedesktop.org/systemd/systemd/tree/src/timedate/timedated.c)

For more information how the system clock and RTC interact see [http://lists.freedesktop.org/archives/systemd-devel/2011-May/002526.html](http://lists.freedesktop.org/archives/systemd-devel/2011-May/002526.html)

This D-Bus interface follows [the usual interface versioning guidelines](http://0pointer.de/blog/projects/versioning-dbus.html).
