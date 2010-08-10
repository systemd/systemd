#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

# See systemd.special(7) for details

[Unit]
Description=System Initialization
Conflicts=emergency.service emergency.target
After=emergency.service emergency.target
RefuseManualStart=yes
m4_dnl
m4_ifdef(`TARGET_FEDORA',
m4_dnl Hook in Fedora's /etc/rc.d/rc.sysinit
Requires=sysinit.service
After=sysinit.service
)m4_dnl
m4_ifdef(`TARGET_ARCH',
m4_dnl Hook in Arch's /etc/rc.sysinit
Requires=sysinit.service
After=sysinit.service
)m4_dnl
m4_ifdef(`TARGET_SUSE',`',
m4_dnl On Suse, fsck.target is seperate, everywhere else it is just an alias for sysinit.target
Names=fsck.target
)m4_dnl
