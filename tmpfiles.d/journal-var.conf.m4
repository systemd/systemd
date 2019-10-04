#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

# See tmpfiles.d(5) for details

z /var/log/journal 2755 root systemd-journal - -
z /var/log/journal/%m 2755 root systemd-journal - -
z /var/log/journal/%m/system.journal 0640 root systemd-journal - -
m4_ifdef(`HAVE_ACL',`m4_dnl
m4_ifdef(`ENABLE_ADM_GROUP',`m4_dnl
m4_ifdef(`ENABLE_WHEEL_GROUP',``
a+ /var/log/journal    - - - - d:group::r-x,d:group:adm:r-x,d:group:wheel:r-x,group::r-x,group:adm:r-x,group:wheel:r-x
a+ /var/log/journal/%m - - - - d:group:adm:r-x,d:group:wheel:r-x,group:adm:r-x,group:wheel:r-x
a+ /var/log/journal/%m/system.journal - - - - group:adm:r--,group:wheel:r--
'', ``
a+ /var/log/journal    - - - - d:group::r-x,d:group:adm:r-x,group::r-x,group:adm:r-x
a+ /var/log/journal/%m - - - - d:group:adm:r-x,group:adm:r-x
a+ /var/log/journal/%m/system.journal - - - - group:adm:r--
'')',`m4_dnl
m4_ifdef(`ENABLE_WHEEL_GROUP',``
a+ /var/log/journal    - - - - d:group::r-x,d:group:wheel:r-x,group::r-x,group:wheel:r-x
a+ /var/log/journal/%m - - - - d:group:wheel:r-x,group:wheel:r-x
a+ /var/log/journal/%m/system.journal - - - - group:wheel:r--
'')')')m4_dnl
