#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

m4_ifdef(`HAVE_MICROHTTPD',
u systemd-journal-gateway - "systemd Journal Gateway"
u systemd-journal-remote  - "systemd Journal Remote"
)m4_dnl
m4_ifdef(`HAVE_LIBCURL',
u systemd-journal-upload  - "systemd Journal Upload"
)m4_dnl
