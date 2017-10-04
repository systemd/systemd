/***
  This file is part of systemd.

  Copyright 2017 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <selinux/selinux.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "selinux-util.h"
#include "string-util.h"

static int cached_use = -1;

bool mac_selinux_use(void) {
#ifdef HAVE_SELINUX

#  ifdef ENABLE_SELINUX_WORKAROUND
        _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;

        if (cached_use >= 0)
                return cached_use;

        if (access("/etc/selinux/config", F_OK) < 0)
                return (cached_use = false);

        proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
        if (!proc_self_mountinfo)
                return (cached_use = false);

        for (;;) {
                _cleanup_free_ char *type = NULL;
                int r;

                r = fscanf(proc_self_mountinfo,
                           "%*s "       /* (1) mount id */
                           "%*s "       /* (2) parent id */
                           "%*s "       /* (3) major:minor */
                           "%*s "       /* (4) root */
                           "%*s "       /* (5) mount point */
                           "%*s"        /* (6) mount options */
                           "%*[^-]"     /* (7) optional fields */
                           "- "         /* (8) separator */
                           "%ms "       /* (9) file system type */
                           "%*s"        /* (10) mount source */
                           "%*s"        /* (11) mount options 2 */
                           "%*[^\n]",   /* some rubbish at the end */
                           &type);
                if (r != 1) {
                        if (r == EOF)
                                break;

                        continue;
                }

                if (streq(type, "selinuxfs"))
                        return (cached_use = true);
        }

        return (cached_use = false);

#  else
        if (cached_use < 0)
                cached_use = is_selinux_enabled() > 0;

        return cached_use;
#  endif
#else
        return false;
#endif
}

void mac_selinux_retest(void) {
#ifdef HAVE_SELINUX
        cached_use = -1;
#endif
}
