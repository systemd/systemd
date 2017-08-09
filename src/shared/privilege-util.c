/***
  This file is part of systemd.

  Copyright 2017 Yu Watanabe

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

#include <errno.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <unistd.h>

#include "capability-util.h"
#include "cap-list.h"
#include "log.h"
#include "privilege-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

int check_privileges(const char *username, uint64_t required_caps) {
        uint64_t current_caps;
        int r;

        assert(username);

        if (geteuid() == 0 || getegid() == 0) {
                uid_t uid;
                gid_t gid;

                r = get_user_creds(&username, &uid, &gid, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Cannot resolve user name %s: %m", username);

                r = drop_privileges(uid, gid, required_caps);
                if (r < 0)
                        return log_error_errno(r, "Failed to drop privileges: %m");

                return 0;
        }

        r = get_effective_caps(&current_caps);
        if (r < 0) {
                log_notice_errno(r, "Failed to get current capabilities (libcap bug?), ignoring: %m");
                return 0;
        }

        if ((current_caps & required_caps) != required_caps) {
                _cleanup_strv_free_ char **caps = NULL;
                _cleanup_free_ char *c = NULL;
                unsigned long i;

                for (i = 0; i < cap_last_cap(); i++)
                        if (required_caps & (UINT64_C(1) << i)) {
                                r = strv_extend(&caps, capability_to_name(i));
                                if (r < 0)
                                        return log_oom();
                        }

                c = strv_join(caps, " ");
                if (!c)
                        return log_oom();

                log_error("Missing required capabilities. This process requires %s.", ascii_strupper(c));
                return -EPERM;
        }

        if (current_caps != required_caps) {
                r = capability_bounding_set_drop(required_caps, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to drop unnecessary capabilities: %m");
        }

        return 0;
}
