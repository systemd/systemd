/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "clean-ipc.h"
#include "user-util.h"
#include "util.h"

int main(int argc, char *argv[]) {
        uid_t uid;
        int r;
        const char* name = argv[1] ?: NOBODY_USER_NAME;

        r = get_user_creds(&name, &uid, NULL, NULL, NULL);
        if (r < 0) {
                log_full_errno(r == -ESRCH ? LOG_NOTICE : LOG_ERR,
                               r, "Failed to resolve \"%s\": %m", name);
                return r == -ESRCH ? EXIT_TEST_SKIP : EXIT_FAILURE;
        }

        r = clean_ipc_by_uid(uid);
        return  r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
