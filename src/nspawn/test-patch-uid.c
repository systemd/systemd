/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include <stdlib.h>

#include "log.h"
#include "nspawn-user-namespace.h"
#include "user-util.h"
#include "util.h"

int main(int argc, char *argv[]) {
        UserNamespaceContext *userns;
        uid_t shift, range;
        int r;

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        if (argc != 4) {
                log_error("Expected PATH SHIFT RANGE parameters.");
                return EXIT_FAILURE;
        }

        r = parse_uid(argv[2], &shift);
        if (r < 0) {
                log_error_errno(r, "Failed to parse UID shift %s.", argv[2]);
                return EXIT_FAILURE;
        }

        r = parse_gid(argv[3], &range);
        if (r < 0) {
                log_error_errno(r, "Failed to parse UID range %s.", argv[3]);
                return EXIT_FAILURE;
        }

        r = userns_ctx_new(0, 0, shift, range, USER_NAMESPACE_FIXED, &userns);
        if (r < 0) {
                log_error_errno(r, "Failed to create UserNamespaceContext object: %m");
                return EXIT_FAILURE;
        }

        r = userns_path_patch_uid(userns, argv[1]);
        if (r < 0) {
                log_error_errno(r, "Failed to patch directory tree: %m");
                return EXIT_FAILURE;
        }

        log_info("Changed: %s", yes_no(r));

        userns_ctx_free(userns);

        return EXIT_SUCCESS;
}
