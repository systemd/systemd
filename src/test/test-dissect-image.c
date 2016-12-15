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

#include <fcntl.h>
#include <stdio.h>

#include "dissect-image.h"
#include "log.h"
#include "loop-util.h"
#include "string-util.h"

int main(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        int r, i;

        log_set_max_level(LOG_DEBUG);

        if (argc < 2) {
                log_error("Requires one command line argument.");
                return EXIT_FAILURE;
        }

        r = loop_device_make_by_path(argv[1], O_RDONLY, &d);
        if (r < 0) {
                log_error_errno(r, "Failed to set up loopback device: %m");
                return EXIT_FAILURE;
        }

        r = dissect_image(d->fd, NULL, 0, DISSECT_IMAGE_REQUIRE_ROOT, &m);
        if (r < 0) {
                log_error_errno(r, "Failed to dissect image: %m");
                return EXIT_FAILURE;
        }

        for (i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {

                if (!m->partitions[i].found)
                        continue;

                printf("Found %s partition, %s of type %s at #%i (%s)\n",
                       partition_designator_to_string(i),
                       m->partitions[i].rw ? "writable" : "read-only",
                       strna(m->partitions[i].fstype),
                       m->partitions[i].partno,
                       strna(m->partitions[i].node));
        }

        return EXIT_SUCCESS;
}
