/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <stdio.h>

#include "dissect-image.h"
#include "log.h"
#include "loop-util.h"
#include "string-util.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        int r, i;

        test_setup_logging(LOG_DEBUG);

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
