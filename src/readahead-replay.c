/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "missing.h"
#include "util.h"
#include "set.h"
#include "sd-daemon.h"
#include "ioprio.h"
#include "readahead-common.h"

static int unpack_file(FILE *pack) {
        char fn[PATH_MAX];
        int r = 0, fd = -1;
        bool any = false;
        struct stat st;

        assert(pack);

        if (!fgets(fn, sizeof(fn), pack))
                return 0;

        char_array_0(fn);
        truncate_nl(fn);

        if ((fd = open(fn, O_RDONLY|O_CLOEXEC|O_NOATIME|O_NOCTTY|O_NOFOLLOW)) < 0)
                log_warning("open(%s) failed: %m", fn);
        else if (file_verify(fd, fn, &st) <= 0) {
                close_nointr_nofail(fd);
                fd = -1;
        }

        for (;;) {
                uint32_t b, c;

                if (fread(&b, sizeof(b), 1, pack) != 1 ||
                    fread(&c, sizeof(c), 1, pack) != 1) {
                        log_error("Premature end of pack file.");
                        r = -EIO;
                        goto finish;
                }

                if (b == 0 && c == 0)
                        break;

                if (c <= b) {
                        log_error("Invalid pack file.");
                        r = -EIO;
                        goto finish;
                }

                log_debug("%s: page %u to %u", fn, b, c);

                any = true;

                if (fd >= 0)
                        if (readahead(fd, b * PAGE_SIZE, (c - b) * PAGE_SIZE) < 0) {
                                log_warning("readahead() failed: %m");
                                goto finish;
                        }
        }

        if (!any && fd >= 0) {
                /* if no range is encoded in the pack file this is
                 * intended to mean that the whole file shall be
                 * read */

                if (readahead(fd, 0, st.st_size) < 0) {
                        log_warning("readahead() failed: %m");
                        goto finish;
                }
        }

finish:
        if (fd >= 0)
                close_nointr_nofail(fd);

        return r;
}

static int replay(const char *root) {
        FILE *pack;
        char line[LINE_MAX];
        int r = 0;
        char *pack_fn = NULL, c;
        bool on_ssd;
        int prio;

        assert(root);

        if (asprintf(&pack_fn, "%s/.readahead", root) < 0) {
                log_error("Out of memory");
                r = -ENOMEM;
                goto finish;
        }

        if ((!(pack = fopen(pack_fn, "re")))) {
                if (errno == -ENOENT)
                        log_debug("No pack file found.");
                else {
                        log_error("Failed to open pack file: %m");
                        r = -errno;
                }

                goto finish;
        }

        if (!(fgets(line, sizeof(line), pack))) {
                log_error("Premature end of pack file.");
                r = -EIO;
                goto finish;
        }

        char_array_0(line);

        if (!streq(line, CANONICAL_HOST "\n")) {
                log_debug("Pack file host type mismatch.");
                goto finish;
        }

        if ((c = getc(pack)) == EOF) {
                log_debug("Premature end of pack file.");
                r = -EIO;
                goto finish;
        }

        /* We do not retest SSD here, so that we can start replaying
         * before udev is up.*/
        on_ssd = c == 'S';
        log_debug("On SSD: %s", yes_no(on_ssd));

        if (on_ssd)
                prio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0);
        else
                prio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 7);

        if (ioprio_set(IOPRIO_WHO_PROCESS, getpid(), prio) < 0)
                log_warning("Failed to set IDLE IO priority class: %m");

        sd_notify(0,
                  "READY=1\n"
                  "STATUS=Replaying readahead data");

        log_debug("Replaying...");

        while (!feof(pack) && !ferror(pack)) {
                int k;

                if ((k = unpack_file(pack)) < 0) {
                        r = k;
                        goto finish;
                }
        }

        if (ferror(pack)) {
                log_error("Failed to read pack file.");
                r = -EIO;
                goto finish;
        }

        log_debug("Done.");

finish:
        if (pack)
                fclose(pack);

        free(pack_fn);

        return r;
}

int main(int argc, char*argv[]) {

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        if (replay(argc >= 2 ? argv[1] : "/") < 0)
                return 1;

        return 0;
}
