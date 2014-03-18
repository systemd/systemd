/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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
#include <getopt.h>
#include <sys/inotify.h>

#include <systemd/sd-daemon.h>

#include "missing.h"
#include "util.h"
#include "set.h"
#include "ioprio.h"
#include "readahead-common.h"
#include "virt.h"

static ReadaheadShared *shared = NULL;

static int unpack_file(FILE *pack) {
        char fn[PATH_MAX];
        int r = 0, fd = -1;
        bool any = false;
        struct stat st;
        uint64_t inode;

        assert(pack);

        if (!fgets(fn, sizeof(fn), pack))
                return 0;

        char_array_0(fn);
        truncate_nl(fn);

        fd = open(fn, O_RDONLY|O_CLOEXEC|O_NOATIME|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0) {

                if (errno != ENOENT && errno != EPERM && errno != EACCES && errno != ELOOP)
                        log_warning("open(%s) failed: %m", fn);

        } else if (file_verify(fd, fn, arg_file_size_max, &st) <= 0)
                fd = safe_close(fd);

        if (fread(&inode, sizeof(inode), 1, pack) != 1) {
                log_error("Premature end of pack file.");
                r = -EIO;
                goto finish;
        }

        if (fd >= 0) {
                /* If the inode changed the file got deleted, so just
                 * ignore this entry */
                if (st.st_ino != (uint64_t) inode)
                        fd = safe_close(fd);
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
                        if (posix_fadvise(fd, b * page_size(), (c - b) * page_size(), POSIX_FADV_WILLNEED) < 0) {
                                log_warning("posix_fadvise() failed: %m");
                                goto finish;
                        }
        }

        if (!any && fd >= 0) {
                /* if no range is encoded in the pack file this is
                 * intended to mean that the whole file shall be
                 * read */

                if (posix_fadvise(fd, 0, st.st_size, POSIX_FADV_WILLNEED) < 0) {
                        log_warning("posix_fadvise() failed: %m");
                        goto finish;
                }
        }

finish:
        safe_close(fd);

        return r;
}

static int replay(const char *root) {
        FILE *pack = NULL;
        char line[LINE_MAX];
        int r = 0;
        char *pack_fn = NULL;
        int c;
        bool on_ssd, ready = false;
        int prio;
        int inotify_fd = -1;

        assert(root);

        block_bump_request_nr(root);

        if (asprintf(&pack_fn, "%s/.readahead", root) < 0) {
                r = log_oom();
                goto finish;
        }

        pack = fopen(pack_fn, "re");
        if (!pack) {
                if (errno == ENOENT)
                        log_debug("No pack file found.");
                else {
                        log_error("Failed to open pack file: %m");
                        r = -errno;
                }

                goto finish;
        }

        posix_fadvise(fileno(pack), 0, 0, POSIX_FADV_WILLNEED);

        if ((inotify_fd = open_inotify()) < 0) {
                r = inotify_fd;
                goto finish;
        }

        if (!(fgets(line, sizeof(line), pack))) {
                log_error("Premature end of pack file.");
                r = -EIO;
                goto finish;
        }

        char_array_0(line);

        if (!streq(line, CANONICAL_HOST READAHEAD_PACK_FILE_VERSION)) {
                log_debug("Pack file host or version type mismatch.");
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
                /* We are not using RT here, since we'd starve IO that
                we didn't record (which is for example blkid, since
                its disk accesses go directly to the block device and
                are thus not visible in fallocate) to death. However,
                we do ask for an IO prio that is slightly higher than
                the default (which is BE. 4) */
                prio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 2);

        if (ioprio_set(IOPRIO_WHO_PROCESS, getpid(), prio) < 0)
                log_warning("Failed to set IDLE IO priority class: %m");

        sd_notify(0, "STATUS=Replaying readahead data");

        log_debug("Replaying...");

        if (access("/run/systemd/readahead/noreplay", F_OK) >= 0) {
                log_debug("Got termination request");
                goto done;
        }

        while (!feof(pack) && !ferror(pack)) {
                uint8_t inotify_buffer[sizeof(struct inotify_event) + FILENAME_MAX];
                int k;
                ssize_t n;

                if ((n = read(inotify_fd, &inotify_buffer, sizeof(inotify_buffer))) < 0) {
                        if (errno != EINTR && errno != EAGAIN) {
                                log_error("Failed to read inotify event: %m");
                                r = -errno;
                                goto finish;
                        }
                } else {
                        struct inotify_event *e = (struct inotify_event*) inotify_buffer;

                        while (n > 0) {
                                size_t step;

                                if ((e->mask & IN_CREATE) && streq(e->name, "noreplay")) {
                                        log_debug("Got termination request");
                                        goto done;
                                }

                                step = sizeof(struct inotify_event) + e->len;
                                assert(step <= (size_t) n);

                                e = (struct inotify_event*) ((uint8_t*) e + step);
                                n -= step;
                        }
                }

                if ((k = unpack_file(pack)) < 0) {
                        r = k;
                        goto finish;
                }

                if (!ready) {
                        /* We delay the ready notification until we
                         * queued at least one read */
                        sd_notify(0, "READY=1");
                        ready = true;
                }
        }

done:
        if (!ready)
                sd_notify(0, "READY=1");

        if (ferror(pack)) {
                log_error("Failed to read pack file.");
                r = -EIO;
                goto finish;
        }

        log_debug("Done.");

finish:
        if (pack)
                fclose(pack);

        safe_close(inotify_fd);

        free(pack_fn);

        return r;
}

int main_replay(const char *root) {

        if (!root)
                root = "/";

        if (!enough_ram()) {
                log_info("Disabling readahead replay due to low memory.");
                return EXIT_SUCCESS;
        }

        shared = shared_get();
        if (!shared)
                return EXIT_FAILURE;

        shared->replay = getpid();
        __sync_synchronize();

        if (replay(root) < 0)
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}
