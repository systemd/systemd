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
#include <getopt.h>
#include <sys/inotify.h>

#include "missing.h"
#include "util.h"
#include "set.h"
#include "sd-daemon.h"
#include "ioprio.h"
#include "readahead-common.h"
#include "virt.h"

static off_t arg_file_size_max = READAHEAD_FILE_SIZE_MAX;

static ReadaheadShared *shared = NULL;

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

        if ((fd = open(fn, O_RDONLY|O_CLOEXEC|O_NOATIME|O_NOCTTY|O_NOFOLLOW)) < 0) {

                if (errno != ENOENT && errno != EPERM && errno != EACCES)
                        log_warning("open(%s) failed: %m", fn);

        } else if (file_verify(fd, fn, arg_file_size_max, &st) <= 0) {
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
        if (fd >= 0)
                close_nointr_nofail(fd);

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

        write_one_line_file("/proc/self/oom_score_adj", "1000");
        bump_request_nr(root);

        if (asprintf(&pack_fn, "%s/.readahead", root) < 0) {
                log_error("Out of memory");
                r = -ENOMEM;
                goto finish;
        }

        if ((!(pack = fopen(pack_fn, "re")))) {
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

        if (inotify_fd >= 0)
                close_nointr_nofail(inotify_fd);

        free(pack_fn);

        return r;
}


static int help(void) {

        printf("%s [OPTIONS...] [DIRECTORY]\n\n"
               "Replay collected read-ahead data on early boot.\n\n"
               "  -h --help                 Show this help\n"
               "     --max-file-size=BYTES  Maximum size of files to read ahead\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_FILE_SIZE_MAX
        };

        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'                },
                { "file-size-max", required_argument, NULL, ARG_FILE_SIZE_MAX  },
                { NULL,            0,                 NULL, 0                  }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_FILE_SIZE_MAX: {
                        unsigned long long ull;

                        if (safe_atollu(optarg, &ull) < 0 || ull <= 0) {
                                log_error("Failed to parse maximum file size %s.", optarg);
                                return -EINVAL;
                        }

                        arg_file_size_max = (off_t) ull;
                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind != argc &&
            optind != argc-1) {
                help();
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char*argv[]) {
        int r;
        const char *root;

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        umask(0022);

        if ((r = parse_argv(argc, argv)) <= 0)
                return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

        root = optind < argc ? argv[optind] : "/";

        if (!enough_ram()) {
                log_info("Disabling readahead replay due to low memory.");
                return 0;
        }

        if (detect_virtualization(NULL) > 0) {
                log_info("Disabling readahead replay due to execution in virtualized environment.");
                return 0;
        }

        if (!(shared = shared_get()))
                return 1;

        shared->replay = getpid();
        __sync_synchronize();

        if (replay(root) < 0)
                return 1;

        return 0;
}
