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
#include <linux/fanotify.h>
#include <sys/signalfd.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>

#include "missing.h"
#include "util.h"
#include "set.h"
#include "sd-daemon.h"
#include "ioprio.h"
#include "readahead-common.h"

#define MINCORE_VEC_SIZE (READAHEAD_FILE_SIZE_MAX/PAGE_SIZE)
#define TIMEOUT_USEC (2*USEC_PER_MINUTE)

/* fixme:
 *
 * - detect ssd on btrfs/lvm...
 * - read ahead directories
 * - sd_readahead_cancel
 * - gzip?
 * - remount rw
 * - are filenames from anotify normalized regards /../ and // and /./?
 * - does ioprio_set work with fadvise()?
 */

static int btrfs_defrag(int fd) {
        struct btrfs_ioctl_vol_args data;

        zero(data);
        data.fd = fd;

        return ioctl(fd, BTRFS_IOC_DEFRAG, &data);
}

static int pack_file(FILE *pack, const char *fn, bool on_btrfs) {
        struct stat st;
        void *start = MAP_FAILED;
        uint8_t vec[MINCORE_VEC_SIZE];
        uint32_t b, c;
        size_t l, pages;
        bool mapped;
        int r = 0, fd = -1, k;

        assert(pack);
        assert(fn);

        if ((fd = open(fn, O_RDONLY|O_CLOEXEC|O_NOATIME|O_NOCTTY|O_NOFOLLOW)) < 0) {
                log_warning("open(%s) failed: %m", fn);
                r = -errno;
                goto finish;
        }

        if ((k = file_verify(fd, fn, &st)) <= 0) {
                r = k;
                goto finish;
        }

        if (on_btrfs)
                btrfs_defrag(fd);

        l = PAGE_ALIGN(st.st_size);
        if ((start = mmap(NULL, l, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
                log_warning("mmap(%s) failed: %m", fn);
                r = -errno;
                goto finish;
        }

        if (mincore(start, l, vec) < 0) {
                log_warning("mincore(%s) failed: %m", fn);
                r = -errno;
                goto finish;
        }

        fputs(fn, pack);
        fputc('\n', pack);

        pages = l / PAGE_SIZE;
        mapped = false;
        for (c = 0; c < pages; c++) {
                bool new_mapped = !!(vec[c] & 1);

                if (!mapped && new_mapped)
                        b = c;
                else if (mapped && !new_mapped) {
                        fwrite(&b, sizeof(b), 1, pack);
                        fwrite(&c, sizeof(c), 1, pack);

                        log_debug("%s: page %u to %u", fn, b, c);
                }

                mapped = new_mapped;
        }

        /* We don't write any range data if we should read the entire file */
        if (mapped && b > 0) {
                fwrite(&b, sizeof(b), 1, pack);
                fwrite(&c, sizeof(c), 1, pack);

                log_debug("%s: page %u to %u", fn, b, c);
        }

        /* End marker */
        b = 0;
        fwrite(&b, sizeof(b), 1, pack);
        fwrite(&b, sizeof(b), 1, pack);

finish:
        if (start != MAP_FAILED)
                munmap(start, l);

        if (fd >= 0)
                close_nointr_nofail(fd);

        return r;
}

static unsigned long fd_first_block(int fd) {
        struct {
                struct fiemap fiemap;
                struct fiemap_extent extent;
        } data;

        zero(data);
        data.fiemap.fm_length = ~0ULL;
        data.fiemap.fm_extent_count = 1;

        if (ioctl(fd, FS_IOC_FIEMAP, &data) < 0)
                return 0;

        if (data.fiemap.fm_mapped_extents <= 0)
                return 0;

        if (data.fiemap.fm_extents[0].fe_flags & FIEMAP_EXTENT_UNKNOWN)
                return 0;

        return (unsigned long) data.fiemap.fm_extents[0].fe_physical;
}

struct item {
        const char *path;
        unsigned long block;
};

static int qsort_compare(const void *a, const void *b) {
        const struct item *i, *j;

        i = a;
        j = b;

        if (i->block < j->block)
                return -1;
        if (i->block > j->block)
                return 1;

        return strcmp(i->path, j->path);
}

static int collect(const char *root) {
        enum {
                FD_FANOTIFY,
                FD_SIGNAL,
                _FD_MAX
        };
        struct pollfd pollfd[_FD_MAX];
        int fanotify_fd = -1, signal_fd = -1, r = 0;
        pid_t my_pid;
        Hashmap *files = NULL;
        Iterator i;
        char *p, *q;
        sigset_t mask;
        FILE *pack = NULL;
        char *pack_fn_new = NULL, *pack_fn = NULL;
        bool on_ssd, on_btrfs;
        struct statfs sfs;
        usec_t not_after;

        assert(root);

        write_one_line_file("/proc/self/oom_score_adj", "1000");

        if (ioprio_set(IOPRIO_WHO_PROCESS, getpid(), IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0)) < 0)
                log_warning("Failed to set IDLE IO priority class: %m");

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGINT, SIGTERM, -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        if ((signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC)) < 0) {
                log_error("signalfd(): %m");
                r = -errno;
                goto finish;
        }

        if (!(files = hashmap_new(string_hash_func, string_compare_func))) {
                log_error("Failed to allocate set.");
                r = -ENOMEM;
                goto finish;
        }

        if ((fanotify_fd = fanotify_init(FAN_CLOEXEC|FAN_NONBLOCK, O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_NOATIME)) < 0)  {
                log_error("Failed to create fanotify object: %m");
                r = -errno;
                goto finish;
        }

        if (fanotify_mark(fanotify_fd, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_OPEN, AT_FDCWD, root) < 0) {
                log_error("Failed to mark %s: %m", root);
                r = -errno;
                goto finish;
        }

        not_after = now(CLOCK_MONOTONIC) + TIMEOUT_USEC;

        my_pid = getpid();

        zero(pollfd);
        pollfd[FD_FANOTIFY].fd = fanotify_fd;
        pollfd[FD_FANOTIFY].events = POLLIN;
        pollfd[FD_SIGNAL].fd = signal_fd;
        pollfd[FD_SIGNAL].events = POLLIN;

        sd_notify(0,
                  "READY=1\n"
                  "STATUS=Collecting readahead data");

        log_debug("Collecting...");

        for (;;) {
                union {
                        struct fanotify_event_metadata metadata;
                        char buffer[4096];
                } data;
                ssize_t n;
                struct fanotify_event_metadata *m;
                usec_t t;
                int h;

                if (hashmap_size(files) > READAHEAD_FILES_MAX) {
                        log_debug("Reached maximum number of read ahead files, ending collection.");
                        break;
                }

                t = now(CLOCK_MONOTONIC);
                if (t >= not_after) {
                        log_debug("Reached maximum collection time, ending collection.");
                        break;
                }

                if ((h = poll(pollfd, _FD_MAX, (int) ((not_after - t) / USEC_PER_MSEC))) < 0) {

                        if (errno == EINTR)
                                continue;

                        log_error("poll(): %m");
                        r = -errno;
                        goto finish;
                }

                if (pollfd[FD_SIGNAL].revents != 0)
                        break;

                if (h == 0) {
                        log_debug("Reached maximum collection time, ending collection.");
                        break;
                }

                if ((n = read(fanotify_fd, &data, sizeof(data))) < 0) {

                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        log_error("Failed to read event: %m");
                        r = -errno;
                        goto finish;
                }

                for (m = &data.metadata; FAN_EVENT_OK(m, n); m = FAN_EVENT_NEXT(m, n)) {

                        if (m->pid != my_pid && m->fd >= 0) {
                                char fn[PATH_MAX];
                                int k;

                                snprintf(fn, sizeof(fn), "/proc/self/fd/%i", m->fd);
                                char_array_0(fn);

                                if ((k = readlink_malloc(fn, &p)) >= 0) {

                                        if (hashmap_get(files, p))
                                                /* Already read */
                                                free(p);
                                        else {
                                                unsigned long ul;

                                                ul = fd_first_block(m->fd);

                                                if ((k = hashmap_put(files, p, ULONG_TO_PTR(ul))) < 0) {
                                                        log_warning("set_put() failed: %s", strerror(-k));
                                                        free(p);
                                                }
                                        }

                                } else
                                        log_warning("readlink(%s) failed: %s", fn, strerror(-k));
                        }

                        if (m->fd)
                                close_nointr_nofail(m->fd);
                }
        }

        if (fanotify_fd >= 0) {
                close_nointr_nofail(fanotify_fd);
                fanotify_fd = -1;
        }

        log_debug("Writing Pack File...");

        on_ssd = fs_on_ssd(root);
        log_debug("On SSD: %s", yes_no(on_ssd));

        on_btrfs = statfs(root, &sfs) >= 0 && sfs.f_type == BTRFS_SUPER_MAGIC;
        log_debug("On btrfs: %s", yes_no(on_btrfs));

        asprintf(&pack_fn, "%s/.readahead", root);
        asprintf(&pack_fn_new, "%s/.readahead.new", root);

        if (!pack_fn || !pack_fn_new) {
                log_error("Out of memory");
                r = -ENOMEM;
                goto finish;
        }

        if (!(pack = fopen(pack_fn_new, "we"))) {
                log_error("Failed to open pack file: %m");
                r = -errno;
                goto finish;
        }

        fputs(CANONICAL_HOST "\n", pack);
        putc(on_ssd ? 'S' : 'R', pack);

        if (on_ssd || on_btrfs) {

                /* On SSD or on btrfs, just write things out in the
                 * order the files were accessed. */

                HASHMAP_FOREACH_KEY(q, p, files, i)
                        pack_file(pack, p, on_btrfs);
        } else {
                struct item *ordered, *j;
                unsigned k, n;

                /* On rotating media, order things by the block
                 * numbers */

                log_debug("Ordering...");

                n = hashmap_size(files);
                if (!(ordered = new(struct item, n))) {
                        log_error("Out of memory");
                        r = -ENOMEM;
                        goto finish;
                }

                j = ordered;
                HASHMAP_FOREACH_KEY(q, p, files, i) {
                        j->path = p;
                        j->block = PTR_TO_ULONG(q);
                        j++;
                }

                assert(ordered + n == j);

                qsort(ordered, n, sizeof(struct item), qsort_compare);

                for (k = 0; k < n; k++)
                        pack_file(pack, ordered[k].path, on_btrfs);

                free(ordered);
        }

        log_debug("Finalizing...");

        fflush(pack);

        if (ferror(pack)) {
                log_error("Failed to write pack file.");
                r = -EIO;
                goto finish;
        }

        if (rename(pack_fn_new, pack_fn) < 0) {
                log_error("Failed to rename readahead file: %m");
                r = -errno;
                goto finish;
        }

        fclose(pack);
        pack = NULL;

        log_debug("Done.");

finish:
        if (fanotify_fd >= 0)
                close_nointr_nofail(fanotify_fd);

        if (signal_fd >= 0)
                close_nointr_nofail(signal_fd);

        if (pack) {
                fclose(pack);
                unlink(pack_fn_new);
        }

        free(pack_fn_new);
        free(pack_fn);

        while ((p = hashmap_steal_first_key(files)))
                free(q);

        hashmap_free(files);

        return r;
}

int main(int argc, char *argv[]) {

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        if (!enough_ram()) {
                log_info("Disabling readahead collector due to low memory.");
                return 0;
        }

        if (collect(argc >= 2 ? argv[1] : "/") < 0)
                return 1;

        return 0;
}
