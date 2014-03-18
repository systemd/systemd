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
#include <linux/fanotify.h>
#include <sys/signalfd.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <getopt.h>
#include <sys/inotify.h>
#include <math.h>

#ifdef HAVE_LINUX_BTRFS_H
#include <linux/btrfs.h>
#endif

#ifdef HAVE_FANOTIFY_INIT
#include <sys/fanotify.h>
#endif

#include <systemd/sd-daemon.h>

#include "missing.h"
#include "util.h"
#include "set.h"
#include "ioprio.h"
#include "readahead-common.h"
#include "virt.h"

/* fixme:
 *
 * - detect ssd on btrfs/lvm...
 * - read ahead directories
 * - gzip?
 * - remount rw?
 * - handle files where nothing is in mincore
 * - does ioprio_set work with fadvise()?
 */

static ReadaheadShared *shared = NULL;
static usec_t starttime;

/* Avoid collisions with the NULL pointer */
#define SECTOR_TO_PTR(s) ULONG_TO_PTR((s)+1)
#define PTR_TO_SECTOR(p) (PTR_TO_ULONG(p)-1)

static int btrfs_defrag(int fd) {
        struct btrfs_ioctl_vol_args data = { .fd = fd };

        return ioctl(fd, BTRFS_IOC_DEFRAG, &data);
}

static int pack_file(FILE *pack, const char *fn, bool on_btrfs) {
        struct stat st;
        void *start = MAP_FAILED;
        uint8_t *vec;
        uint32_t b, c;
        uint64_t inode;
        size_t l, pages;
        bool mapped;
        int r = 0, fd = -1, k;

        assert(pack);
        assert(fn);

        fd = open(fn, O_RDONLY|O_CLOEXEC|O_NOATIME|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0) {

                if (errno == ENOENT)
                        return 0;

                if (errno == EPERM || errno == EACCES)
                        return 0;

                log_warning("open(%s) failed: %m", fn);
                r = -errno;
                goto finish;
        }

        k = file_verify(fd, fn, arg_file_size_max, &st);
        if (k <= 0) {
                r = k;
                goto finish;
        }

        if (on_btrfs)
                btrfs_defrag(fd);

        l = PAGE_ALIGN(st.st_size);
        start = mmap(NULL, l, PROT_READ, MAP_SHARED, fd, 0);
        if (start == MAP_FAILED) {
                log_warning("mmap(%s) failed: %m", fn);
                r = -errno;
                goto finish;
        }

        pages = l / page_size();
        vec = alloca0(pages);
        if (mincore(start, l, vec) < 0) {
                log_warning("mincore(%s) failed: %m", fn);
                r = -errno;
                goto finish;
        }

        fputs(fn, pack);
        fputc('\n', pack);

        /* Store the inode, so that we notice when the file is deleted */
        inode = (uint64_t) st.st_ino;
        fwrite(&inode, sizeof(inode), 1, pack);

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

        safe_close(fd);

        return r;
}

static unsigned long fd_first_block(int fd) {
        struct {
                struct fiemap fiemap;
                struct fiemap_extent extent;
        } data = {
                .fiemap.fm_length = ~0ULL,
                .fiemap.fm_extent_count = 1,
        };

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
        unsigned long bin;
};

static int qsort_compare(const void *a, const void *b) {
        const struct item *i, *j;

        i = a;
        j = b;

        /* sort by bin first */
        if (i->bin < j->bin)
                return -1;
        if (i->bin > j->bin)
                return 1;

        /* then sort by sector */
        if (i->block < j->block)
                return -1;
        if (i->block > j->block)
                return 1;

        return strcmp(i->path, j->path);
}

static int collect(const char *root) {
        enum {
                FD_FANOTIFY,  /* Get the actual fs events */
                FD_SIGNAL,
                FD_INOTIFY,   /* We get notifications to quit early via this fd */
                _FD_MAX
        };
        struct pollfd pollfd[_FD_MAX] = {};
        int fanotify_fd = -1, signal_fd = -1, inotify_fd = -1, r = 0;
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
        uint64_t previous_block_readahead;
        bool previous_block_readahead_set = false;

        assert(root);

        if (asprintf(&pack_fn, "%s/.readahead", root) < 0) {
                r = log_oom();
                goto finish;
        }

        starttime = now(CLOCK_MONOTONIC);

        /* If there's no pack file yet we lower the kernel readahead
         * so that mincore() is accurate. If there is a pack file
         * already we assume it is accurate enough so that kernel
         * readahead is never triggered. */
        previous_block_readahead_set =
                access(pack_fn, F_OK) < 0 &&
                block_get_readahead(root, &previous_block_readahead) >= 0 &&
                block_set_readahead(root, 8*1024) >= 0;

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

        files = hashmap_new(string_hash_func, string_compare_func);
        if (!files) {
                log_error("Failed to allocate set.");
                r = -ENOMEM;
                goto finish;
        }

        fanotify_fd = fanotify_init(FAN_CLOEXEC|FAN_NONBLOCK, O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_NOATIME);
        if (fanotify_fd < 0)  {
                log_error("Failed to create fanotify object: %m");
                r = -errno;
                goto finish;
        }

        if (fanotify_mark(fanotify_fd, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_OPEN, AT_FDCWD, root) < 0) {
                log_error("Failed to mark %s: %m", root);
                r = -errno;
                goto finish;
        }

        inotify_fd = open_inotify();
        if (inotify_fd < 0) {
                r = inotify_fd;
                goto finish;
        }

        not_after = now(CLOCK_MONOTONIC) + arg_timeout;

        my_pid = getpid();

        pollfd[FD_FANOTIFY].fd = fanotify_fd;
        pollfd[FD_FANOTIFY].events = POLLIN;
        pollfd[FD_SIGNAL].fd = signal_fd;
        pollfd[FD_SIGNAL].events = POLLIN;
        pollfd[FD_INOTIFY].fd = inotify_fd;
        pollfd[FD_INOTIFY].events = POLLIN;

        sd_notify(0,
                  "READY=1\n"
                  "STATUS=Collecting readahead data");

        log_debug("Collecting...");

        if (access("/run/systemd/readahead/cancel", F_OK) >= 0) {
                log_debug("Collection canceled");
                r = -ECANCELED;
                goto finish;
        }

        if (access("/run/systemd/readahead/done", F_OK) >= 0) {
                log_debug("Got termination request");
                goto done;
        }

        for (;;) {
                union {
                        struct fanotify_event_metadata metadata;
                        char buffer[4096];
                } data;
                ssize_t n;
                struct fanotify_event_metadata *m;
                usec_t t;
                int h;

                if (hashmap_size(files) > arg_files_max) {
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

                if (h == 0) {
                        log_debug("Reached maximum collection time, ending collection.");
                        break;
                }

                if (pollfd[FD_SIGNAL].revents) {
                        log_debug("Got signal.");
                        break;
                }

                if (pollfd[FD_INOTIFY].revents) {
                        uint8_t inotify_buffer[sizeof(struct inotify_event) + FILENAME_MAX];
                        struct inotify_event *e;

                        if ((n = read(inotify_fd, &inotify_buffer, sizeof(inotify_buffer))) < 0) {
                                if (errno == EINTR || errno == EAGAIN)
                                        continue;

                                log_error("Failed to read inotify event: %m");
                                r = -errno;
                                goto finish;
                        }

                        e = (struct inotify_event*) inotify_buffer;
                        while (n > 0) {
                                size_t step;

                                if ((e->mask & IN_CREATE) && streq(e->name, "cancel")) {
                                        log_debug("Collection canceled");
                                        r = -ECANCELED;
                                        goto finish;
                                }

                                if ((e->mask & IN_CREATE) && streq(e->name, "done")) {
                                        log_debug("Got termination request");
                                        goto done;
                                }

                                step = sizeof(struct inotify_event) + e->len;
                                assert(step <= (size_t) n);

                                e = (struct inotify_event*) ((uint8_t*) e + step);
                                n -= step;
                        }
                }

                n = read(fanotify_fd, &data, sizeof(data));
                if (n < 0) {

                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        /* fanotify sometimes returns EACCES on read()
                         * where it shouldn't. For now let's just
                         * ignore it here (which is safe), but
                         * eventually this should be
                         * dropped when the kernel is fixed.
                         *
                         * https://bugzilla.redhat.com/show_bug.cgi?id=707577 */
                        if (errno == EACCES)
                                continue;

                        log_error("Failed to read event: %m");
                        r = -errno;
                        goto finish;
                }

                for (m = &data.metadata; FAN_EVENT_OK(m, n); m = FAN_EVENT_NEXT(m, n)) {
                        char fn[sizeof("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
                        int k;

                        if (m->fd < 0)
                                goto next_iteration;

                        if (m->pid == my_pid)
                                goto next_iteration;

                        __sync_synchronize();
                        if (m->pid == shared->replay)
                                goto next_iteration;

                        snprintf(fn, sizeof(fn), "/proc/self/fd/%i", m->fd);
                        k = readlink_malloc(fn, &p);
                        if (k >= 0) {
                                if (startswith(p, "/tmp") ||
                                    endswith(p, " (deleted)") ||
                                    hashmap_get(files, p))
                                        /* Not interesting, or
                                         * already read */
                                        free(p);
                                else {
                                        unsigned long ul;
                                        usec_t entrytime;
                                        struct item *entry;

                                        entry = new0(struct item, 1);
                                        if (!entry) {
                                                r = log_oom();
                                                goto finish;
                                        }

                                        ul = fd_first_block(m->fd);

                                        entrytime = now(CLOCK_MONOTONIC);

                                        entry->block = ul;
                                        entry->path = strdup(p);
                                        if (!entry->path) {
                                                free(entry);
                                                r = log_oom();
                                                goto finish;
                                        }
                                        entry->bin = (entrytime - starttime) / 2000000;

                                        k = hashmap_put(files, p, entry);
                                        if (k < 0) {
                                                log_warning("hashmap_put() failed: %s", strerror(-k));
                                                free(p);
                                        }
                                }

                        } else
                                log_warning("readlink(%s) failed: %s", fn, strerror(-k));

                next_iteration:
                        safe_close(m->fd);
                }
        }

done:
        fanotify_fd = safe_close(fanotify_fd);

        log_debug("Writing Pack File...");

        on_ssd = fs_on_ssd(root) > 0;
        log_debug("On SSD: %s", yes_no(on_ssd));

        on_btrfs = statfs(root, &sfs) >= 0 && F_TYPE_EQUAL(sfs.f_type, BTRFS_SUPER_MAGIC);
        log_debug("On btrfs: %s", yes_no(on_btrfs));

        if (asprintf(&pack_fn_new, "%s/.readahead.new", root) < 0) {
                r = log_oom();
                goto finish;
        }

        pack = fopen(pack_fn_new, "we");
        if (!pack) {
                log_error("Failed to open pack file: %m");
                r = -errno;
                goto finish;
        }

        fputs(CANONICAL_HOST READAHEAD_PACK_FILE_VERSION, pack);
        putc(on_ssd ? 'S' : 'R', pack);

        if (on_ssd || on_btrfs) {

                /* On SSD or on btrfs, just write things out in the
                 * order the files were accessed. */

                HASHMAP_FOREACH_KEY(q, p, files, i)
                        pack_file(pack, p, on_btrfs);
        } else {
                unsigned n;

                /* On rotating media, order things by the block
                 * numbers */

                log_debug("Ordering...");

                n = hashmap_size(files);
                if (n) {
                        _cleanup_free_ struct item *ordered;
                        struct item *j;
                        unsigned k;

                        ordered = new(struct item, n);
                        if (!ordered) {
                                r = log_oom();
                                goto finish;
                        }

                        j = ordered;
                        HASHMAP_FOREACH_KEY(q, p, files, i) {
                                memcpy(j, q, sizeof(struct item));
                                j++;
                        }

                        assert(ordered + n == j);

                        qsort(ordered, n, sizeof(struct item), qsort_compare);

                        for (k = 0; k < n; k++)
                                pack_file(pack, ordered[k].path, on_btrfs);
                } else
                        log_warning("No pack files");
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
        safe_close(fanotify_fd);
        safe_close(signal_fd);
        safe_close(inotify_fd);

        if (pack) {
                fclose(pack);
                unlink(pack_fn_new);
        }
        free(pack_fn_new);
        free(pack_fn);

        while ((p = hashmap_steal_first_key(files)))
                free(p);

        hashmap_free(files);

        if (previous_block_readahead_set) {
                uint64_t bytes;

                /* Restore the original kernel readahead setting if we
                 * changed it, and nobody has overwritten it since
                 * yet. */
                if (block_get_readahead(root, &bytes) >= 0 && bytes == 8*1024)
                        block_set_readahead(root, previous_block_readahead);
        }

        return r;
}

int main_collect(const char *root) {

        if (!root)
                root = "/";

        /* Skip this step on read-only media. Note that we check the
         * underlying block device here, not he read-only flag of the
         * file system on top, since that one is most likely mounted
         * read-only anyway at boot, even if the underlying block
         * device is theoretically writable. */
        if (fs_on_read_only(root) > 0) {
                log_info("Disabling readahead collector due to read-only media.");
                return EXIT_SUCCESS;
        }

        if (!enough_ram()) {
                log_info("Disabling readahead collector due to low memory.");
                return EXIT_SUCCESS;
        }

        shared = shared_get();
        if (!shared)
                return EXIT_FAILURE;

        shared->collect = getpid();
        __sync_synchronize();

        if (collect(root) < 0)
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}
