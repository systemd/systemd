/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-vacuum.h"
#include "parse-util.h"
#include "string-util.h"
#include "time-util.h"
#include "util.h"
#include "xattr-util.h"

struct vacuum_info {
        uint64_t usage;
        char *filename;

        uint64_t realtime;

        sd_id128_t seqnum_id;
        uint64_t seqnum;
        bool have_seqnum;
};

static int vacuum_compare(const struct vacuum_info *a, const struct vacuum_info *b) {
        int r;

        if (a->have_seqnum && b->have_seqnum &&
            sd_id128_equal(a->seqnum_id, b->seqnum_id))
                return CMP(a->seqnum, b->seqnum);

        r = CMP(a->realtime, b->realtime);
        if (r != 0)
                return r;

        if (a->have_seqnum && b->have_seqnum)
                return memcmp(&a->seqnum_id, &b->seqnum_id, 16);

        return strcmp(a->filename, b->filename);
}

static void patch_realtime(
                int fd,
                const char *fn,
                const struct stat *st,
                unsigned long long *realtime) {

        usec_t x, crtime = 0;

        /* The timestamp was determined by the file name, but let's
         * see if the file might actually be older than the file name
         * suggested... */

        assert(fd >= 0);
        assert(fn);
        assert(st);
        assert(realtime);

        x = timespec_load(&st->st_ctim);
        if (x > 0 && x != USEC_INFINITY && x < *realtime)
                *realtime = x;

        x = timespec_load(&st->st_atim);
        if (x > 0 && x != USEC_INFINITY && x < *realtime)
                *realtime = x;

        x = timespec_load(&st->st_mtim);
        if (x > 0 && x != USEC_INFINITY && x < *realtime)
                *realtime = x;

        /* Let's read the original creation time, if possible. Ideally
         * we'd just query the creation time the FS might provide, but
         * unfortunately there's currently no sane API to query
         * it. Hence let's implement this manually... */

        if (fd_getcrtime_at(fd, fn, &crtime, 0) >= 0) {
                if (crtime < *realtime)
                        *realtime = crtime;
        }
}

static int journal_file_empty(int dir_fd, const char *name) {
        _cleanup_close_ int fd;
        struct stat st;
        le64_t n_entries;
        ssize_t n;

        fd = openat(dir_fd, name, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK|O_NOATIME);
        if (fd < 0) {
                /* Maybe failed due to O_NOATIME and lack of privileges? */
                fd = openat(dir_fd, name, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
                if (fd < 0)
                        return -errno;
        }

        if (fstat(fd, &st) < 0)
                return -errno;

        /* If an offline file doesn't even have a header we consider it empty */
        if (st.st_size < (off_t) sizeof(Header))
                return 1;

        /* If the number of entries is empty, we consider it empty, too */
        n = pread(fd, &n_entries, sizeof(n_entries), offsetof(Header, n_entries));
        if (n < 0)
                return -errno;
        if (n != sizeof(n_entries))
                return -EIO;

        return le64toh(n_entries) <= 0;
}

int journal_directory_vacuum(
                const char *directory,
                uint64_t max_use,
                uint64_t n_max_files,
                usec_t max_retention_usec,
                usec_t *oldest_usec,
                bool verbose) {

        uint64_t sum = 0, freed = 0, n_active_files = 0;
        size_t n_list = 0, n_allocated = 0, i;
        _cleanup_closedir_ DIR *d = NULL;
        struct vacuum_info *list = NULL;
        usec_t retention_limit = 0;
        char sbytes[FORMAT_BYTES_MAX];
        struct dirent *de;
        int r;

        assert(directory);

        if (max_use <= 0 && max_retention_usec <= 0 && n_max_files <= 0)
                return 0;

        if (max_retention_usec > 0)
                retention_limit = usec_sub_unsigned(now(CLOCK_REALTIME), max_retention_usec);

        d = opendir(directory);
        if (!d)
                return -errno;

        FOREACH_DIRENT_ALL(de, d, r = -errno; goto finish) {

                unsigned long long seqnum = 0, realtime;
                _cleanup_free_ char *p = NULL;
                sd_id128_t seqnum_id;
                bool have_seqnum;
                uint64_t size;
                struct stat st;
                size_t q;

                if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                        log_debug_errno(errno, "Failed to stat file %s while vacuuming, ignoring: %m", de->d_name);
                        continue;
                }

                if (!S_ISREG(st.st_mode))
                        continue;

                q = strlen(de->d_name);

                if (endswith(de->d_name, ".journal")) {

                        /* Vacuum archived files. Active files are
                         * left around */

                        if (q < 1 + 32 + 1 + 16 + 1 + 16 + 8) {
                                n_active_files++;
                                continue;
                        }

                        if (de->d_name[q-8-16-1] != '-' ||
                            de->d_name[q-8-16-1-16-1] != '-' ||
                            de->d_name[q-8-16-1-16-1-32-1] != '@') {
                                n_active_files++;
                                continue;
                        }

                        p = strdup(de->d_name);
                        if (!p) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        de->d_name[q-8-16-1-16-1] = 0;
                        if (sd_id128_from_string(de->d_name + q-8-16-1-16-1-32, &seqnum_id) < 0) {
                                n_active_files++;
                                continue;
                        }

                        if (sscanf(de->d_name + q-8-16-1-16, "%16llx-%16llx.journal", &seqnum, &realtime) != 2) {
                                n_active_files++;
                                continue;
                        }

                        have_seqnum = true;

                } else if (endswith(de->d_name, ".journal~")) {
                        unsigned long long tmp;

                        /* Vacuum corrupted files */

                        if (q < 1 + 16 + 1 + 16 + 8 + 1) {
                                n_active_files++;
                                continue;
                        }

                        if (de->d_name[q-1-8-16-1] != '-' ||
                            de->d_name[q-1-8-16-1-16-1] != '@') {
                                n_active_files++;
                                continue;
                        }

                        p = strdup(de->d_name);
                        if (!p) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        if (sscanf(de->d_name + q-1-8-16-1-16, "%16llx-%16llx.journal~", &realtime, &tmp) != 2) {
                                n_active_files++;
                                continue;
                        }

                        have_seqnum = false;
                } else {
                        /* We do not vacuum unknown files! */
                        log_debug("Not vacuuming unknown file %s.", de->d_name);
                        continue;
                }

                size = 512UL * (uint64_t) st.st_blocks;

                r = journal_file_empty(dirfd(d), p);
                if (r < 0) {
                        log_debug_errno(r, "Failed check if %s is empty, ignoring: %m", p);
                        continue;
                }
                if (r > 0) {
                        /* Always vacuum empty non-online files. */

                        r = unlinkat_deallocate(dirfd(d), p, 0);
                        if (r >= 0) {

                                log_full(verbose ? LOG_INFO : LOG_DEBUG,
                                         "Deleted empty archived journal %s/%s (%s).", directory, p, format_bytes(sbytes, sizeof(sbytes), size));

                                freed += size;
                        } else if (r != -ENOENT)
                                log_warning_errno(r, "Failed to delete empty archived journal %s/%s: %m", directory, p);

                        continue;
                }

                patch_realtime(dirfd(d), p, &st, &realtime);

                if (!GREEDY_REALLOC(list, n_allocated, n_list + 1)) {
                        r = -ENOMEM;
                        goto finish;
                }

                list[n_list++] = (struct vacuum_info) {
                        .filename = TAKE_PTR(p),
                        .usage = size,
                        .seqnum = seqnum,
                        .realtime = realtime,
                        .seqnum_id = seqnum_id,
                        .have_seqnum = have_seqnum,
                };

                sum += size;
        }

        typesafe_qsort(list, n_list, vacuum_compare);

        for (i = 0; i < n_list; i++) {
                uint64_t left;

                left = n_active_files + n_list - i;

                if ((max_retention_usec <= 0 || list[i].realtime >= retention_limit) &&
                    (max_use <= 0 || sum <= max_use) &&
                    (n_max_files <= 0 || left <= n_max_files))
                        break;

                r = unlinkat_deallocate(dirfd(d), list[i].filename, 0);
                if (r >= 0) {
                        log_full(verbose ? LOG_INFO : LOG_DEBUG, "Deleted archived journal %s/%s (%s).", directory, list[i].filename, format_bytes(sbytes, sizeof(sbytes), list[i].usage));
                        freed += list[i].usage;

                        if (list[i].usage < sum)
                                sum -= list[i].usage;
                        else
                                sum = 0;

                } else if (r != -ENOENT)
                        log_warning_errno(r, "Failed to delete archived journal %s/%s: %m", directory, list[i].filename);
        }

        if (oldest_usec && i < n_list && (*oldest_usec == 0 || list[i].realtime < *oldest_usec))
                *oldest_usec = list[i].realtime;

        r = 0;

finish:
        for (i = 0; i < n_list; i++)
                free(list[i].filename);
        free(list);

        log_full(verbose ? LOG_INFO : LOG_DEBUG, "Vacuuming done, freed %s of archived journals from %s.", format_bytes(sbytes, sizeof(sbytes), freed), directory);

        return r;
}
