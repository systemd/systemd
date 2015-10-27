/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include "sd-daemon.h"

#include "alloc-util.h"
#include "btrfs-util.h"
#include "export-tar.h"
#include "fd-util.h"
#include "fileio.h"
#include "import-common.h"
#include "process-util.h"
#include "ratelimit.h"
#include "string-util.h"
#include "util.h"

#define COPY_BUFFER_SIZE (16*1024)

struct TarExport {
        sd_event *event;

        TarExportFinished on_finished;
        void *userdata;

        char *path;
        char *temp_path;

        int output_fd;
        int tar_fd;

        ImportCompress compress;

        sd_event_source *output_event_source;

        void *buffer;
        size_t buffer_size;
        size_t buffer_allocated;

        uint64_t written_compressed;
        uint64_t written_uncompressed;

        pid_t tar_pid;

        struct stat st;
        uint64_t quota_referenced;

        unsigned last_percent;
        RateLimit progress_rate_limit;

        bool eof;
        bool tried_splice;
};

TarExport *tar_export_unref(TarExport *e) {
        if (!e)
                return NULL;

        sd_event_source_unref(e->output_event_source);

        if (e->tar_pid > 1) {
                (void) kill_and_sigcont(e->tar_pid, SIGKILL);
                (void) wait_for_terminate(e->tar_pid, NULL);
        }

        if (e->temp_path) {
                (void) btrfs_subvol_remove(e->temp_path, BTRFS_REMOVE_QUOTA);
                free(e->temp_path);
        }

        import_compress_free(&e->compress);

        sd_event_unref(e->event);

        safe_close(e->tar_fd);

        free(e->buffer);
        free(e->path);
        free(e);

        return NULL;
}

int tar_export_new(
                TarExport **ret,
                sd_event *event,
                TarExportFinished on_finished,
                void *userdata) {

        _cleanup_(tar_export_unrefp) TarExport *e = NULL;
        int r;

        assert(ret);

        e = new0(TarExport, 1);
        if (!e)
                return -ENOMEM;

        e->output_fd = e->tar_fd = -1;
        e->on_finished = on_finished;
        e->userdata = userdata;
        e->quota_referenced = (uint64_t) -1;

        RATELIMIT_INIT(e->progress_rate_limit, 100 * USEC_PER_MSEC, 1);
        e->last_percent = (unsigned) -1;

        if (event)
                e->event = sd_event_ref(event);
        else {
                r = sd_event_default(&e->event);
                if (r < 0)
                        return r;
        }

        *ret = e;
        e = NULL;

        return 0;
}

static void tar_export_report_progress(TarExport *e) {
        unsigned percent;
        assert(e);

        /* Do we have any quota info? If not, we don't know anything about the progress */
        if (e->quota_referenced == (uint64_t) -1)
                return;

        if (e->written_uncompressed >= e->quota_referenced)
                percent = 100;
        else
                percent = (unsigned) ((e->written_uncompressed * UINT64_C(100)) / e->quota_referenced);

        if (percent == e->last_percent)
                return;

        if (!ratelimit_test(&e->progress_rate_limit))
                return;

        sd_notifyf(false, "X_IMPORT_PROGRESS=%u", percent);
        log_info("Exported %u%%.", percent);

        e->last_percent = percent;
}

static int tar_export_process(TarExport *e) {
        ssize_t l;
        int r;

        assert(e);

        if (!e->tried_splice && e->compress.type == IMPORT_COMPRESS_UNCOMPRESSED) {

                l = splice(e->tar_fd, NULL, e->output_fd, NULL, COPY_BUFFER_SIZE, 0);
                if (l < 0) {
                        if (errno == EAGAIN)
                                return 0;

                        e->tried_splice = true;
                } else if (l == 0) {
                        r = 0;
                        goto finish;
                } else {
                        e->written_uncompressed += l;
                        e->written_compressed += l;

                        tar_export_report_progress(e);

                        return 0;
                }
        }

        while (e->buffer_size <= 0) {
                uint8_t input[COPY_BUFFER_SIZE];

                if (e->eof) {
                        r = 0;
                        goto finish;
                }

                l = read(e->tar_fd, input, sizeof(input));
                if (l < 0) {
                        r = log_error_errno(errno, "Failed to read tar file: %m");
                        goto finish;
                }

                if (l == 0) {
                        e->eof = true;
                        r = import_compress_finish(&e->compress, &e->buffer, &e->buffer_size, &e->buffer_allocated);
                } else {
                        e->written_uncompressed += l;
                        r = import_compress(&e->compress, input, l, &e->buffer, &e->buffer_size, &e->buffer_allocated);
                }
                if (r < 0) {
                        r = log_error_errno(r, "Failed to encode: %m");
                        goto finish;
                }
        }

        l = write(e->output_fd, e->buffer, e->buffer_size);
        if (l < 0) {
                if (errno == EAGAIN)
                        return 0;

                r = log_error_errno(errno, "Failed to write output file: %m");
                goto finish;
        }

        assert((size_t) l <= e->buffer_size);
        memmove(e->buffer, (uint8_t*) e->buffer + l, e->buffer_size - l);
        e->buffer_size -= l;
        e->written_compressed += l;

        tar_export_report_progress(e);

        return 0;

finish:
        if (e->on_finished)
                e->on_finished(e, r, e->userdata);
        else
                sd_event_exit(e->event, r);

        return 0;
}

static int tar_export_on_output(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        TarExport *i = userdata;

        return tar_export_process(i);
}

static int tar_export_on_defer(sd_event_source *s, void *userdata) {
        TarExport *i = userdata;

        return tar_export_process(i);
}

int tar_export_start(TarExport *e, const char *path, int fd, ImportCompressType compress) {
        _cleanup_close_ int sfd = -1;
        int r;

        assert(e);
        assert(path);
        assert(fd >= 0);
        assert(compress < _IMPORT_COMPRESS_TYPE_MAX);
        assert(compress != IMPORT_COMPRESS_UNKNOWN);

        if (e->output_fd >= 0)
                return -EBUSY;

        sfd = open(path, O_DIRECTORY|O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (sfd < 0)
                return -errno;

        if (fstat(sfd, &e->st) < 0)
                return -errno;

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        r = free_and_strdup(&e->path, path);
        if (r < 0)
                return r;

        e->quota_referenced = (uint64_t) -1;

        if (e->st.st_ino == 256) { /* might be a btrfs subvolume? */
                BtrfsQuotaInfo q;

                r = btrfs_subvol_get_subtree_quota_fd(sfd, 0, &q);
                if (r >= 0)
                        e->quota_referenced = q.referenced;

                e->temp_path = mfree(e->temp_path);

                r = tempfn_random(path, NULL, &e->temp_path);
                if (r < 0)
                        return r;

                /* Let's try to make a snapshot, if we can, so that the export is atomic */
                r = btrfs_subvol_snapshot_fd(sfd, e->temp_path, BTRFS_SNAPSHOT_READ_ONLY|BTRFS_SNAPSHOT_RECURSIVE);
                if (r < 0) {
                        log_debug_errno(r, "Couldn't create snapshot %s of %s, not exporting atomically: %m", e->temp_path, path);
                        e->temp_path = mfree(e->temp_path);
                }
        }

        r = import_compress_init(&e->compress, compress);
        if (r < 0)
                return r;

        r = sd_event_add_io(e->event, &e->output_event_source, fd, EPOLLOUT, tar_export_on_output, e);
        if (r == -EPERM) {
                r = sd_event_add_defer(e->event, &e->output_event_source, tar_export_on_defer, e);
                if (r < 0)
                        return r;

                r = sd_event_source_set_enabled(e->output_event_source, SD_EVENT_ON);
        }
        if (r < 0)
                return r;

        e->tar_fd = import_fork_tar_c(e->temp_path ?: e->path, &e->tar_pid);
        if (e->tar_fd < 0) {
                e->output_event_source = sd_event_source_unref(e->output_event_source);
                return e->tar_fd;
        }

        e->output_fd = fd;
        return r;
}
