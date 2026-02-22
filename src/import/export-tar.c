/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "btrfs-util.h"
#include "dissect-image.h"
#include "export-tar.h"
#include "fd-util.h"
#include "format-util.h"
#include "import-common.h"
#include "log.h"
#include "pidref.h"
#include "pretty-print.h"
#include "process-util.h"
#include "ratelimit.h"
#include "string-util.h"
#include "terminal-util.h"
#include "time-util.h"
#include "tmpfile-util.h"

typedef struct TarExport {
        sd_event *event;

        TarExportFinished on_finished;
        void *userdata;

        ImportFlags flags;

        char *path;
        char *temp_path;

        int output_fd; /* compressed tar file in the fs */
        int tar_fd;    /* uncompressed tar stream coming from child doing the libarchive loop */
        int tree_fd;   /* directory fd of the tree to set up */
        int userns_fd;

        ImportCompress compress;

        sd_event_source *output_event_source;

        void *buffer;
        size_t buffer_size;
        size_t buffer_allocated;

        uint64_t written_compressed;
        uint64_t written_uncompressed;

        PidRef tar_pid;

        struct stat st;
        uint64_t quota_referenced;

        unsigned last_percent;
        RateLimit progress_ratelimit;

        bool eof;
        bool tried_splice;
} TarExport;

TarExport *tar_export_unref(TarExport *e) {
        if (!e)
                return NULL;

        sd_event_source_unref(e->output_event_source);

        pidref_done_sigkill_wait(&e->tar_pid);

        if (e->temp_path) {
                (void) btrfs_subvol_remove(e->temp_path, BTRFS_REMOVE_QUOTA);
                free(e->temp_path);
        }

        import_compress_free(&e->compress);

        sd_event_unref(e->event);

        safe_close(e->tar_fd);

        free(e->buffer);
        free(e->path);
        return mfree(e);
}

int tar_export_new(
                TarExport **ret,
                sd_event *event,
                TarExportFinished on_finished,
                void *userdata) {

        _cleanup_(tar_export_unrefp) TarExport *e = NULL;
        int r;

        assert(ret);

        e = new(TarExport, 1);
        if (!e)
                return -ENOMEM;

        *e = (TarExport) {
                .output_fd = -EBADF,
                .tar_fd = -EBADF,
                .tree_fd = -EBADF,
                .userns_fd = -EBADF,
                .on_finished = on_finished,
                .userdata = userdata,
                .quota_referenced = UINT64_MAX,
                .last_percent = UINT_MAX,
                .progress_ratelimit = { 100 * USEC_PER_MSEC, 1 },
                .tar_pid = PIDREF_NULL,
        };

        if (event)
                e->event = sd_event_ref(event);
        else {
                r = sd_event_default(&e->event);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(e);

        return 0;
}

static void tar_export_report_progress(TarExport *e) {
        unsigned percent;
        assert(e);

        /* Do we have any quota info? If not, we don't know anything about the progress */
        if (e->quota_referenced == UINT64_MAX)
                return;

        if (e->written_uncompressed >= e->quota_referenced)
                percent = 100;
        else
                percent = (unsigned) ((e->written_uncompressed * UINT64_C(100)) / e->quota_referenced);

        if (percent == e->last_percent)
                return;

        if (!ratelimit_below(&e->progress_ratelimit))
                return;

        sd_notifyf(false, "X_IMPORT_PROGRESS=%u%%", percent);

        if (isatty_safe(STDERR_FILENO))
                (void) draw_progress_barf(
                                percent,
                                "%s %s/%s",
                                glyph(GLYPH_ARROW_RIGHT),
                                FORMAT_BYTES(e->written_uncompressed),
                                FORMAT_BYTES(e->quota_referenced));
        else
                log_info("Exported %u%%.", percent);

        e->last_percent = percent;
}

static int tar_export_finish(TarExport *e) {
        int r;

        assert(e);
        assert(e->tar_fd >= 0);

        if (pidref_is_set(&e->tar_pid)) {
                r = pidref_wait_for_terminate_and_check("tar", &e->tar_pid, WAIT_LOG);
                if (r < 0)
                        return r;

                pidref_done(&e->tar_pid);

                if (r != EXIT_SUCCESS)
                        return -EPROTO;
        }

        e->tar_fd = safe_close(e->tar_fd);

        return 0;
}

static int tar_export_process(TarExport *e) {
        ssize_t l;
        int r;

        assert(e);

        if (!e->tried_splice && e->compress.type == IMPORT_COMPRESS_UNCOMPRESSED) {

                l = splice(e->tar_fd, NULL, e->output_fd, NULL, IMPORT_BUFFER_SIZE, 0);
                if (l < 0) {
                        if (errno == EAGAIN)
                                return 0;

                        e->tried_splice = true;
                } else if (l == 0) {
                        r = tar_export_finish(e);
                        goto finish;
                } else {
                        e->written_uncompressed += l;
                        e->written_compressed += l;

                        tar_export_report_progress(e);

                        return 0;
                }
        }

        while (e->buffer_size <= 0) {
                uint8_t input[IMPORT_BUFFER_SIZE];

                if (e->eof) {
                        r = tar_export_finish(e);
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
        if (r >= 0 && isatty_safe(STDERR_FILENO))
                clear_progress_bar(/* prefix= */ NULL);

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

int tar_export_start(
                TarExport *e,
                const char *path,
                int fd,
                ImportCompressType compress,
                ImportFlags flags) {

        _cleanup_close_ int sfd = -EBADF;
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

        e->flags = flags;
        e->quota_referenced = UINT64_MAX;

        if (btrfs_might_be_subvol(&e->st)) {
                BtrfsQuotaInfo q;

                r = btrfs_subvol_get_subtree_quota_fd(sfd, 0, &q);
                if (r >= 0)
                        e->quota_referenced = q.referenced;

                e->temp_path = mfree(e->temp_path);

                r = tempfn_random(path, NULL, &e->temp_path);
                if (r < 0)
                        return r;

                /* Let's try to make a snapshot, if we can, so that the export is atomic */
                r = btrfs_subvol_snapshot_at(sfd, NULL, AT_FDCWD, e->temp_path, BTRFS_SNAPSHOT_READ_ONLY|BTRFS_SNAPSHOT_RECURSIVE);
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

        const char *p = e->temp_path ?: e->path;

        if (FLAGS_SET(e->flags, IMPORT_FOREIGN_UID)) {
                r = import_make_foreign_userns(&e->userns_fd);
                if (r < 0)
                        return r;

                _cleanup_close_ int directory_fd = open(p, O_DIRECTORY|O_CLOEXEC|O_PATH);
                if (directory_fd < 0)
                        return log_error_errno(r, "Failed to open '%s': %m", p);

                _cleanup_close_ int mapped_fd = -EBADF;
                r = mountfsd_mount_directory_fd(
                                /* vl= */ NULL,
                                directory_fd,
                                e->userns_fd,
                                DISSECT_IMAGE_FOREIGN_UID,
                                &mapped_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to mount directory via mountfsd: %m");

                /* Drop O_PATH */
                e->tree_fd = fd_reopen(mapped_fd, O_DIRECTORY|O_CLOEXEC);
                if (e->tree_fd < 0)
                        return log_error_errno(errno, "Failed to re-open mapped '%s': %m", p);
        } else {
                e->tree_fd = open(p, O_DIRECTORY|O_CLOEXEC);
                if (e->tree_fd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", p);
        }

        e->tar_fd = import_fork_tar_c(e->tree_fd, e->userns_fd, &e->tar_pid);
        if (e->tar_fd < 0) {
                e->output_event_source = sd_event_source_unref(e->output_event_source);
                return e->tar_fd;
        }

        e->output_fd = fd;
        return r;
}
