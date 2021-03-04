/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/fs.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "btrfs-util.h"
#include "copy.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "import-common.h"
#include "import-compress.h"
#include "import-tar.h"
#include "io-util.h"
#include "machine-pool.h"
#include "mkdir.h"
#include "path-util.h"
#include "process-util.h"
#include "qcow2-util.h"
#include "ratelimit.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "util.h"

struct TarImport {
        sd_event *event;

        char *image_root;

        TarImportFinished on_finished;
        void *userdata;

        char *local;
        ImportFlags flags;

        char *temp_path;
        char *final_path;

        int input_fd;
        int tar_fd;

        ImportCompress compress;

        sd_event_source *input_event_source;

        uint8_t buffer[16*1024];
        size_t buffer_size;

        uint64_t written_compressed;
        uint64_t written_uncompressed;

        struct stat st;

        pid_t tar_pid;

        unsigned last_percent;
        RateLimit progress_ratelimit;
};

TarImport* tar_import_unref(TarImport *i) {
        if (!i)
                return NULL;

        sd_event_source_unref(i->input_event_source);

        if (i->tar_pid > 1) {
                (void) kill_and_sigcont(i->tar_pid, SIGKILL);
                (void) wait_for_terminate(i->tar_pid, NULL);
        }

        rm_rf_subvolume_and_free(i->temp_path);

        import_compress_free(&i->compress);

        sd_event_unref(i->event);

        safe_close(i->tar_fd);

        free(i->final_path);
        free(i->image_root);
        free(i->local);
        return mfree(i);
}

int tar_import_new(
                TarImport **ret,
                sd_event *event,
                const char *image_root,
                TarImportFinished on_finished,
                void *userdata) {

        _cleanup_(tar_import_unrefp) TarImport *i = NULL;
        _cleanup_free_ char *root = NULL;
        int r;

        assert(ret);

        root = strdup(image_root ?: "/var/lib/machines");
        if (!root)
                return -ENOMEM;

        i = new(TarImport, 1);
        if (!i)
                return -ENOMEM;

        *i = (TarImport) {
                .input_fd = -1,
                .tar_fd = -1,
                .on_finished = on_finished,
                .userdata = userdata,
                .last_percent = UINT_MAX,
                .image_root = TAKE_PTR(root),
                .progress_ratelimit = { 100 * USEC_PER_MSEC, 1 },
        };

        if (event)
                i->event = sd_event_ref(event);
        else {
                r = sd_event_default(&i->event);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(i);

        return 0;
}

static void tar_import_report_progress(TarImport *i) {
        unsigned percent;
        assert(i);

        /* We have no size information, unless the source is a regular file */
        if (!S_ISREG(i->st.st_mode))
                return;

        if (i->written_compressed >= (uint64_t) i->st.st_size)
                percent = 100;
        else
                percent = (unsigned) ((i->written_compressed * UINT64_C(100)) / (uint64_t) i->st.st_size);

        if (percent == i->last_percent)
                return;

        if (!ratelimit_below(&i->progress_ratelimit))
                return;

        sd_notifyf(false, "X_IMPORT_PROGRESS=%u", percent);
        log_info("Imported %u%%.", percent);

        i->last_percent = percent;
}

static int tar_import_finish(TarImport *i) {
        int r;

        assert(i);
        assert(i->tar_fd >= 0);
        assert(i->temp_path);
        assert(i->final_path);

        i->tar_fd = safe_close(i->tar_fd);

        if (i->tar_pid > 0) {
                r = wait_for_terminate_and_check("tar", i->tar_pid, WAIT_LOG);
                i->tar_pid = 0;
                if (r < 0)
                        return r;
                if (r != EXIT_SUCCESS)
                        return -EPROTO;
        }

        r = import_mangle_os_tree(i->temp_path);
        if (r < 0)
                return r;

        if (i->flags & IMPORT_READ_ONLY) {
                r = import_make_read_only(i->temp_path);
                if (r < 0)
                        return r;
        }

        if (i->flags & IMPORT_FORCE)
                (void) rm_rf(i->final_path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);

        r = rename_noreplace(AT_FDCWD, i->temp_path, AT_FDCWD, i->final_path);
        if (r < 0)
                return log_error_errno(r, "Failed to move image into place: %m");

        i->temp_path = mfree(i->temp_path);

        return 0;
}

static int tar_import_fork_tar(TarImport *i) {
        int r;

        assert(i);

        assert(!i->final_path);
        assert(!i->temp_path);
        assert(i->tar_fd < 0);

        i->final_path = path_join(i->image_root, i->local);
        if (!i->final_path)
                return log_oom();

        r = tempfn_random(i->final_path, NULL, &i->temp_path);
        if (r < 0)
                return log_oom();

        (void) mkdir_parents_label(i->temp_path, 0700);

        r = btrfs_subvol_make_fallback(i->temp_path, 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create directory/subvolume %s: %m", i->temp_path);
        if (r > 0) { /* actually btrfs subvol */
                (void) import_assign_pool_quota_and_warn(i->image_root);
                (void) import_assign_pool_quota_and_warn(i->temp_path);
        }

        i->tar_fd = import_fork_tar_x(i->temp_path, &i->tar_pid);
        if (i->tar_fd < 0)
                return i->tar_fd;

        return 0;
}

static int tar_import_write(const void *p, size_t sz, void *userdata) {
        TarImport *i = userdata;
        int r;

        r = loop_write(i->tar_fd, p, sz, false);
        if (r < 0)
                return r;

        i->written_uncompressed += sz;

        return 0;
}

static int tar_import_process(TarImport *i) {
        ssize_t l;
        int r;

        assert(i);
        assert(i->buffer_size < sizeof(i->buffer));

        l = read(i->input_fd, i->buffer + i->buffer_size, sizeof(i->buffer) - i->buffer_size);
        if (l < 0) {
                if (errno == EAGAIN)
                        return 0;

                r = log_error_errno(errno, "Failed to read input file: %m");
                goto finish;
        }

        i->buffer_size += l;

        if (i->compress.type == IMPORT_COMPRESS_UNKNOWN) {

                if (l == 0) { /* EOF */
                        log_debug("File too short to be compressed, as no compression signature fits in, thus assuming uncompressed.");
                        import_uncompress_force_off(&i->compress);
                } else {
                        r = import_uncompress_detect(&i->compress, i->buffer, i->buffer_size);
                        if (r < 0) {
                                log_error_errno(r, "Failed to detect file compression: %m");
                                goto finish;
                        }
                        if (r == 0) /* Need more data */
                                return 0;
                }

                r = tar_import_fork_tar(i);
                if (r < 0)
                        goto finish;
        }

        r = import_uncompress(&i->compress, i->buffer, i->buffer_size, tar_import_write, i);
        if (r < 0) {
                log_error_errno(r, "Failed to decode and write: %m");
                goto finish;
        }

        i->written_compressed += i->buffer_size;
        i->buffer_size = 0;

        if (l == 0) { /* EOF */
                r = tar_import_finish(i);
                goto finish;
        }

        tar_import_report_progress(i);

        return 0;

finish:
        if (i->on_finished)
                i->on_finished(i, r, i->userdata);
        else
                sd_event_exit(i->event, r);

        return 0;
}

static int tar_import_on_input(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        TarImport *i = userdata;

        return tar_import_process(i);
}

static int tar_import_on_defer(sd_event_source *s, void *userdata) {
        TarImport *i = userdata;

        return tar_import_process(i);
}

int tar_import_start(TarImport *i, int fd, const char *local, ImportFlags flags) {
        int r;

        assert(i);
        assert(fd >= 0);
        assert(local);
        assert(!(flags & ~IMPORT_FLAGS_MASK));

        if (!hostname_is_valid(local, 0))
                return -EINVAL;

        if (i->input_fd >= 0)
                return -EBUSY;

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        r = free_and_strdup(&i->local, local);
        if (r < 0)
                return r;

        i->flags = flags;

        if (fstat(fd, &i->st) < 0)
                return -errno;

        r = sd_event_add_io(i->event, &i->input_event_source, fd, EPOLLIN, tar_import_on_input, i);
        if (r == -EPERM) {
                /* This fd does not support epoll, for example because it is a regular file. Busy read in that case */
                r = sd_event_add_defer(i->event, &i->input_event_source, tar_import_on_defer, i);
                if (r < 0)
                        return r;

                r = sd_event_source_set_enabled(i->input_event_source, SD_EVENT_ON);
        }
        if (r < 0)
                return r;

        i->input_fd = fd;
        return r;
}
