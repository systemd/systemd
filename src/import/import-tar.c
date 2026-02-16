/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "btrfs-util.h"
#include "dissect-image.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "import-common.h"
#include "import-compress.h"
#include "import-tar.h"
#include "import-util.h"
#include "install-file.h"
#include "io-util.h"
#include "log.h"
#include "mkdir-label.h"
#include "path-util.h"
#include "pidref.h"
#include "pretty-print.h"
#include "process-util.h"
#include "ratelimit.h"
#include "rm-rf.h"
#include "string-util.h"
#include "terminal-util.h"
#include "time-util.h"
#include "tmpfile-util.h"

typedef struct TarImport {
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
        int tree_fd;
        int userns_fd;

        ImportCompress compress;

        sd_event_source *input_event_source;

        uint8_t buffer[IMPORT_BUFFER_SIZE];
        size_t buffer_size;

        uint64_t written_compressed;
        uint64_t written_uncompressed;

        struct stat input_stat;

        PidRef tar_pid;

        unsigned last_percent;
        RateLimit progress_ratelimit;
} TarImport;

TarImport* tar_import_unref(TarImport *i) {
        if (!i)
                return NULL;

        sd_event_source_unref(i->input_event_source);

        pidref_done_sigkill_wait(&i->tar_pid);

        if (i->temp_path) {
                import_remove_tree(i->temp_path, &i->userns_fd, i->flags);
                free(i->temp_path);
        }

        import_compress_free(&i->compress);

        sd_event_unref(i->event);

        safe_close(i->tar_fd);
        safe_close(i->tree_fd);
        safe_close(i->userns_fd);

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
        assert(image_root);

        root = strdup(image_root);
        if (!root)
                return -ENOMEM;

        i = new(TarImport, 1);
        if (!i)
                return -ENOMEM;

        *i = (TarImport) {
                .input_fd = -EBADF,
                .tar_fd = -EBADF,
                .tree_fd = -EBADF,
                .userns_fd = -EBADF,
                .on_finished = on_finished,
                .userdata = userdata,
                .last_percent = UINT_MAX,
                .image_root = TAKE_PTR(root),
                .progress_ratelimit = { 100 * USEC_PER_MSEC, 1 },
                .tar_pid = PIDREF_NULL,
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
        if (!S_ISREG(i->input_stat.st_mode))
                return;

        if (i->written_compressed >= (uint64_t) i->input_stat.st_size)
                percent = 100;
        else
                percent = (unsigned) ((i->written_compressed * UINT64_C(100)) / (uint64_t) i->input_stat.st_size);

        if (percent == i->last_percent)
                return;

        if (!ratelimit_below(&i->progress_ratelimit))
                return;

        sd_notifyf(false, "X_IMPORT_PROGRESS=%u%%", percent);

        if (isatty_safe(STDERR_FILENO))
                (void) draw_progress_barf(
                                percent,
                                "%s %s/%s",
                                glyph(GLYPH_ARROW_RIGHT),
                                FORMAT_BYTES(i->written_compressed),
                                FORMAT_BYTES(i->input_stat.st_size));
        else
                log_info("Imported %u%%.", percent);

        i->last_percent = percent;
}

static int tar_import_finish(TarImport *i) {
        const char *d;
        int r;

        assert(i);
        assert(i->tar_fd >= 0);
        assert(i->tree_fd >= 0);

        i->tar_fd = safe_close(i->tar_fd);

        if (pidref_is_set(&i->tar_pid)) {
                r = pidref_wait_for_terminate_and_check("tar", &i->tar_pid, WAIT_LOG);
                if (r < 0)
                        return r;

                pidref_done(&i->tar_pid);

                if (r != EXIT_SUCCESS)
                        return -EPROTO;
        }

        assert_se(d = i->temp_path ?: i->local);

        r = import_mangle_os_tree_fd(i->tree_fd, i->userns_fd, i->flags);
        if (r < 0)
                return r;

        r = install_file(
                        AT_FDCWD, d,
                        AT_FDCWD, i->final_path,
                        (i->flags & IMPORT_FORCE ? INSTALL_REPLACE : 0) |
                        (i->flags & IMPORT_READ_ONLY ? INSTALL_READ_ONLY|INSTALL_GRACEFUL : 0) |
                        (i->flags & IMPORT_SYNC ? INSTALL_SYNCFS|INSTALL_GRACEFUL : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to move '%s' into place: %m", i->final_path ?: i->local);

        i->temp_path = mfree(i->temp_path);

        return 0;
}

static int tar_import_fork_tar(TarImport *i) {
        const char *d, *root;
        int r;

        assert(i);
        assert(i->local);
        assert(!i->final_path);
        assert(!i->temp_path);
        assert(i->tar_fd < 0);
        assert(i->tree_fd < 0);

        if (i->flags & IMPORT_DIRECT) {
                d = i->local;
                root = NULL;
        } else {
                i->final_path = path_join(i->image_root, i->local);
                if (!i->final_path)
                        return log_oom();

                r = tempfn_random(i->final_path, NULL, &i->temp_path);
                if (r < 0)
                        return log_oom();

                d = i->temp_path;
                root = i->image_root;
        }

        assert(d);

        (void) mkdir_parents_label(d, 0700);

        if (FLAGS_SET(i->flags, IMPORT_DIRECT|IMPORT_FORCE))
                (void) rm_rf(d, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);

        if (FLAGS_SET(i->flags, IMPORT_FOREIGN_UID)) {
                r = import_make_foreign_userns(&i->userns_fd);
                if (r < 0)
                        return r;

                _cleanup_close_ int directory_fd = -EBADF;
                r = mountfsd_make_directory(d, MODE_INVALID, /* flags= */ 0, &directory_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to make directory via mountfsd: %m");

                r = mountfsd_mount_directory_fd(directory_fd, i->userns_fd, DISSECT_IMAGE_FOREIGN_UID, &i->tree_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed mount directory via mountfsd: %m");
        } else {
                if (i->flags & IMPORT_BTRFS_SUBVOL)
                        r = btrfs_subvol_make_fallback(AT_FDCWD, d, 0755);
                else
                        r = RET_NERRNO(mkdir(d, 0755));
                if (r == -EEXIST && (i->flags & IMPORT_DIRECT)) /* EEXIST is OK if in direct mode, but not otherwise,
                                                                 * because in that case our temporary path collided */
                        r = 0;
                if (r < 0)
                        return log_error_errno(r, "Failed to create directory/subvolume %s: %m", d);
                if (r > 0 && (i->flags & IMPORT_BTRFS_QUOTA)) { /* actually btrfs subvol */
                        if (!(i->flags & IMPORT_DIRECT))
                                (void) import_assign_pool_quota_and_warn(root);
                        (void) import_assign_pool_quota_and_warn(d);
                }

                i->tree_fd = open(d, O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
                if (i->tree_fd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", d);
        }

        i->tar_fd = import_fork_tar_x(i->tree_fd, i->userns_fd, &i->tar_pid);
        if (i->tar_fd < 0)
                return i->tar_fd;

        return 0;
}

static int tar_import_write(const void *p, size_t sz, void *userdata) {
        TarImport *i = userdata;
        int r;

        r = loop_write(i->tar_fd, p, sz);
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

        if ((size_t) l > sizeof(i->buffer) - i->buffer_size) {
                r = log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Read input file exceeded maximum size.");
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
        if (r >= 0 && isatty_safe(STDERR_FILENO))
                clear_progress_bar(/* prefix= */ NULL);

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
        assert(!(flags & ~IMPORT_FLAGS_MASK_TAR));

        if (!import_validate_local(local, flags))
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

        if (fstat(fd, &i->input_stat) < 0)
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
        return 0;
}
