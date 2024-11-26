/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/fs.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "btrfs-util.h"
#include "copy.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "import-common.h"
#include "import-compress.h"
#include "import-raw.h"
#include "install-file.h"
#include "io-util.h"
#include "machine-pool.h"
#include "mkdir-label.h"
#include "path-util.h"
#include "pretty-print.h"
#include "qcow2-util.h"
#include "ratelimit.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tmpfile-util.h"

struct RawImport {
        sd_event *event;

        char *image_root;

        RawImportFinished on_finished;
        void *userdata;

        char *local;
        ImportFlags flags;

        char *temp_path;
        char *final_path;

        int input_fd;
        int output_fd;

        ImportCompress compress;

        sd_event_source *input_event_source;

        uint8_t buffer[16*1024];
        size_t buffer_size;

        uint64_t written_compressed;
        uint64_t written_uncompressed;

        struct stat input_stat;
        struct stat output_stat;

        unsigned last_percent;
        RateLimit progress_ratelimit;

        uint64_t offset;
        uint64_t size_max;
};

RawImport* raw_import_unref(RawImport *i) {
        if (!i)
                return NULL;

        sd_event_source_unref(i->input_event_source);

        unlink_and_free(i->temp_path);

        import_compress_free(&i->compress);

        sd_event_unref(i->event);

        safe_close(i->output_fd);

        free(i->final_path);
        free(i->image_root);
        free(i->local);
        return mfree(i);
}

int raw_import_new(
                RawImport **ret,
                sd_event *event,
                const char *image_root,
                RawImportFinished on_finished,
                void *userdata) {

        _cleanup_(raw_import_unrefp) RawImport *i = NULL;
        _cleanup_free_ char *root = NULL;
        int r;

        assert(ret);
        assert(image_root);

        root = strdup(image_root);
        if (!root)
                return -ENOMEM;

        i = new(RawImport, 1);
        if (!i)
                return -ENOMEM;

        *i = (RawImport) {
                .input_fd = -EBADF,
                .output_fd = -EBADF,
                .on_finished = on_finished,
                .userdata = userdata,
                .last_percent = UINT_MAX,
                .image_root = TAKE_PTR(root),
                .progress_ratelimit = { 100 * USEC_PER_MSEC, 1 },
                .offset = UINT64_MAX,
                .size_max = UINT64_MAX,
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

static void raw_import_report_progress(RawImport *i) {
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
                                special_glyph(SPECIAL_GLYPH_ARROW_RIGHT),
                                FORMAT_BYTES(i->written_compressed),
                                FORMAT_BYTES(i->input_stat.st_size));
        else
                log_info("Imported %u%%.", percent);

        i->last_percent = percent;
}

static int raw_import_maybe_convert_qcow2(RawImport *i) {
        _cleanup_close_ int converted_fd = -EBADF;
        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_free_ char *f = NULL;
        int r;

        assert(i);

        /* Do QCOW2 conversion if enabled and not in direct mode */
        if ((i->flags & (IMPORT_CONVERT_QCOW2|IMPORT_DIRECT)) != IMPORT_CONVERT_QCOW2)
                return 0;

        assert(i->final_path);

        r = qcow2_detect(i->output_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to detect whether this is a QCOW2 image: %m");
        if (r == 0)
                return 0;

        /* This is a QCOW2 image, let's convert it */
        r = tempfn_random(i->final_path, NULL, &f);
        if (r < 0)
                return log_oom();

        converted_fd = open(f, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
        if (converted_fd < 0)
                return log_error_errno(errno, "Failed to create %s: %m", f);

        t = TAKE_PTR(f);

        (void) import_set_nocow_and_log(converted_fd, t);

        log_info("Unpacking QCOW2 file.");

        r = qcow2_convert(i->output_fd, converted_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to convert qcow2 image: %m");

        unlink_and_free(i->temp_path);
        i->temp_path = TAKE_PTR(t);
        close_and_replace(i->output_fd, converted_fd);

        return 1;
}

static int raw_import_finish(RawImport *i) {
        int r;

        assert(i);
        assert(i->output_fd >= 0);

        /* Nothing of what is below applies to block devices */
        if (S_ISBLK(i->output_stat.st_mode)) {

                if (i->flags & IMPORT_SYNC) {
                        if (fsync(i->output_fd) < 0)
                                return log_error_errno(errno, "Failed to synchronize block device: %m");
                }

                return 0;
        }

        assert(S_ISREG(i->output_stat.st_mode));

        /* If an offset is specified we only are supposed to affect part of an existing output file or block
         * device, thus don't manipulate file properties in that case */

        if (i->offset == UINT64_MAX) {
                /* In case this was a sparse file, make sure the file size is right */
                if (i->written_uncompressed > 0) {
                        if (ftruncate(i->output_fd, i->written_uncompressed) < 0)
                                return log_error_errno(errno, "Failed to truncate file: %m");
                }

                r = raw_import_maybe_convert_qcow2(i);
                if (r < 0)
                        return r;

                if (S_ISREG(i->input_stat.st_mode)) {
                        (void) copy_times(i->input_fd, i->output_fd, COPY_CRTIME);
                        (void) copy_xattr(i->input_fd, NULL, i->output_fd, NULL, 0);
                }
        }

        r = install_file(AT_FDCWD, i->temp_path ?: i->local,
                         AT_FDCWD, i->final_path,
                         (i->flags & IMPORT_FORCE ? INSTALL_REPLACE : 0) |
                         (i->flags & IMPORT_READ_ONLY ? INSTALL_READ_ONLY : 0) |
                         (i->flags & IMPORT_SYNC ? INSTALL_FSYNC_FULL : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to move image into place: %m");

        i->temp_path = mfree(i->temp_path);

        log_info("Wrote %s.", FORMAT_BYTES(i->written_uncompressed));

        return 0;
}

static int raw_import_open_disk(RawImport *i) {
        int r;

        assert(i);
        assert(i->local);
        assert(!i->final_path);
        assert(!i->temp_path);
        assert(i->output_fd < 0);

        if (i->flags & IMPORT_DIRECT) {
                (void) mkdir_parents_label(i->local, 0700);

                /* In direct mode we just open/create the local path and truncate it (like shell >
                 * redirection would do it) — except if an offset was passed, in which case we are supposed
                 * to operate on a section of the file only, in which case we apparently work on an some
                 * existing thing (i.e. are not the sole thing stored in the file), in which case we will
                 * neither truncate nor create. */

                i->output_fd = open(i->local, O_RDWR|O_NOCTTY|O_CLOEXEC|(i->offset == UINT64_MAX ? O_TRUNC|O_CREAT : 0), 0664);
                if (i->output_fd < 0)
                        return log_error_errno(errno, "Failed to open destination '%s': %m", i->local);

                if (i->offset == UINT64_MAX)
                        (void) import_set_nocow_and_log(i->output_fd, i->local);
        } else {
                i->final_path = strjoin(i->image_root, "/", i->local, ".raw");
                if (!i->final_path)
                        return log_oom();

                r = tempfn_random(i->final_path, NULL, &i->temp_path);
                if (r < 0)
                        return log_oom();

                (void) mkdir_parents_label(i->temp_path, 0700);

                i->output_fd = open(i->temp_path, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
                if (i->output_fd < 0)
                        return log_error_errno(errno, "Failed to open destination '%s': %m", i->temp_path);

                (void) import_set_nocow_and_log(i->output_fd, i->temp_path);
        }

        if (fstat(i->output_fd, &i->output_stat) < 0)
                return log_error_errno(errno, "Failed to stat() output file: %m");

        if (!S_ISREG(i->output_stat.st_mode) && !S_ISBLK(i->output_stat.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(EBADFD),
                                       "Target file is not a regular file or block device");

        if (i->offset != UINT64_MAX) {
                if (lseek(i->output_fd, i->offset, SEEK_SET) < 0)
                        return log_error_errno(errno, "Failed to seek to offset: %m");
        }

        return 0;
}

static int raw_import_try_reflink(RawImport *i) {
        off_t p;
        int r;

        assert(i);
        assert(i->input_fd >= 0);
        assert(i->output_fd >= 0);

        if (i->compress.type != IMPORT_COMPRESS_UNCOMPRESSED)
                return 0;

        if (i->offset != UINT64_MAX || i->size_max != UINT64_MAX)
                return 0;

        if (!S_ISREG(i->input_stat.st_mode) || !S_ISREG(i->output_stat.st_mode))
                return 0;

        p = lseek(i->input_fd, 0, SEEK_CUR);
        if (p < 0)
                return log_error_errno(errno, "Failed to read file offset of input file: %m");

        /* Let's only try a btrfs reflink, if we are reading from the beginning of the file */
        if ((uint64_t) p != (uint64_t) i->buffer_size)
                return 0;

        r = reflink(i->input_fd, i->output_fd);
        if (r >= 0)
                return 1;

        log_debug_errno(r, "Couldn't establish reflink, using copy: %m");
        return 0;
}

static int raw_import_write(const void *p, size_t sz, void *userdata) {
        RawImport *i = ASSERT_PTR(userdata);
        bool too_much = false;
        int r;

        assert(p);
        assert(sz > 0);

        if (i->written_uncompressed >= UINT64_MAX - sz)
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "File too large, overflow");

        if (i->size_max != UINT64_MAX) {
                if (i->written_uncompressed >= i->size_max) {
                        too_much = true;
                        goto finish;
                }

                if (i->written_uncompressed + sz > i->size_max) {
                        too_much = true;
                        sz = i->size_max - i->written_uncompressed; /* since we have the data in memory
                                                                     * already, we might as well write it to
                                                                     * disk to the max */
                }
        }

        /* Generate sparse file if we created/truncated the file */
        if (S_ISREG(i->output_stat.st_mode) && i->offset == UINT64_MAX) {
                ssize_t n;

                n = sparse_write(i->output_fd, p, sz, 64);
                if (n < 0)
                        return log_error_errno((int) n, "Failed to write file: %m");
                if ((size_t) n < sz)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write");
        } else {
                r = loop_write(i->output_fd, p, sz);
                if (r < 0)
                        return log_error_errno(r, "Failed to write file: %m");
        }

        i->written_uncompressed += sz;

finish:
        if (too_much)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "File too large");

        return 0;
}

static int raw_import_process(RawImport *i) {
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

                r = raw_import_open_disk(i);
                if (r < 0)
                        goto finish;

                r = raw_import_try_reflink(i);
                if (r < 0)
                        goto finish;
                if (r > 0)
                        goto complete;
        }

        r = import_uncompress(&i->compress, i->buffer, i->buffer_size, raw_import_write, i);
        if (r < 0) {
                log_error_errno(r, "Failed to decode and write: %m");
                goto finish;
        }

        i->written_compressed += i->buffer_size;
        i->buffer_size = 0;

        if (l == 0) /* EOF */
                goto complete;

        raw_import_report_progress(i);

        return 0;

complete:
        if (isatty_safe(STDERR_FILENO))
                clear_progress_bar(/* prefix= */ NULL);

        r = raw_import_finish(i);

finish:
        if (i->on_finished)
                i->on_finished(i, r, i->userdata);
        else
                sd_event_exit(i->event, r);

        return 0;
}

static int raw_import_on_input(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        RawImport *i = userdata;

        return raw_import_process(i);
}

static int raw_import_on_defer(sd_event_source *s, void *userdata) {
        RawImport *i = userdata;

        return raw_import_process(i);
}

int raw_import_start(
                RawImport *i,
                int fd,
                const char *local,
                uint64_t offset,
                uint64_t size_max,
                ImportFlags flags) {
        int r;

        assert(i);
        assert(fd >= 0);
        assert(local);
        assert(!(flags & ~IMPORT_FLAGS_MASK_RAW));
        assert(offset == UINT64_MAX || FLAGS_SET(flags, IMPORT_DIRECT));

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
        i->offset = offset;
        i->size_max = size_max;

        if (fstat(fd, &i->input_stat) < 0)
                return -errno;

        r = sd_event_add_io(i->event, &i->input_event_source, fd, EPOLLIN, raw_import_on_input, i);
        if (r == -EPERM) {
                /* This fd does not support epoll, for example because it is a regular file. Busy read in that case */
                r = sd_event_add_defer(i->event, &i->input_event_source, raw_import_on_defer, i);
                if (r < 0)
                        return r;

                r = sd_event_source_set_enabled(i->input_event_source, SD_EVENT_ON);
        }
        if (r < 0)
                return r;

        i->input_fd = fd;
        return 0;
}
