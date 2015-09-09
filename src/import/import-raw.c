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

#include <linux/fs.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "util.h"
#include "path-util.h"
#include "btrfs-util.h"
#include "hostname-util.h"
#include "copy.h"
#include "mkdir.h"
#include "rm-rf.h"
#include "ratelimit.h"
#include "machine-pool.h"
#include "qcow2-util.h"
#include "import-compress.h"
#include "import-common.h"
#include "import-raw.h"

struct RawImport {
        sd_event *event;

        char *image_root;

        RawImportFinished on_finished;
        void *userdata;

        char *local;
        bool force_local;
        bool read_only;
        bool grow_machine_directory;

        char *temp_path;
        char *final_path;

        int input_fd;
        int output_fd;

        ImportCompress compress;

        uint64_t written_since_last_grow;

        sd_event_source *input_event_source;

        uint8_t buffer[16*1024];
        size_t buffer_size;

        uint64_t written_compressed;
        uint64_t written_uncompressed;

        struct stat st;

        unsigned last_percent;
        RateLimit progress_rate_limit;
};

RawImport* raw_import_unref(RawImport *i) {
        if (!i)
                return NULL;

        sd_event_unref(i->event);

        if (i->temp_path) {
                (void) unlink(i->temp_path);
                free(i->temp_path);
        }

        import_compress_free(&i->compress);

        sd_event_source_unref(i->input_event_source);

        safe_close(i->output_fd);

        free(i->final_path);
        free(i->image_root);
        free(i->local);
        free(i);

        return NULL;
}

int raw_import_new(
                RawImport **ret,
                sd_event *event,
                const char *image_root,
                RawImportFinished on_finished,
                void *userdata) {

        _cleanup_(raw_import_unrefp) RawImport *i = NULL;
        int r;

        assert(ret);

        i = new0(RawImport, 1);
        if (!i)
                return -ENOMEM;

        i->input_fd = i->output_fd = -1;
        i->on_finished = on_finished;
        i->userdata = userdata;

        RATELIMIT_INIT(i->progress_rate_limit, 100 * USEC_PER_MSEC, 1);
        i->last_percent = (unsigned) -1;

        i->image_root = strdup(image_root ?: "/var/lib/machines");
        if (!i->image_root)
                return -ENOMEM;

        i->grow_machine_directory = path_startswith(i->image_root, "/var/lib/machines");

        if (event)
                i->event = sd_event_ref(event);
        else {
                r = sd_event_default(&i->event);
                if (r < 0)
                        return r;
        }

        *ret = i;
        i = NULL;

        return 0;
}

static void raw_import_report_progress(RawImport *i) {
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

        if (!ratelimit_test(&i->progress_rate_limit))
                return;

        sd_notifyf(false, "X_IMPORT_PROGRESS=%u", percent);
        log_info("Imported %u%%.", percent);

        i->last_percent = percent;
}

static int raw_import_maybe_convert_qcow2(RawImport *i) {
        _cleanup_close_ int converted_fd = -1;
        _cleanup_free_ char *t = NULL;
        int r;

        assert(i);

        r = qcow2_detect(i->output_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to detect whether this is a QCOW2 image: %m");
        if (r == 0)
                return 0;

        /* This is a QCOW2 image, let's convert it */
        r = tempfn_random(i->final_path, NULL, &t);
        if (r < 0)
                return log_oom();

        converted_fd = open(t, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
        if (converted_fd < 0)
                return log_error_errno(errno, "Failed to create %s: %m", t);

        r = chattr_fd(converted_fd, FS_NOCOW_FL, FS_NOCOW_FL);
        if (r < 0)
                log_warning_errno(errno, "Failed to set file attributes on %s: %m", t);

        log_info("Unpacking QCOW2 file.");

        r = qcow2_convert(i->output_fd, converted_fd);
        if (r < 0) {
                unlink(t);
                return log_error_errno(r, "Failed to convert qcow2 image: %m");
        }

        (void) unlink(i->temp_path);
        free(i->temp_path);
        i->temp_path = t;
        t = NULL;

        safe_close(i->output_fd);
        i->output_fd = converted_fd;
        converted_fd = -1;

        return 1;
}

static int raw_import_finish(RawImport *i) {
        int r;

        assert(i);
        assert(i->output_fd >= 0);
        assert(i->temp_path);
        assert(i->final_path);

        /* In case this was a sparse file, make sure the file system is right */
        if (i->written_uncompressed > 0) {
                if (ftruncate(i->output_fd, i->written_uncompressed) < 0)
                        return log_error_errno(errno, "Failed to truncate file: %m");
        }

        r = raw_import_maybe_convert_qcow2(i);
        if (r < 0)
                return r;

        if (S_ISREG(i->st.st_mode)) {
                (void) copy_times(i->input_fd, i->output_fd);
                (void) copy_xattr(i->input_fd, i->output_fd);
        }

        if (i->read_only) {
                r = import_make_read_only_fd(i->output_fd);
                if (r < 0)
                        return r;
        }

        if (i->force_local)
                (void) rm_rf(i->final_path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);

        r = rename_noreplace(AT_FDCWD, i->temp_path, AT_FDCWD, i->final_path);
        if (r < 0)
                return log_error_errno(r, "Failed to move image into place: %m");

        i->temp_path = mfree(i->temp_path);

        return 0;
}

static int raw_import_open_disk(RawImport *i) {
        int r;

        assert(i);

        assert(!i->final_path);
        assert(!i->temp_path);
        assert(i->output_fd < 0);

        i->final_path = strjoin(i->image_root, "/", i->local, ".raw", NULL);
        if (!i->final_path)
                return log_oom();

        r = tempfn_random(i->final_path, NULL, &i->temp_path);
        if (r < 0)
                return log_oom();

        (void) mkdir_parents_label(i->temp_path, 0700);

        i->output_fd = open(i->temp_path, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
        if (i->output_fd < 0)
                return log_error_errno(errno, "Failed to open destination %s: %m", i->temp_path);

        r = chattr_fd(i->output_fd, FS_NOCOW_FL, FS_NOCOW_FL);
        if (r < 0)
                log_warning_errno(errno, "Failed to set file attributes on %s: %m", i->temp_path);

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

        if (!S_ISREG(i->st.st_mode))
                return 0;

        p = lseek(i->input_fd, 0, SEEK_CUR);
        if (p == (off_t) -1)
                return log_error_errno(errno, "Failed to read file offset of input file: %m");

        /* Let's only try a btrfs reflink, if we are reading from the beginning of the file */
        if ((uint64_t) p != (uint64_t) i->buffer_size)
                return 0;

        r = btrfs_reflink(i->input_fd, i->output_fd);
        if (r >= 0)
                return 1;

        return 0;
}

static int raw_import_write(const void *p, size_t sz, void *userdata) {
        RawImport *i = userdata;
        ssize_t n;

        if (i->grow_machine_directory && i->written_since_last_grow >= GROW_INTERVAL_BYTES) {
                i->written_since_last_grow = 0;
                grow_machine_directory();
        }

        n = sparse_write(i->output_fd, p, sz, 64);
        if (n < 0)
                return -errno;
        if ((size_t) n < sz)
                return -EIO;

        i->written_uncompressed += sz;
        i->written_since_last_grow += sz;

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
        if (l == 0) {
                if (i->compress.type == IMPORT_COMPRESS_UNKNOWN) {
                        log_error("Premature end of file: %m");
                        r = -EIO;
                        goto finish;
                }

                r = raw_import_finish(i);
                goto finish;
        }

        i->buffer_size += l;

        if (i->compress.type == IMPORT_COMPRESS_UNKNOWN) {
                r = import_uncompress_detect(&i->compress, i->buffer, i->buffer_size);
                if (r < 0) {
                        log_error("Failed to detect file compression: %m");
                        goto finish;
                }
                if (r == 0) /* Need more data */
                        return 0;

                r = raw_import_open_disk(i);
                if (r < 0)
                        goto finish;

                r = raw_import_try_reflink(i);
                if (r < 0)
                        goto finish;
                if (r > 0) {
                        r = raw_import_finish(i);
                        goto finish;
                }
        }

        r = import_uncompress(&i->compress, i->buffer, i->buffer_size, raw_import_write, i);
        if (r < 0) {
                log_error_errno(r, "Failed to decode and write: %m");
                goto finish;
        }

        i->written_compressed += i->buffer_size;
        i->buffer_size = 0;

        raw_import_report_progress(i);

        return 0;

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

int raw_import_start(RawImport *i, int fd, const char *local, bool force_local, bool read_only) {
        int r;

        assert(i);
        assert(fd >= 0);
        assert(local);

        if (!machine_name_is_valid(local))
                return -EINVAL;

        if (i->input_fd >= 0)
                return -EBUSY;

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        r = free_and_strdup(&i->local, local);
        if (r < 0)
                return r;
        i->force_local = force_local;
        i->read_only = read_only;

        if (fstat(fd, &i->st) < 0)
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
        return r;
}
