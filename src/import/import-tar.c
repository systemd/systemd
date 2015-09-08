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
#include "import-tar.h"
#include "process-util.h"

struct TarImport {
        sd_event *event;

        char *image_root;

        TarImportFinished on_finished;
        void *userdata;

        char *local;
        bool force_local;
        bool read_only;
        bool grow_machine_directory;

        char *temp_path;
        char *final_path;

        int input_fd;
        int tar_fd;

        ImportCompress compress;

        uint64_t written_since_last_grow;

        sd_event_source *input_event_source;

        uint8_t buffer[16*1024];
        size_t buffer_size;

        uint64_t written_compressed;
        uint64_t written_uncompressed;

        struct stat st;

        pid_t tar_pid;

        unsigned last_percent;
        RateLimit progress_rate_limit;
};

TarImport* tar_import_unref(TarImport *i) {
        if (!i)
                return NULL;

        sd_event_source_unref(i->input_event_source);

        if (i->tar_pid > 1) {
                (void) kill_and_sigcont(i->tar_pid, SIGKILL);
                (void) wait_for_terminate(i->tar_pid, NULL);
        }

        if (i->temp_path) {
                (void) rm_rf(i->temp_path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
                free(i->temp_path);
        }

        import_compress_free(&i->compress);

        sd_event_unref(i->event);

        safe_close(i->tar_fd);

        free(i->final_path);
        free(i->image_root);
        free(i->local);
        free(i);

        return NULL;
}

int tar_import_new(
                TarImport **ret,
                sd_event *event,
                const char *image_root,
                TarImportFinished on_finished,
                void *userdata) {

        _cleanup_(tar_import_unrefp) TarImport *i = NULL;
        int r;

        assert(ret);

        i = new0(TarImport, 1);
        if (!i)
                return -ENOMEM;

        i->input_fd = i->tar_fd = -1;
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

        if (!ratelimit_test(&i->progress_rate_limit))
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
                r = wait_for_terminate_and_warn("tar", i->tar_pid, true);
                i->tar_pid = 0;
                if (r < 0)
                        return r;
        }

        if (i->read_only) {
                r = import_make_read_only(i->temp_path);
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

static int tar_import_fork_tar(TarImport *i) {
        int r;

        assert(i);

        assert(!i->final_path);
        assert(!i->temp_path);
        assert(i->tar_fd < 0);

        i->final_path = strjoin(i->image_root, "/", i->local, NULL);
        if (!i->final_path)
                return log_oom();

        r = tempfn_random(i->final_path, NULL, &i->temp_path);
        if (r < 0)
                return log_oom();

        (void) mkdir_parents_label(i->temp_path, 0700);

        r = btrfs_subvol_make(i->temp_path);
        if (r == -ENOTTY) {
                if (mkdir(i->temp_path, 0755) < 0)
                        return log_error_errno(errno, "Failed to create directory %s: %m", i->temp_path);
        } else if (r < 0)
                return log_error_errno(errno, "Failed to create subvolume %s: %m", i->temp_path);

        i->tar_fd = import_fork_tar_x(i->temp_path, &i->tar_pid);
        if (i->tar_fd < 0)
                return i->tar_fd;

        return 0;
}

static int tar_import_write(const void *p, size_t sz, void *userdata) {
        TarImport *i = userdata;
        int r;

        if (i->grow_machine_directory && i->written_since_last_grow >= GROW_INTERVAL_BYTES) {
                i->written_since_last_grow = 0;
                grow_machine_directory();
        }

        r = loop_write(i->tar_fd, p, sz, false);
        if (r < 0)
                return r;

        i->written_uncompressed += sz;
        i->written_since_last_grow += sz;

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
        if (l == 0) {
                if (i->compress.type == IMPORT_COMPRESS_UNKNOWN) {
                        log_error("Premature end of file: %m");
                        r = -EIO;
                        goto finish;
                }

                r = tar_import_finish(i);
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

int tar_import_start(TarImport *i, int fd, const char *local, bool force_local, bool read_only) {
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
