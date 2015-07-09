/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Codethink Limited

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

#include <stdint.h>
#include "untar-job.h"
#include "util.h"
#include "process-util.h"
#include "import-common.h"

int untar_job_new(
                UnTarJob **ret,
                sd_event *event,
                UnTarJobRead on_read,
                UnTarJobProgress on_progress,
                UnTarJobFinished on_finished,
                void *userdata) {
        _cleanup_(untar_job_unrefp) UnTarJob *j = NULL;
        int r;

        assert(ret);

        j = new0(UnTarJob, 1);
        if (!j)
                return -ENOMEM;

        j->input_fd = j->tar_fd = -1;
        j->on_read = on_read;
        j->on_progress = on_progress;
        j->on_finished = on_finished;
        j->userdata = userdata;

        j->last_percent = (unsigned) -1;
        RATELIMIT_INIT(j->progress_rate_limit, 100 * USEC_PER_MSEC, 1);

        if (event)
                j->event = sd_event_ref(event);
        else {
                r = sd_event_default(&j->event);
                if (r < 0)
                        return r;
        }

        *ret = j;
        j = NULL;
        return 0;
}

UnTarJob *untar_job_unref(UnTarJob *j) {
        if (!j)
                return NULL;

        sd_event_source_unref(j->input_event_source);

        if (j->tar_pid > 1) {
                (void) kill_and_sigcont(j->tar_pid, SIGKILL);
                (void) wait_for_terminate(j->tar_pid, NULL);
        }

        sd_event_unref(j->event);

        safe_close(j->tar_fd);

        free(j->path);
        free(j);

        return NULL;
}

static void untar_job_finish(UnTarJob *j, int r) {
        assert(j);

        if (r < 0)
                goto finish;

        j->tar_fd = safe_close(j->tar_fd);

        if (j->tar_pid > 0) {
                r = wait_for_terminate_and_warn("tar", j->tar_pid, true);
                j->tar_pid = 0;
                if (r < 0)
                        goto finish;
        }

finish:
        assert_se(sd_event_source_set_enabled(j->input_event_source, SD_EVENT_OFF) == 0);

        if (j->on_finished)
                j->on_finished(j, r);
        else
                sd_event_exit(j->event, r);
}

static void untar_job_report_progress(UnTarJob *j) {
        unsigned percent;
        assert(j);

        if (!j->on_progress)
                return;

        /* We have no size information, unless the source is a regular file */
        if (!S_ISREG(j->st.st_mode))
                return;

        percent = (unsigned) ((j->input_processed * UINT64_C(100)) / (uint64_t) j->st.st_size);

        if (percent == j->last_percent)
                return;

        if (!ratelimit_test(&j->progress_rate_limit))
                return;

        j->on_progress(j, percent);

        j->last_percent = percent;
}

static int untar_job_process(UnTarJob *j) {
        ssize_t l;
        int r = 0;

        assert(j);
        assert(j->buffer_size < sizeof(j->buffer));

        l = read(j->input_fd, j->buffer + j->buffer_size, sizeof(j->buffer) - j->buffer_size);
        if (l < 0) {
                if (errno == EAGAIN)
                        return 0;

                r = log_error_errno(errno, "Failed to read input file: %m");
                goto finish;
        }
        if (l == 0)
                goto finish;

        j->buffer_size += l;

        if (j->on_read)
                r = j->on_read(j);
        else {
                r = loop_write(j->tar_fd, j->buffer, j->buffer_size, false);
                if (r < 0)
                        goto finish;
        }

        j->input_processed += j->buffer_size;
        j->buffer_size = 0;

        untar_job_report_progress(j);

        return 0;
finish:
        untar_job_finish(j, r);

        return 0;
}

static int untar_job_on_input(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        return untar_job_process(userdata);
}
static int untar_job_on_defer(sd_event_source *s, void *userdata) {
        return untar_job_process(userdata);
}

int untar_job_begin(UnTarJob *j, int input_fd, const char *path) {
        int r;

        assert(j);
        assert(input_fd >= 0);
        assert(path);

        if (j->input_fd >= 0)
                return -EBUSY;

        r = fd_nonblock(input_fd, true);
        if (r < 0)
                return r;

        r = free_and_strdup(&j->path, path);
        if (r < 0)
                return r;

        if (fstat(input_fd, &j->st) < 0)
                return -errno;

        r = sd_event_add_io(j->event, &j->input_event_source, input_fd, EPOLLIN, untar_job_on_input, j);
        if (r == -EPERM) {
                /* This fd does not support epoll, for example because it is a regular file. Busy read in that case */
                r = sd_event_add_defer(j->event, &j->input_event_source, untar_job_on_defer, j);
                if (r < 0)
                        return r;

                r = sd_event_source_set_enabled(j->input_event_source, SD_EVENT_ON);
        }
        if (r < 0)
                return r;

        j->tar_fd = import_fork_tar_x(j->path, &j->tar_pid);
        if (j->tar_fd < 0)
                return j->tar_fd;

        j->input_fd = input_fd;
        return r;
}
