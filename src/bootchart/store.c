/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2009-2013 Intel Corporation

  Authors:
    Auke Kok <auke-jan.h.kok@intel.com>

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

#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>

#include "util.h"
#include "time-util.h"
#include "strxcpyx.h"
#include "store.h"
#include "bootchart.h"
#include "cgroup-util.h"

/*
 * Alloc a static 4k buffer for stdio - primarily used to increase
 * PSS buffering from the default 1k stdin buffer to reduce
 * read() overhead.
 */
static char smaps_buf[4096];
static int skip = 0;

double gettime_ns(void) {
        struct timespec n;

        clock_gettime(CLOCK_MONOTONIC, &n);

        return (n.tv_sec + (n.tv_nsec / (double) NSEC_PER_SEC));
}

static char *bufgetline(char *buf) {
        char *c;

        if (!buf)
                return NULL;

        c = strchr(buf, '\n');
        if (c)
                c++;

        return c;
}

static int pid_cmdline_strscpy(int procfd, char *buffer, size_t buf_len, int pid) {
        char filename[PATH_MAX];
        _cleanup_close_ int fd = -1;
        ssize_t n;

        sprintf(filename, "%d/cmdline", pid);
        fd = openat(procfd, filename, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        n = read(fd, buffer, buf_len-1);
        if (n > 0) {
                int i;
                for (i = 0; i < n; i++)
                        if (buffer[i] == '\0')
                                buffer[i] = ' ';
                buffer[n] = '\0';
        }

        return 0;
}

int log_sample(DIR *proc,
               int sample,
               struct ps_struct *ps_first,
               struct list_sample_data **ptr,
               int *pscount,
               int *cpus) {

        static int vmstat = -1;
        static int schedstat = -1;
        char buf[4096];
        char key[256];
        char val[256];
        char rt[256];
        char wt[256];
        char *m;
        int c;
        int p;
        int mod;
        static int e_fd = -1;
        ssize_t s;
        ssize_t n;
        struct dirent *ent;
        int fd;
        struct list_sample_data *sampledata;
        struct ps_sched_struct *ps_prev = NULL;
        int procfd;

        sampledata = *ptr;

        procfd = dirfd(proc);
        if (procfd < 0)
                return -errno;

        if (vmstat < 0) {
                /* block stuff */
                vmstat = openat(procfd, "vmstat", O_RDONLY|O_CLOEXEC);
                if (vmstat < 0)
                        return log_error_errno(errno, "Failed to open /proc/vmstat: %m");
        }

        n = pread(vmstat, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
                vmstat = safe_close(vmstat);
                if (n < 0)
                        return -errno;
                return -ENODATA;
        }

        buf[n] = '\0';

        m = buf;
        while (m) {
                if (sscanf(m, "%s %s", key, val) < 2)
                        goto vmstat_next;
                if (streq(key, "pgpgin"))
                        sampledata->blockstat.bi = atoi(val);
                if (streq(key, "pgpgout")) {
                        sampledata->blockstat.bo = atoi(val);
                        break;
                }
vmstat_next:
                m = bufgetline(m);
                if (!m)
                        break;
        }

        if (schedstat < 0) {
                /* overall CPU utilization */
                schedstat = openat(procfd, "schedstat", O_RDONLY|O_CLOEXEC);
                if (schedstat < 0)
                        return log_error_errno(errno, "Failed to open /proc/schedstat (requires CONFIG_SCHEDSTATS=y in kernel config): %m");
        }

        n = pread(schedstat, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
                schedstat = safe_close(schedstat);
                if (n < 0)
                        return -errno;
                return -ENODATA;
        }

        buf[n] = '\0';

        m = buf;
        while (m) {
                int r;

                if (sscanf(m, "%s %*s %*s %*s %*s %*s %*s %s %s", key, rt, wt) < 3)
                        goto schedstat_next;

                if (strstr(key, "cpu")) {
                        r = safe_atoi((const char*)(key+3), &c);
                        if (r < 0 || c > MAXCPUS -1)
                                /* Oops, we only have room for MAXCPUS data */
                                break;
                        sampledata->runtime[c] = atoll(rt);
                        sampledata->waittime[c] = atoll(wt);

                        if (c == *cpus)
                                *cpus = c + 1;
                }
schedstat_next:
                m = bufgetline(m);
                if (!m)
                        break;
        }

        if (arg_entropy) {
                if (e_fd < 0) {
                        e_fd = openat(procfd, "sys/kernel/random/entropy_avail", O_RDONLY|O_CLOEXEC);
                        if (e_fd < 0)
                                return log_error_errno(errno, "Failed to open /proc/sys/kernel/random/entropy_avail: %m");
                }

                n = pread(e_fd, buf, sizeof(buf) - 1, 0);
                if (n <= 0) {
                        e_fd = safe_close(e_fd);
                } else {
                        buf[n] = '\0';
                        sampledata->entropy_avail = atoi(buf);
                }
        }

        while ((ent = readdir(proc)) != NULL) {
                char filename[PATH_MAX];
                int pid;
                struct ps_struct *ps;

                if ((ent->d_name[0] < '0') || (ent->d_name[0] > '9'))
                        continue;

                pid = atoi(ent->d_name);

                if (pid >= MAXPIDS)
                        continue;

                ps = ps_first;
                while (ps->next_ps) {
                        ps = ps->next_ps;
                        if (ps->pid == pid)
                                break;
                }

                /* end of our LL? then append a new record */
                if (ps->pid != pid) {
                        _cleanup_fclose_ FILE *st = NULL;
                        char t[32];
                        struct ps_struct *parent;
                        int r;

                        ps->next_ps = new0(struct ps_struct, 1);
                        if (!ps->next_ps)
                                return log_oom();

                        ps = ps->next_ps;
                        ps->pid = pid;
                        ps->sched = -1;
                        ps->schedstat = -1;

                        ps->sample = new0(struct ps_sched_struct, 1);
                        if (!ps->sample)
                                return log_oom();

                        ps->sample->sampledata = sampledata;

                        (*pscount)++;

                        /* mark our first sample */
                        ps->first = ps->last = ps->sample;
                        ps->sample->runtime = atoll(rt);
                        ps->sample->waittime = atoll(wt);

                        /* get name, start time */
                        if (ps->sched < 0) {
                                sprintf(filename, "%d/sched", pid);
                                ps->sched = openat(procfd, filename, O_RDONLY|O_CLOEXEC);
                                if (ps->sched < 0)
                                        continue;
                        }

                        s = pread(ps->sched, buf, sizeof(buf) - 1, 0);
                        if (s <= 0) {
                                ps->sched = safe_close(ps->sched);
                                continue;
                        }
                        buf[s] = '\0';

                        if (!sscanf(buf, "%s %*s %*s", key))
                                continue;

                        strscpy(ps->name, sizeof(ps->name), key);

                        /* cmdline */
                        if (arg_show_cmdline)
                                pid_cmdline_strscpy(procfd, ps->name, sizeof(ps->name), pid);

                        /* discard line 2 */
                        m = bufgetline(buf);
                        if (!m)
                                continue;

                        m = bufgetline(m);
                        if (!m)
                                continue;

                        if (!sscanf(m, "%*s %*s %s", t))
                                continue;

                        r = safe_atod(t, &ps->starttime);
                        if (r < 0)
                                continue;

                        ps->starttime /= 1000.0;

                        if (arg_show_cgroup)
                                /* if this fails, that's OK */
                                cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER,
                                                ps->pid, &ps->cgroup);

                        /* ppid */
                        sprintf(filename, "%d/stat", pid);
                        fd = openat(procfd, filename, O_RDONLY|O_CLOEXEC);
                        if (fd < 0)
                                continue;

                        st = fdopen(fd, "re");
                        if (!st) {
                                close(fd);
                                continue;
                        }

                        if (!fscanf(st, "%*s %*s %*s %i", &p))
                                continue;

                        ps->ppid = p;

                        /*
                         * setup child pointers
                         *
                         * these are used to paint the tree coherently later
                         * each parent has a LL of children, and a LL of siblings
                         */
                        if (pid == 1)
                                continue; /* nothing to do for init atm */

                        /* kthreadd has ppid=0, which breaks our tree ordering */
                        if (ps->ppid == 0)
                                ps->ppid = 1;

                        parent = ps_first;
                        while ((parent->next_ps && parent->pid != ps->ppid))
                                parent = parent->next_ps;

                        if (parent->pid != ps->ppid) {
                                /* orphan */
                                ps->ppid = 1;
                                parent = ps_first->next_ps;
                        }

                        ps->parent = parent;

                        if (!parent->children) {
                                /* it's the first child */
                                parent->children = ps;
                        } else {
                                /* walk all children and append */
                                struct ps_struct *children;
                                children = parent->children;
                                while (children->next)
                                        children = children->next;

                                children->next = ps;
                        }
                }

                /* else -> found pid, append data in ps */

                /* below here is all continuous logging parts - we get here on every
                 * iteration */

                /* rt, wt */
                if (ps->schedstat < 0) {
                        sprintf(filename, "%d/schedstat", pid);
                        ps->schedstat = openat(procfd, filename, O_RDONLY|O_CLOEXEC);
                        if (ps->schedstat < 0)
                                continue;
                }

                s = pread(ps->schedstat, buf, sizeof(buf) - 1, 0);
                if (s <= 0) {
                        /* clean up our file descriptors - assume that the process exited */
                        close(ps->schedstat);
                        ps->schedstat = -1;
                        ps->sched = safe_close(ps->sched);
                        continue;
                }

                buf[s] = '\0';

                if (!sscanf(buf, "%s %s %*s", rt, wt))
                        continue;

                ps->sample->next = new0(struct ps_sched_struct, 1);
                if (!ps->sample->next)
                        return log_oom();

                ps->sample->next->prev = ps->sample;
                ps->sample = ps->sample->next;
                ps->last = ps->sample;
                ps->sample->runtime = atoll(rt);
                ps->sample->waittime = atoll(wt);
                ps->sample->sampledata = sampledata;
                ps->sample->ps_new = ps;
                if (ps_prev)
                        ps_prev->cross = ps->sample;

                ps_prev = ps->sample;
                ps->total = (ps->last->runtime - ps->first->runtime)
                            / 1000000000.0;

                if (!arg_pss)
                        goto catch_rename;

                /* Pss */
                if (!ps->smaps) {
                        sprintf(filename, "%d/smaps", pid);
                        fd = openat(procfd, filename, O_RDONLY|O_CLOEXEC);
                        if (fd < 0)
                                continue;
                        ps->smaps = fdopen(fd, "re");
                        if (!ps->smaps) {
                                close(fd);
                                continue;
                        }
                        setvbuf(ps->smaps, smaps_buf, _IOFBF, sizeof(smaps_buf));
                } else {
                        rewind(ps->smaps);
                }

                /* test to see if we need to skip another field */
                if (skip == 0) {
                        if (fgets(buf, sizeof(buf), ps->smaps) == NULL) {
                                continue;
                        }
                        if (fread(buf, 1, 28 * 15, ps->smaps) != (28 * 15)) {
                                continue;
                        }
                        if (buf[392] == 'V') {
                                skip = 2;
                        }
                        else {
                                skip = 1;
                        }
                        rewind(ps->smaps);
                }

                while (1) {
                        int pss_kb;

                        /* skip one line, this contains the object mapped. */
                        if (fgets(buf, sizeof(buf), ps->smaps) == NULL) {
                                break;
                        }
                        /* then there's a 28 char 14 line block */
                        if (fread(buf, 1, 28 * 14, ps->smaps) != 28 * 14) {
                                break;
                        }
                        pss_kb = atoi(&buf[61]);
                        ps->sample->pss += pss_kb;

                        /* skip one more line if this is a newer kernel */
                        if (skip == 2) {
                               if (fgets(buf, sizeof(buf), ps->smaps) == NULL)
                                       break;
                        }
                }

                if (ps->sample->pss > ps->pss_max)
                        ps->pss_max = ps->sample->pss;

catch_rename:
                /* catch process rename, try to randomize time */
                mod = (arg_hz < 4.0) ? 4.0 : (arg_hz / 4.0);
                if (((sample - ps->pid) + pid) % (int)(mod) == 0) {

                        /* re-fetch name */
                        /* get name, start time */
                        if (ps->sched < 0) {
                                sprintf(filename, "%d/sched", pid);
                                ps->sched = openat(procfd, filename, O_RDONLY|O_CLOEXEC);
                                if (ps->sched < 0)
                                        continue;
                        }

                        s = pread(ps->sched, buf, sizeof(buf) - 1, 0);
                        if (s <= 0) {
                                /* clean up file descriptors */
                                ps->sched = safe_close(ps->sched);
                                ps->schedstat = safe_close(ps->schedstat);
                                continue;
                        }

                        buf[s] = '\0';

                        if (!sscanf(buf, "%s %*s %*s", key))
                                continue;

                        strscpy(ps->name, sizeof(ps->name), key);

                        /* cmdline */
                        if (arg_show_cmdline)
                                pid_cmdline_strscpy(procfd, ps->name, sizeof(ps->name), pid);
                }
        }

        return 0;
}
