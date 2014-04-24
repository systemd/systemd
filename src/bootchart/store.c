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
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>

#include "util.h"
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
DIR *proc;
int procfd = -1;

double gettime_ns(void) {
        struct timespec n;

        clock_gettime(CLOCK_MONOTONIC, &n);

        return (n.tv_sec + (n.tv_nsec / 1000000000.0));
}

void log_uptime(void) {
        _cleanup_fclose_ FILE *f = NULL;
        char str[32];
        double uptime;

        f = fopen("/proc/uptime", "re");

        if (!f)
                return;
        if (!fscanf(f, "%s %*s", str))
                return;

        uptime = strtod(str, NULL);

        log_start = gettime_ns();

        /* start graph at kernel boot time */
        if (arg_relative)
                graph_start = log_start;
        else
                graph_start = log_start - uptime;
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

static int pid_cmdline_strscpy(char *buffer, size_t buf_len, int pid) {
        char filename[PATH_MAX];
        _cleanup_close_ int fd=-1;
        ssize_t n;

        sprintf(filename, "%d/cmdline", pid);
        fd = openat(procfd, filename, O_RDONLY);
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

void log_sample(int sample, struct list_sample_data **ptr) {
        static int vmstat;
        static int schedstat;
        char buf[4096];
        char key[256];
        char val[256];
        char rt[256];
        char wt[256];
        char *m;
        int c;
        int p;
        int mod;
        static int e_fd;
        ssize_t s;
        ssize_t n;
        struct dirent *ent;
        int fd;
        struct list_sample_data *sampledata;
        struct ps_sched_struct *ps_prev = NULL;

        sampledata = *ptr;

        /* all the per-process stuff goes here */
        if (!proc) {
                /* find all processes */
                proc = opendir("/proc");
                if (!proc)
                        return;
                procfd = dirfd(proc);
        } else {
                rewinddir(proc);
        }

        if (!vmstat) {
                /* block stuff */
                vmstat = openat(procfd, "vmstat", O_RDONLY);
                if (vmstat == -1) {
                        log_error("Failed to open /proc/vmstat: %m");
                        exit(EXIT_FAILURE);
                }
        }

        n = pread(vmstat, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
                close(vmstat);
                return;
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

        if (!schedstat) {
                /* overall CPU utilization */
                schedstat = openat(procfd, "schedstat", O_RDONLY);
                if (schedstat == -1) {
                        log_error("Failed to open /proc/schedstat: %m");
                        exit(EXIT_FAILURE);
                }
        }

        n = pread(schedstat, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
                close(schedstat);
                return;
        }
        buf[n] = '\0';

        m = buf;
        while (m) {
                if (sscanf(m, "%s %*s %*s %*s %*s %*s %*s %s %s", key, rt, wt) < 3)
                        goto schedstat_next;

                if (strstr(key, "cpu")) {
                        c = atoi((const char*)(key+3));
                        if (c > MAXCPUS)
                                /* Oops, we only have room for MAXCPUS data */
                                break;
                        sampledata->runtime[c] = atoll(rt);
                        sampledata->waittime[c] = atoll(wt);

                        if (c == cpus)
                                cpus = c + 1;
                }
schedstat_next:
                m = bufgetline(m);
                if (!m)
                        break;
        }

        if (arg_entropy) {
                if (!e_fd) {
                        e_fd = openat(procfd, "sys/kernel/random/entropy_avail", O_RDONLY);
                }

                if (e_fd) {
                        n = pread(e_fd, buf, sizeof(buf) - 1, 0);
                        if (n > 0) {
                                buf[n] = '\0';
                                sampledata->entropy_avail = atoi(buf);
                        }
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

                        ps->next_ps = new0(struct ps_struct, 1);
                        if (!ps->next_ps) {
                                log_oom();
                                exit (EXIT_FAILURE);
                        }
                        ps = ps->next_ps;
                        ps->pid = pid;

                        ps->sample = new0(struct ps_sched_struct, 1);
                        if (!ps->sample) {
                                log_oom();
                                exit (EXIT_FAILURE);
                        }
                        ps->sample->sampledata = sampledata;

                        pscount++;

                        /* mark our first sample */
                        ps->first = ps->last = ps->sample;
                        ps->sample->runtime = atoll(rt);
                        ps->sample->waittime = atoll(wt);

                        /* get name, start time */
                        if (!ps->sched) {
                                sprintf(filename, "%d/sched", pid);
                                ps->sched = openat(procfd, filename, O_RDONLY);
                                if (ps->sched == -1)
                                        continue;
                        }

                        s = pread(ps->sched, buf, sizeof(buf) - 1, 0);
                        if (s <= 0) {
                                close(ps->sched);
                                continue;
                        }
                        buf[s] = '\0';

                        if (!sscanf(buf, "%s %*s %*s", key))
                                continue;

                        strscpy(ps->name, sizeof(ps->name), key);

                        /* cmdline */
                        if (arg_show_cmdline)
                                pid_cmdline_strscpy(ps->name, sizeof(ps->name), pid);

                        /* discard line 2 */
                        m = bufgetline(buf);
                        if (!m)
                                continue;

                        m = bufgetline(m);
                        if (!m)
                                continue;

                        if (!sscanf(m, "%*s %*s %s", t))
                                continue;

                        ps->starttime = strtod(t, NULL) / 1000.0;

                        if (arg_show_cgroup)
                                /* if this fails, that's OK */
                                cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER,
                                                ps->pid, &ps->cgroup);

                        /* ppid */
                        sprintf(filename, "%d/stat", pid);
                        fd = openat(procfd, filename, O_RDONLY);
                        st = fdopen(fd, "r");
                        if (!st)
                                continue;
                        if (!fscanf(st, "%*s %*s %*s %i", &p)) {
                                continue;
                        }
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
                if (!ps->schedstat) {
                        sprintf(filename, "%d/schedstat", pid);
                        ps->schedstat = openat(procfd, filename, O_RDONLY);
                        if (ps->schedstat == -1)
                                continue;
                }
                s = pread(ps->schedstat, buf, sizeof(buf) - 1, 0);
                if (s <= 0) {
                        /* clean up our file descriptors - assume that the process exited */
                        close(ps->schedstat);
                        if (ps->sched)
                                close(ps->sched);
                        //if (ps->smaps)
                        //        fclose(ps->smaps);
                        continue;
                }
                buf[s] = '\0';

                if (!sscanf(buf, "%s %s %*s", rt, wt))
                        continue;

                ps->sample->next = new0(struct ps_sched_struct, 1);
                if (!ps->sample) {
                        log_oom();
                        exit(EXIT_FAILURE);
                }
                ps->sample->next->prev = ps->sample;
                ps->sample = ps->sample->next;
                ps->last = ps->sample;
                ps->sample->runtime = atoll(rt);
                ps->sample->waittime = atoll(wt);
                ps->sample->sampledata = sampledata;
                ps->sample->ps_new = ps;
                if (ps_prev) {
                        ps_prev->cross = ps->sample;
                }
                ps_prev = ps->sample;
                ps->total = (ps->last->runtime - ps->first->runtime)
                            / 1000000000.0;

                if (!arg_pss)
                        goto catch_rename;

                /* Pss */
                if (!ps->smaps) {
                        sprintf(filename, "%d/smaps", pid);
                        fd = openat(procfd, filename, O_RDONLY);
                        ps->smaps = fdopen(fd, "r");
                        if (!ps->smaps)
                                continue;
                        setvbuf(ps->smaps, smaps_buf, _IOFBF, sizeof(smaps_buf));
                }
                else {
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
                if (((samples - ps->pid) + pid) % (int)(mod) == 0) {

                        /* re-fetch name */
                        /* get name, start time */
                        if (!ps->sched) {
                                sprintf(filename, "%d/sched", pid);
                                ps->sched = openat(procfd, filename, O_RDONLY);
                                if (ps->sched == -1)
                                        continue;
                        }
                        s = pread(ps->sched, buf, sizeof(buf) - 1, 0);
                        if (s <= 0) {
                                /* clean up file descriptors */
                                close(ps->sched);
                                if (ps->schedstat)
                                        close(ps->schedstat);
                                //if (ps->smaps)
                                //        fclose(ps->smaps);
                                continue;
                        }
                        buf[s] = '\0';

                        if (!sscanf(buf, "%s %*s %*s", key))
                                continue;

                        strscpy(ps->name, sizeof(ps->name), key);

                        /* cmdline */
                        if (arg_show_cmdline)
                                pid_cmdline_strscpy(ps->name, sizeof(ps->name), pid);
                }
        }
}
