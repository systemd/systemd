/***
  bootchart.h - This file is part of systemd-bootchart

  Copyright (C) 2009-2013 Intel Coproration

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

#include <dirent.h>

#define MAXCPUS        16
#define MAXPIDS     65535
#define MAXSAMPLES   8192


struct block_stat_struct {
        /* /proc/vmstat pgpgin & pgpgout */
        int bi;
        int bo;
};

struct cpu_stat_sample_struct {
        /* /proc/schedstat fields 10 & 11 (after name) */
        double runtime;
        double waittime;
};

struct cpu_stat_struct {
        /* per cpu array */
        struct cpu_stat_sample_struct sample[MAXSAMPLES];
};

/* per process, per sample data we will log */
struct ps_sched_struct {
        /* /proc/<n>/schedstat fields 1 & 2 */
        double runtime;
        double waittime;
        int pss;
};

/* process info */
struct ps_struct {
        struct ps_struct *next_ps;    /* SLL pointer */
        struct ps_struct *parent;     /* ppid ref */
        struct ps_struct *children;   /* children */
        struct ps_struct *next;       /* siblings */

        /* must match - otherwise it's a new process with same PID */
        char name[16];
        int pid;
        int ppid;

        /* cache fd's */
        int sched;
        int schedstat;
        FILE *smaps;

        /* index to first/last seen timestamps */
        int first;
        int last;

        /* records actual start time, may be way before bootchart runs */
        double starttime;

        /* record human readable total cpu time */
        double total;

        /* largest PSS size found */
        int pss_max;

        /* for drawing connection lines later */
        double pos_x;
        double pos_y;

        struct ps_sched_struct *sample;
};

extern int entropy_avail[];

extern double graph_start;
extern double log_start;
extern double sampletime[];
extern struct ps_struct *ps_first;
extern struct block_stat_struct blockstat[];
extern struct cpu_stat_struct cpustat[];
extern int pscount;
extern int relative;
extern int filter;
extern int pss;
extern int entropy;
extern int initcall;
extern int samples;
extern int cpus;
extern int len;
extern double hz;
extern double scale_x;
extern double scale_y;
extern int overrun;
extern double interval;

extern char output_path[PATH_MAX];
extern char init_path[PATH_MAX];

extern FILE *of;
extern DIR *proc;

extern double gettime_ns(void);
extern void log_uptime(void);
extern void log_sample(int sample);

extern void svg_do(void);
