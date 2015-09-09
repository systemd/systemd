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

/***

  Many thanks to those who contributed ideas and code:
  - Ziga Mahkovec - Original bootchart author
  - Anders Norgaard - PyBootchartgui
  - Michael Meeks - bootchart2
  - Scott James Remnant - Ubuntu C-based logger
  - Arjan van der Ven - for the idea to merge bootgraph.pl functionality

 ***/

#include <sys/resource.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include "systemd/sd-journal.h"

#include "util.h"
#include "fileio.h"
#include "macro.h"
#include "conf-parser.h"
#include "strxcpyx.h"
#include "path-util.h"
#include "store.h"
#include "svg.h"
#include "bootchart.h"
#include "list.h"

static int exiting = 0;

#define DEFAULT_SAMPLES_LEN 500
#define DEFAULT_HZ 25.0
#define DEFAULT_SCALE_X 100.0 /* 100px = 1sec */
#define DEFAULT_SCALE_Y 20.0  /* 16px = 1 process bar */
#define DEFAULT_INIT ROOTLIBEXECDIR "/systemd"
#define DEFAULT_OUTPUT "/run/log"

/* graph defaults */
bool arg_entropy = false;
bool arg_initcall = true;
bool arg_relative = false;
bool arg_filter = true;
bool arg_show_cmdline = false;
bool arg_show_cgroup = false;
bool arg_pss = false;
bool arg_percpu = false;
int arg_samples_len = DEFAULT_SAMPLES_LEN; /* we record len+1 (1 start sample) */
double arg_hz = DEFAULT_HZ;
double arg_scale_x = DEFAULT_SCALE_X;
double arg_scale_y = DEFAULT_SCALE_Y;

char arg_init_path[PATH_MAX] = DEFAULT_INIT;
char arg_output_path[PATH_MAX] = DEFAULT_OUTPUT;

static void signal_handler(int sig) {
        exiting = 1;
}

#define BOOTCHART_CONF "/etc/systemd/bootchart.conf"

#define BOOTCHART_MAX (16*1024*1024)

static void parse_conf(void) {
        char *init = NULL, *output = NULL;
        const ConfigTableItem items[] = {
                { "Bootchart", "Samples",          config_parse_int,    0, &arg_samples_len },
                { "Bootchart", "Frequency",        config_parse_double, 0, &arg_hz          },
                { "Bootchart", "Relative",         config_parse_bool,   0, &arg_relative    },
                { "Bootchart", "Filter",           config_parse_bool,   0, &arg_filter      },
                { "Bootchart", "Output",           config_parse_path,   0, &output          },
                { "Bootchart", "Init",             config_parse_path,   0, &init            },
                { "Bootchart", "PlotMemoryUsage",  config_parse_bool,   0, &arg_pss         },
                { "Bootchart", "PlotEntropyGraph", config_parse_bool,   0, &arg_entropy     },
                { "Bootchart", "ScaleX",           config_parse_double, 0, &arg_scale_x     },
                { "Bootchart", "ScaleY",           config_parse_double, 0, &arg_scale_y     },
                { "Bootchart", "ControlGroup",     config_parse_bool,   0, &arg_show_cgroup },
                { "Bootchart", "PerCPU",           config_parse_bool,   0, &arg_percpu      },
                { NULL, NULL, NULL, 0, NULL }
        };

        config_parse_many(BOOTCHART_CONF,
                          CONF_DIRS_NULSTR("systemd/bootchart.conf"),
                          NULL, config_item_table_lookup, items, true, NULL);

        if (init != NULL)
                strscpy(arg_init_path, sizeof(arg_init_path), init);
        if (output != NULL)
                strscpy(arg_output_path, sizeof(arg_output_path), output);
}

static void help(void) {
        printf("Usage: %s [OPTIONS]\n\n"
               "Options:\n"
               "  -r --rel             Record time relative to recording\n"
               "  -f --freq=FREQ       Sample frequency [%g]\n"
               "  -n --samples=N       Stop sampling at [%d] samples\n"
               "  -x --scale-x=N       Scale the graph horizontally [%g] \n"
               "  -y --scale-y=N       Scale the graph vertically [%g] \n"
               "  -p --pss             Enable PSS graph (CPU intensive)\n"
               "  -e --entropy         Enable the entropy_avail graph\n"
               "  -o --output=PATH     Path to output files [%s]\n"
               "  -i --init=PATH       Path to init executable [%s]\n"
               "  -F --no-filter       Disable filtering of unimportant or ephemeral processes\n"
               "  -C --cmdline         Display full command lines with arguments\n"
               "  -c --control-group   Display process control group\n"
               "     --per-cpu         Draw each CPU utilization and wait bar also\n"
               "  -h --help            Display this message\n\n"
               "See bootchart.conf for more information.\n",
               program_invocation_short_name,
               DEFAULT_HZ,
               DEFAULT_SAMPLES_LEN,
               DEFAULT_SCALE_X,
               DEFAULT_SCALE_Y,
               DEFAULT_OUTPUT,
               DEFAULT_INIT);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_PERCPU = 0x100,
        };

        static const struct option options[] = {
                {"rel",           no_argument,        NULL,  'r'       },
                {"freq",          required_argument,  NULL,  'f'       },
                {"samples",       required_argument,  NULL,  'n'       },
                {"pss",           no_argument,        NULL,  'p'       },
                {"output",        required_argument,  NULL,  'o'       },
                {"init",          required_argument,  NULL,  'i'       },
                {"no-filter",     no_argument,        NULL,  'F'       },
                {"cmdline",       no_argument,        NULL,  'C'       },
                {"control-group", no_argument,        NULL,  'c'       },
                {"help",          no_argument,        NULL,  'h'       },
                {"scale-x",       required_argument,  NULL,  'x'       },
                {"scale-y",       required_argument,  NULL,  'y'       },
                {"entropy",       no_argument,        NULL,  'e'       },
                {"per-cpu",       no_argument,        NULL,  ARG_PERCPU},
                {}
        };
        int c, r;

        if (getpid() == 1)
                opterr = 0;

        while ((c = getopt_long(argc, argv, "erpf:n:o:i:FCchx:y:", options, NULL)) >= 0)
                switch (c) {

                case 'r':
                        arg_relative = true;
                        break;
                case 'f':
                        r = safe_atod(optarg, &arg_hz);
                        if (r < 0)
                                log_warning_errno(r, "failed to parse --freq/-f argument '%s': %m",
                                                  optarg);
                        break;
                case 'F':
                        arg_filter = false;
                        break;
                case 'C':
                        arg_show_cmdline = true;
                        break;
                case 'c':
                        arg_show_cgroup = true;
                        break;
                case 'n':
                        r = safe_atoi(optarg, &arg_samples_len);
                        if (r < 0)
                                log_warning_errno(r, "failed to parse --samples/-n argument '%s': %m",
                                                  optarg);
                        break;
                case 'o':
                        path_kill_slashes(optarg);
                        strscpy(arg_output_path, sizeof(arg_output_path), optarg);
                        break;
                case 'i':
                        path_kill_slashes(optarg);
                        strscpy(arg_init_path, sizeof(arg_init_path), optarg);
                        break;
                case 'p':
                        arg_pss = true;
                        break;
                case 'x':
                        r = safe_atod(optarg, &arg_scale_x);
                        if (r < 0)
                                log_warning_errno(r, "failed to parse --scale-x/-x argument '%s': %m",
                                                  optarg);
                        break;
                case 'y':
                        r = safe_atod(optarg, &arg_scale_y);
                        if (r < 0)
                                log_warning_errno(r, "failed to parse --scale-y/-y argument '%s': %m",
                                                  optarg);
                        break;
                case 'e':
                        arg_entropy = true;
                        break;
                case ARG_PERCPU:
                        arg_percpu = true;
                        break;
                case 'h':
                        help();
                        return 0;
                case '?':
                        if (getpid() != 1)
                                return -EINVAL;
                        else
                                return 0;
                default:
                        assert_not_reached("Unhandled option code.");
                }

        if (arg_hz <= 0) {
                log_error("Frequency needs to be > 0");
                return -EINVAL;
        }

        return 1;
}

static int do_journal_append(char *file) {
        _cleanup_free_ char *bootchart_message = NULL;
        _cleanup_free_ char *bootchart_file = NULL;
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -1;
        struct iovec iovec[5];
        int r, j = 0;
        ssize_t n;

        bootchart_file = strappend("BOOTCHART_FILE=", file);
        if (!bootchart_file)
                return log_oom();

        IOVEC_SET_STRING(iovec[j++], bootchart_file);
        IOVEC_SET_STRING(iovec[j++], "MESSAGE_ID=9f26aa562cf440c2b16c773d0479b518");
        IOVEC_SET_STRING(iovec[j++], "PRIORITY=7");
        bootchart_message = strjoin("MESSAGE=Bootchart created: ", file, NULL);
        if (!bootchart_message)
                return log_oom();

        IOVEC_SET_STRING(iovec[j++], bootchart_message);

        p = malloc(10 + BOOTCHART_MAX);
        if (!p)
                return log_oom();

        memcpy(p, "BOOTCHART=", 10);

        fd = open(file, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open bootchart data \"%s\": %m", file);

        n = loop_read(fd, p + 10, BOOTCHART_MAX, false);
        if (n < 0)
                return log_error_errno(n, "Failed to read bootchart data: %m");

        iovec[j].iov_base = p;
        iovec[j].iov_len = 10 + n;
        j++;

        r = sd_journal_sendv(iovec, j);
        if (r < 0)
                log_error_errno(r, "Failed to send bootchart: %m");

        return 0;
}

int main(int argc, char *argv[]) {
        static struct list_sample_data *sampledata;
        _cleanup_closedir_ DIR *proc = NULL;
        _cleanup_free_ char *build = NULL;
        _cleanup_fclose_ FILE *of = NULL;
        _cleanup_close_ int sysfd = -1;
        struct ps_struct *ps_first;
        double graph_start;
        double log_start;
        double interval;
        char output_file[PATH_MAX];
        char datestr[200];
        int pscount = 0;
        int n_cpus = 0;
        int overrun = 0;
        time_t t = 0;
        int r, samples;
        struct ps_struct *ps;
        struct rlimit rlim;
        struct list_sample_data *head;
        struct sigaction sig = {
                .sa_handler = signal_handler,
        };

        parse_conf();

        r = parse_argv(argc, argv);
        if (r < 0)
                return EXIT_FAILURE;

        if (r == 0)
                return EXIT_SUCCESS;

        /*
         * If the kernel executed us through init=/usr/lib/systemd/systemd-bootchart, then
         * fork:
         * - parent execs executable specified via init_path[] (/usr/lib/systemd/systemd by default) as pid=1
         * - child logs data
         */
        if (getpid() == 1) {
                if (fork())
                        /* parent */
                        execl(arg_init_path, arg_init_path, NULL);
        }
        argv[0][0] = '@';

        rlim.rlim_cur = 4096;
        rlim.rlim_max = 4096;
        (void) setrlimit(RLIMIT_NOFILE, &rlim);

        /* start with empty ps LL */
        ps_first = new0(struct ps_struct, 1);
        if (!ps_first) {
                log_oom();
                return EXIT_FAILURE;
        }

        /* handle TERM/INT nicely */
        sigaction(SIGHUP, &sig, NULL);

        interval = (1.0 / arg_hz) * 1000000000.0;

        if (arg_relative)
                graph_start = log_start = gettime_ns();
        else {
                struct timespec n;
                double uptime;

                clock_gettime(clock_boottime_or_monotonic(), &n);
                uptime = (n.tv_sec + (n.tv_nsec / (double) NSEC_PER_SEC));

                log_start = gettime_ns();
                graph_start = log_start - uptime;
        }

        if (graph_start < 0.0) {
                log_error("Failed to setup graph start time.\n\n"
                          "The system uptime probably includes time that the system was suspended. "
                          "Use --rel to bypass this issue.");
                return EXIT_FAILURE;
        }

        LIST_HEAD_INIT(head);

        /* main program loop */
        for (samples = 0; !exiting && samples < arg_samples_len; samples++) {
                int res;
                double sample_stop;
                double elapsed;
                double timeleft;

                sampledata = new0(struct list_sample_data, 1);
                if (sampledata == NULL) {
                        log_oom();
                        return EXIT_FAILURE;
                }

                sampledata->sampletime = gettime_ns();
                sampledata->counter = samples;

                if (sysfd < 0)
                        sysfd = open("/sys", O_RDONLY|O_CLOEXEC);

                if (!build) {
                        if (parse_env_file("/etc/os-release", NEWLINE, "PRETTY_NAME", &build, NULL) == -ENOENT)
                                parse_env_file("/usr/lib/os-release", NEWLINE, "PRETTY_NAME", &build, NULL);
                }

                if (proc)
                        rewinddir(proc);
                else
                        proc = opendir("/proc");

                /* wait for /proc to become available, discarding samples */
                if (proc) {
                        r = log_sample(proc, samples, ps_first, &sampledata, &pscount, &n_cpus);
                        if (r < 0)
                                return EXIT_FAILURE;
                }

                sample_stop = gettime_ns();

                elapsed = (sample_stop - sampledata->sampletime) * 1000000000.0;
                timeleft = interval - elapsed;

                /*
                 * check if we have not consumed our entire timeslice. If we
                 * do, don't sleep and take a new sample right away.
                 * we'll lose all the missed samples and overrun our total
                 * time
                 */
                if (timeleft > 0) {
                        struct timespec req;

                        req.tv_sec = (time_t)(timeleft / 1000000000.0);
                        req.tv_nsec = (long)(timeleft - (req.tv_sec * 1000000000.0));

                        res = nanosleep(&req, NULL);
                        if (res) {
                                if (errno == EINTR)
                                        /* caught signal, probably HUP! */
                                        break;
                                log_error_errno(errno, "nanosleep() failed: %m");
                                return EXIT_FAILURE;
                        }
                } else {
                        overrun++;
                        /* calculate how many samples we lost and scrap them */
                        arg_samples_len -= (int)(-timeleft / interval);
                }
                LIST_PREPEND(link, head, sampledata);
        }

        /* do some cleanup, close fd's */
        ps = ps_first;
        while (ps->next_ps) {
                ps = ps->next_ps;
                ps->schedstat = safe_close(ps->schedstat);
                ps->sched = safe_close(ps->sched);
                ps->smaps = safe_fclose(ps->smaps);
        }

        if (!of) {
                t = time(NULL);
                r = strftime(datestr, sizeof(datestr), "%Y%m%d-%H%M", localtime(&t));
                assert_se(r > 0);

                snprintf(output_file, PATH_MAX, "%s/bootchart-%s.svg", arg_output_path, datestr);
                of = fopen(output_file, "we");
        }

        if (!of) {
                log_error("Error opening output file '%s': %m\n", output_file);
                return EXIT_FAILURE;
        }

        r = svg_do(of, strna(build), head, ps_first,
                   samples, pscount, n_cpus, graph_start,
                   log_start, interval, overrun);

        if (r < 0) {
                log_error_errno(r, "Error generating svg file: %m");
                return EXIT_FAILURE;
        }

        log_info("systemd-bootchart wrote %s\n", output_file);

        r = do_journal_append(output_file);
        if (r < 0)
                return EXIT_FAILURE;

        /* nitpic cleanups */
        ps = ps_first->next_ps;
        while (ps->next_ps) {
                struct ps_struct *old;

                old = ps;
                old->sample = ps->first;
                ps = ps->next_ps;
                while (old->sample->next) {
                        struct ps_sched_struct *oldsample = old->sample;

                        old->sample = old->sample->next;
                        free(oldsample);
                }
                free(old->cgroup);
                free(old->sample);
                free(old);
        }

        free(ps->cgroup);
        free(ps->sample);
        free(ps);

        sampledata = head;
        while (sampledata->link_prev) {
                struct list_sample_data *old_sampledata = sampledata;
                sampledata = sampledata->link_prev;
                free(old_sampledata);
        }
        free(sampledata);

        /* don't complain when overrun once, happens most commonly on 1st sample */
        if (overrun > 1)
                log_warning("systemd-bootchart: sample time overrun %i times\n", overrun);

        return 0;
}
