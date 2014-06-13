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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
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
#include <systemd/sd-journal.h>

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

double graph_start;
double log_start;
struct ps_struct *ps_first;
int pscount;
int cpus;
double interval;
FILE *of = NULL;
int overrun = 0;
static int exiting = 0;
int sysfd=-1;

#define DEFAULT_SAMPLES_LEN 500
#define DEFAULT_HZ 25.0
#define DEFAULT_SCALE_X 100.0 /* 100px = 1sec */
#define DEFAULT_SCALE_Y 20.0  /* 16px = 1 process bar */
#define DEFAULT_INIT "/sbin/init"
#define DEFAULT_OUTPUT "/run/log"

/* graph defaults */
bool arg_entropy = false;
bool initcall = true;
bool arg_relative = false;
bool arg_filter = true;
bool arg_show_cmdline = false;
bool arg_show_cgroup = false;
bool arg_pss = false;
int samples;
int arg_samples_len = DEFAULT_SAMPLES_LEN; /* we record len+1 (1 start sample) */
double arg_hz = DEFAULT_HZ;
double arg_scale_x = DEFAULT_SCALE_X;
double arg_scale_y = DEFAULT_SCALE_Y;
static struct list_sample_data *sampledata;
struct list_sample_data *head;

char arg_init_path[PATH_MAX] = DEFAULT_INIT;
char arg_output_path[PATH_MAX] = DEFAULT_OUTPUT;

static void signal_handler(int sig) {
        if (sig++)
                sig--;
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
                { NULL, NULL, NULL, 0, NULL }
        };
        _cleanup_fclose_ FILE *f;
        int r;

        f = fopen(BOOTCHART_CONF, "re");
        if (!f)
                return;

        r = config_parse(NULL, BOOTCHART_CONF, f,
                         NULL, config_item_table_lookup, (void*) items, true, false, NULL);
        if (r < 0)
                log_warning("Failed to parse configuration file: %s", strerror(-r));

        if (init != NULL)
                strscpy(arg_init_path, sizeof(arg_init_path), init);
        if (output != NULL)
                strscpy(arg_output_path, sizeof(arg_output_path), output);
}

static void help(void) {
        fprintf(stdout,
                "Usage: %s [OPTIONS]\n\n"
                "Options:\n"
                "  -r, --rel             Record time relative to recording\n"
                "  -f, --freq=FREQ       Sample frequency [%g]\n"
                "  -n, --samples=N       Stop sampling at [%d] samples\n"
                "  -x, --scale-x=N       Scale the graph horizontally [%g] \n"
                "  -y, --scale-y=N       Scale the graph vertically [%g] \n"
                "  -p, --pss             Enable PSS graph (CPU intensive)\n"
                "  -e, --entropy         Enable the entropy_avail graph\n"
                "  -o, --output=PATH     Path to output files [%s]\n"
                "  -i, --init=PATH       Path to init executable [%s]\n"
                "  -F, --no-filter       Disable filtering of unimportant or ephemeral processes\n"
                "  -C, --cmdline         Display full command lines with arguments\n"
                "  -c, --control-group   Display process control group\n"
                "  -h, --help            Display this message\n\n"
                "See bootchart.conf for more information.\n",
                program_invocation_short_name,
                DEFAULT_HZ,
                DEFAULT_SAMPLES_LEN,
                DEFAULT_SCALE_X,
                DEFAULT_SCALE_Y,
                DEFAULT_OUTPUT,
                DEFAULT_INIT);
}

static int parse_args(int argc, char *argv[]) {
        static struct option options[] = {
                {"rel",       no_argument,        NULL,  'r'},
                {"freq",      required_argument,  NULL,  'f'},
                {"samples",   required_argument,  NULL,  'n'},
                {"pss",       no_argument,        NULL,  'p'},
                {"output",    required_argument,  NULL,  'o'},
                {"init",      required_argument,  NULL,  'i'},
                {"no-filter", no_argument,        NULL,  'F'},
                {"cmdline",   no_argument,        NULL,  'C'},
                {"control-group", no_argument,    NULL,  'c'},
                {"help",      no_argument,        NULL,  'h'},
                {"scale-x",   required_argument,  NULL,  'x'},
                {"scale-y",   required_argument,  NULL,  'y'},
                {"entropy",   no_argument,        NULL,  'e'},
                {NULL, 0, NULL, 0}
        };
        int c;

        while ((c = getopt_long(argc, argv, "erpf:n:o:i:FCchx:y:", options, NULL)) >= 0) {
                int r;

                switch (c) {
                case 'r':
                        arg_relative = true;
                        break;
                case 'f':
                        r = safe_atod(optarg, &arg_hz);
                        if (r < 0)
                                log_warning("failed to parse --freq/-f argument '%s': %s",
                                            optarg, strerror(-r));
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
                                log_warning("failed to parse --samples/-n argument '%s': %s",
                                            optarg, strerror(-r));
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
                                log_warning("failed to parse --scale-x/-x argument '%s': %s",
                                            optarg, strerror(-r));
                        break;
                case 'y':
                        r = safe_atod(optarg, &arg_scale_y);
                        if (r < 0)
                                log_warning("failed to parse --scale-y/-y argument '%s': %s",
                                            optarg, strerror(-r));
                        break;
                case 'e':
                        arg_entropy = true;
                        break;
                case 'h':
                        help();
                        exit (EXIT_SUCCESS);
                default:
                        break;
                }
        }

        if (arg_hz <= 0.0) {
                fprintf(stderr, "Error: Frequency needs to be > 0\n");
                return -EINVAL;
        }

        return 0;
}

static void do_journal_append(char *file) {
        struct iovec iovec[5];
        int r, f, j = 0;
        ssize_t n;
        _cleanup_free_ char *bootchart_file = NULL, *bootchart_message = NULL,
                *p = NULL;

        bootchart_file = strappend("BOOTCHART_FILE=", file);
        if (bootchart_file)
                IOVEC_SET_STRING(iovec[j++], bootchart_file);

        IOVEC_SET_STRING(iovec[j++], "MESSAGE_ID=9f26aa562cf440c2b16c773d0479b518");
        IOVEC_SET_STRING(iovec[j++], "PRIORITY=7");
        bootchart_message = strjoin("MESSAGE=Bootchart created: ", file, NULL);
        if (bootchart_message)
                IOVEC_SET_STRING(iovec[j++], bootchart_message);

        p = malloc(9 + BOOTCHART_MAX);
        if (!p) {
                log_oom();
                return;
        }

        memcpy(p, "BOOTCHART=", 10);

        f = open(file, O_RDONLY|O_CLOEXEC);
        if (f < 0) {
                log_error("Failed to read bootchart data: %m");
                return;
        }
        n = loop_read(f, p + 10, BOOTCHART_MAX, false);
        if (n < 0) {
                log_error("Failed to read bootchart data: %s", strerror(-n));
                close(f);
                return;
        }
        close(f);

        iovec[j].iov_base = p;
        iovec[j].iov_len = 10 + n;
        j++;

        r = sd_journal_sendv(iovec, j);
        if (r < 0)
                log_error("Failed to send bootchart: %s", strerror(-r));
}

int main(int argc, char *argv[]) {
        _cleanup_free_ char *build = NULL;
        struct sigaction sig = {
                .sa_handler = signal_handler,
        };
        struct ps_struct *ps;
        char output_file[PATH_MAX];
        char datestr[200];
        time_t t = 0;
        int r;
        struct rlimit rlim;

        parse_conf();

        r = parse_args(argc, argv);
        if (r < 0)
                return EXIT_FAILURE;

        /*
         * If the kernel executed us through init=/usr/lib/systemd/systemd-bootchart, then
         * fork:
         * - parent execs executable specified via init_path[] (/sbin/init by default) as pid=1
         * - child logs data
         */
        if (getpid() == 1) {
                if (fork()) {
                        /* parent */
                        execl(arg_init_path, arg_init_path, NULL);
                }
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

        log_uptime();

        LIST_HEAD_INIT(head);

        /* main program loop */
        for (samples = 0; !exiting && samples < arg_samples_len; samples++) {
                int res;
                double sample_stop;
                struct timespec req;
                time_t newint_s;
                long newint_ns;
                double elapsed;
                double timeleft;

                sampledata = new0(struct list_sample_data, 1);
                if (sampledata == NULL) {
                        log_error("Failed to allocate memory for a node: %m");
                        return -1;
                }

                sampledata->sampletime = gettime_ns();
                sampledata->counter = samples;

                if (!of && (access(arg_output_path, R_OK|W_OK|X_OK) == 0)) {
                        t = time(NULL);
                        strftime(datestr, sizeof(datestr), "%Y%m%d-%H%M", localtime(&t));
                        snprintf(output_file, PATH_MAX, "%s/bootchart-%s.svg", arg_output_path, datestr);
                        of = fopen(output_file, "we");
                }

                if (sysfd < 0)
                        sysfd = open("/sys", O_RDONLY|O_CLOEXEC);

                if (!build) {
                        if (parse_env_file("/etc/os-release", NEWLINE, "PRETTY_NAME", &build, NULL) == -ENOENT)
                                parse_env_file("/usr/lib/os-release", NEWLINE, "PRETTY_NAME", &build, NULL);
                }

                /* wait for /proc to become available, discarding samples */
                if (graph_start <= 0.0)
                        log_uptime();
                else
                        log_sample(samples, &sampledata);

                sample_stop = gettime_ns();

                elapsed = (sample_stop - sampledata->sampletime) * 1000000000.0;
                timeleft = interval - elapsed;

                newint_s = (time_t)(timeleft / 1000000000.0);
                newint_ns = (long)(timeleft - (newint_s * 1000000000.0));

                /*
                 * check if we have not consumed our entire timeslice. If we
                 * do, don't sleep and take a new sample right away.
                 * we'll lose all the missed samples and overrun our total
                 * time
                 */
                if (newint_ns > 0 || newint_s > 0) {
                        req.tv_sec = newint_s;
                        req.tv_nsec = newint_ns;

                        res = nanosleep(&req, NULL);
                        if (res) {
                                if (errno == EINTR) {
                                        /* caught signal, probably HUP! */
                                        break;
                                }
                                log_error("nanosleep() failed: %m");
                                exit(EXIT_FAILURE);
                        }
                } else {
                        overrun++;
                        /* calculate how many samples we lost and scrap them */
                        arg_samples_len -= (int)(newint_ns / interval);
                }
                LIST_PREPEND(link, head, sampledata);
        }

        /* do some cleanup, close fd's */
        ps = ps_first;
        while (ps->next_ps) {
                ps = ps->next_ps;
                if (ps->schedstat)
                        close(ps->schedstat);
                if (ps->sched)
                        close(ps->sched);
                if (ps->smaps)
                        fclose(ps->smaps);
        }

        if (!of) {
                t = time(NULL);
                strftime(datestr, sizeof(datestr), "%Y%m%d-%H%M", localtime(&t));
                snprintf(output_file, PATH_MAX, "%s/bootchart-%s.svg", arg_output_path, datestr);
                of = fopen(output_file, "we");
        }

        if (!of) {
                fprintf(stderr, "opening output file '%s': %m\n", output_file);
                exit (EXIT_FAILURE);
        }

        svg_do(build);

        fprintf(stderr, "systemd-bootchart wrote %s\n", output_file);

        do_journal_append(output_file);

        if (of)
                fclose(of);

        closedir(proc);
        if (sysfd >= 0)
                close(sysfd);

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
                fprintf(stderr, "systemd-boochart: Warning: sample time overrun %i times\n", overrun);

        return 0;
}
