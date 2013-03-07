/***
  bootchart.c - This file is part of systemd-bootchart

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


#include "bootchart.h"
#include "util.h"
#include "fileio.h"
#include "macro.h"
#include "conf-parser.h"
#include "strxcpyx.h"
#include "path-util.h"

double graph_start;
double log_start;
double sampletime[MAXSAMPLES];
struct ps_struct *ps_first;
struct block_stat_struct blockstat[MAXSAMPLES];
int entropy_avail[MAXSAMPLES];
struct cpu_stat_struct cpustat[MAXCPUS];
int pscount;
int cpus;
double interval;
FILE *of = NULL;
int overrun = 0;
static int exiting = 0;
int sysfd=-1;

/* graph defaults */
bool entropy = false;
bool initcall = true;
bool relative = false;
bool filter = true;
bool show_cmdline = false;
bool pss = false;
int samples;
int samples_len = 500; /* we record len+1 (1 start sample) */
double hz = 25.0;   /* 20 seconds log time */
double scale_x = 100.0; /* 100px = 1sec */
double scale_y = 20.0;  /* 16px = 1 process bar */

char init_path[PATH_MAX] = "/sbin/init";
char output_path[PATH_MAX] = "/run/log";

static struct rlimit rlim;

static void signal_handler(int sig)
{
        if (sig++)
                sig--;
        exiting = 1;
}


int main(int argc, char *argv[])
{
        _cleanup_free_ char *build = NULL;
        struct sigaction sig;
        struct ps_struct *ps;
        char output_file[PATH_MAX];
        char datestr[200];
        time_t t = 0;
        const char *fn;
        _cleanup_fclose_ FILE *f;
        int gind;
        int i, r;
        char *init = NULL, *output = NULL;

        const ConfigTableItem items[] = {
                { "Bootchart", "Samples",          config_parse_int,    0, &samples_len },
                { "Bootchart", "Frequency",        config_parse_double, 0, &hz          },
                { "Bootchart", "Relative",         config_parse_bool,   0, &relative    },
                { "Bootchart", "Filter",           config_parse_bool,   0, &filter      },
                { "Bootchart", "Output",           config_parse_path,   0, &output      },
                { "Bootchart", "Init",             config_parse_path,   0, &init        },
                { "Bootchart", "PlotMemoryUsage",  config_parse_bool,   0, &pss         },
                { "Bootchart", "PlotEntropyGraph", config_parse_bool,   0, &entropy     },
                { "Bootchart", "ScaleX",           config_parse_double, 0, &scale_x     },
                { "Bootchart", "ScaleY",           config_parse_double, 0, &scale_y     },
                { NULL, NULL, NULL, 0, NULL }
        };

        rlim.rlim_cur = 4096;
        rlim.rlim_max = 4096;
        (void) setrlimit(RLIMIT_NOFILE, &rlim);

        fn = "/etc/systemd/bootchart.conf";
        f = fopen(fn, "re");
        if (f) {
            r = config_parse(fn, f, NULL, config_item_table_lookup, (void*) items, true, NULL);
            if (r < 0)
                    log_warning("Failed to parse configuration file: %s", strerror(-r));

            if (init != NULL)
                    strscpy(init_path, sizeof(init_path), init);
            if (output != NULL)
                    strscpy(output_path, sizeof(output_path), output);
        }

        while (1) {
                static struct option opts[] = {
                        {"rel",       no_argument,        NULL,  'r'},
                        {"freq",      required_argument,  NULL,  'f'},
                        {"samples",   required_argument,  NULL,  'n'},
                        {"pss",       no_argument,        NULL,  'p'},
                        {"output",    required_argument,  NULL,  'o'},
                        {"init",      required_argument,  NULL,  'i'},
                        {"no-filter", no_argument,        NULL,  'F'},
                        {"cmdline",   no_argument,        NULL,  'C'},
                        {"help",      no_argument,        NULL,  'h'},
                        {"scale-x",   required_argument,  NULL,  'x'},
                        {"scale-y",   required_argument,  NULL,  'y'},
                        {"entropy",   no_argument,        NULL,  'e'},
                        {NULL, 0, NULL, 0}
                };

                gind = 0;

                i = getopt_long(argc, argv, "erpf:n:o:i:FChx:y:", opts, &gind);
                if (i == -1)
                        break;
                switch (i) {
                case 'r':
                        relative = true;
                        break;
                case 'f':
                        r = safe_atod(optarg, &hz);
                        if (r < 0)
                                log_warning("failed to parse --freq/-f argument '%s': %s",
                                            optarg, strerror(-r));
                        break;
                case 'F':
                        filter = false;
                        break;
                case 'C':
                        show_cmdline = true;
                        break;
                case 'n':
                        r = safe_atoi(optarg, &samples_len);
                        if (r < 0)
                                log_warning("failed to parse --samples/-n argument '%s': %s",
                                            optarg, strerror(-r));
                        break;
                case 'o':
                        path_kill_slashes(optarg);
                        strscpy(output_path, sizeof(output_path), optarg);
                        break;
                case 'i':
                        path_kill_slashes(optarg);
                        strscpy(init_path, sizeof(init_path), optarg);
                        break;
                case 'p':
                        pss = true;
                        break;
                case 'x':
                        r = safe_atod(optarg, &scale_x);
                        if (r < 0)
                                log_warning("failed to parse --scale-x/-x argument '%s': %s",
                                            optarg, strerror(-r));
                        break;
                case 'y':
                        r = safe_atod(optarg, &scale_y);
                        if (r < 0)
                                log_warning("failed to parse --scale-y/-y argument '%s': %s",
                                            optarg, strerror(-r));
                        break;
                case 'e':
                        entropy = true;
                        break;
                case 'h':
                        fprintf(stderr, "Usage: %s [OPTIONS]\n", argv[0]);
                        fprintf(stderr, " --rel,       -r          Record time relative to recording\n");
                        fprintf(stderr, " --freq,      -f f        Sample frequency [%f]\n", hz);
                        fprintf(stderr, " --samples,   -n N        Stop sampling at [%d] samples\n", samples_len);
                        fprintf(stderr, " --scale-x,   -x N        Scale the graph horizontally [%f] \n", scale_x);
                        fprintf(stderr, " --scale-y,   -y N        Scale the graph vertically [%f] \n", scale_y);
                        fprintf(stderr, " --pss,       -p          Enable PSS graph (CPU intensive)\n");
                        fprintf(stderr, " --entropy,   -e          Enable the entropy_avail graph\n");
                        fprintf(stderr, " --output,    -o [PATH]   Path to output files [%s]\n", output_path);
                        fprintf(stderr, " --init,      -i [PATH]   Path to init executable [%s]\n", init_path);
                        fprintf(stderr, " --no-filter, -F          Disable filtering of processes from the graph\n");
                        fprintf(stderr, "                          that are of less importance or short-lived\n");
                        fprintf(stderr, " --help,      -h          Display this message\n");
                        fprintf(stderr, "See bootchart.conf for more information.\n");
                        exit (EXIT_SUCCESS);
                        break;
                default:
                        break;
                }
        }

        if (samples_len > MAXSAMPLES) {
                fprintf(stderr, "Error: samples exceeds maximum\n");
                exit(EXIT_FAILURE);
        }

        if (hz <= 0.0) {
                fprintf(stderr, "Error: Frequency needs to be > 0\n");
                exit(EXIT_FAILURE);
        }

        /*
         * If the kernel executed us through init=/usr/lib/systemd/systemd-bootchart, then
         * fork:
         * - parent execs executable specified via init_path[] (/sbin/init by default) as pid=1
         * - child logs data
         */
        if (getpid() == 1) {
                if (fork()) {
                        /* parent */
                        execl(init_path, init_path, NULL);
                }
        }
        argv[0][0] = '@';

        /* start with empty ps LL */
        ps_first = calloc(1, sizeof(struct ps_struct));
        if (!ps_first) {
                perror("calloc(ps_struct)");
                exit(EXIT_FAILURE);
        }

        /* handle TERM/INT nicely */
        memset(&sig, 0, sizeof(struct sigaction));
        sig.sa_handler = signal_handler;
        sigaction(SIGHUP, &sig, NULL);

        interval = (1.0 / hz) * 1000000000.0;

        log_uptime();

        /* main program loop */
        while (!exiting) {
                int res;
                double sample_stop;
                struct timespec req;
                time_t newint_s;
                long newint_ns;
                double elapsed;
                double timeleft;

                sampletime[samples] = gettime_ns();

                if (!of && (access(output_path, R_OK|W_OK|X_OK) == 0)) {
                        t = time(NULL);
                        strftime(datestr, sizeof(datestr), "%Y%m%d-%H%M", localtime(&t));
                        snprintf(output_file, PATH_MAX, "%s/bootchart-%s.svg", output_path, datestr);
                        of = fopen(output_file, "w");
                }

                if (sysfd < 0) {
                        sysfd = open("/sys", O_RDONLY);
                }

                if (!build) {
                        parse_env_file("/etc/os-release", NEWLINE,
                                       "PRETTY_NAME", &build,
                                       NULL);
                }

                /* wait for /proc to become available, discarding samples */
                if (!(graph_start > 0.0))
                        log_uptime();
                else
                        log_sample(samples);

                sample_stop = gettime_ns();

                elapsed = (sample_stop - sampletime[samples]) * 1000000000.0;
                timeleft = interval - elapsed;

                newint_s = (time_t)(timeleft / 1000000000.0);
                newint_ns = (long)(timeleft - (newint_s * 1000000000.0));

                /*
                 * check if we have not consumed our entire timeslice. If we
                 * do, don't sleep and take a new sample right away.
                 * we'll lose all the missed samples and overrun our total
                 * time
                 */
                if ((newint_ns > 0) || (newint_s > 0)) {
                        req.tv_sec = newint_s;
                        req.tv_nsec = newint_ns;

                        res = nanosleep(&req, NULL);
                        if (res) {
                                if (errno == EINTR) {
                                        /* caught signal, probably HUP! */
                                        break;
                                }
                                perror("nanosleep()");
                                exit (EXIT_FAILURE);
                        }
                } else {
                        overrun++;
                        /* calculate how many samples we lost and scrap them */
                        samples_len = samples_len + ((int)(newint_ns / interval));
                }

                samples++;

                if (samples > samples_len)
                        break;

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
                snprintf(output_file, PATH_MAX, "%s/bootchart-%s.svg", output_path, datestr);
                of = fopen(output_file, "w");
        }

        if (!of) {
                fprintf(stderr, "opening output file '%s': %m\n", output_file);
                exit (EXIT_FAILURE);
        }

        svg_do(build);

        fprintf(stderr, "systemd-bootchart wrote %s\n", output_file);
        fclose(of);

        closedir(proc);
        close(sysfd);

        /* nitpic cleanups */
        ps = ps_first;
        while (ps->next_ps) {
                struct ps_struct *old = ps;
                ps = ps->next_ps;
                free(old->sample);
                free(old);
        }
        free(ps->sample);
        free(ps);

        /* don't complain when overrun once, happens most commonly on 1st sample */
        if (overrun > 1)
                fprintf(stderr, "systemd-boochart: Warning: sample time overrun %i times\n", overrun);

        return 0;
}
