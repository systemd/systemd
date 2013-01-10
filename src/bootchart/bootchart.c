/*
 * bootchart.c
 *
 * Copyright (C) 2009-2012 Intel Coproration
 *
 * Authors:
 *   Auke Kok <auke-jan.h.kok@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */


#include <sys/time.h>
#include <sys/types.h>
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


#include "bootchart.h"
#include "util.h"

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
FILE *of;
int overrun = 0;
static int exiting = 0;

/* graph defaults */
int entropy = 0;
int initcall = 1;
int relative;
int filter = 1;
int pss = 0;
int samples;
int len = 500; /* we record len+1 (1 start sample) */
double hz = 25.0;   /* 20 seconds log time */
double scale_x = 100.0; /* 100px = 1sec */
double scale_y = 20.0;  /* 16px = 1 process bar */

char init_path[PATH_MAX] = "/sbin/init";
char output_path[PATH_MAX] = "/var/log";

static struct rlimit rlim;

static void signal_handler(int sig)
{
        if (sig++)
                sig--;
        exiting = 1;
}


int main(int argc, char *argv[])
{
        struct sigaction sig;
        struct ps_struct *ps;
        char output_file[PATH_MAX];
        char datestr[200];
        time_t t;
        FILE *f;
        int gind;
        int i;

        memset(&t, 0, sizeof(time_t));

        rlim.rlim_cur = 4096;
        rlim.rlim_max = 4096;
        (void) setrlimit(RLIMIT_NOFILE, &rlim);

        f = fopen("/etc/systemd/bootchart.conf", "r");
        if (f) {
                char buf[256];
                char *key;
                char *val;

                while (fgets(buf, 80, f) != NULL) {
                        char *c;

                        c = strchr(buf, '\n');
                        if (c) *c = 0; /* remove trailing \n */

                        if (buf[0] == '#')
                                continue; /* comment line */

                        key = strtok(buf, "=");
                        if (!key)
                                continue;
                        val = strtok(NULL, "=");
                        if (!val)
                                continue;

                        // todo: filter leading/trailing whitespace

                        if (streq(key, "samples"))
                                len = atoi(val);
                        if (streq(key, "freq"))
                                hz = atof(val);
                        if (streq(key, "rel"))
                                relative = atoi(val);
                        if (streq(key, "filter"))
                                filter = atoi(val);
                        if (streq(key, "pss"))
                                pss = atoi(val);
                        if (streq(key, "output"))
                                strncpy(output_path, val, PATH_MAX - 1);
                        if (streq(key, "init"))
                                strncpy(init_path, val, PATH_MAX - 1);
                        if (streq(key, "scale_x"))
                                scale_x = atof(val);
                        if (streq(key, "scale_y"))
                                scale_y = atof(val);
                        if (streq(key, "entropy"))
                                entropy = atoi(val);
                }
                fclose(f);
        }

        while (1) {
                static struct option opts[] = {
                        {"rel", 0, NULL, 'r'},
                        {"freq", 1, NULL, 'f'},
                        {"samples", 1, NULL, 'n'},
                        {"pss", 0, NULL, 'p'},
                        {"output", 1, NULL, 'o'},
                        {"init", 1, NULL, 'i'},
                        {"filter", 0, NULL, 'F'},
                        {"help", 0, NULL, 'h'},
                        {"scale-x", 1, NULL, 'x'},
                        {"scale-y", 1, NULL, 'y'},
                        {"entropy", 0, NULL, 'e'},
                        {NULL, 0, NULL, 0}
                };

                gind = 0;

                i = getopt_long(argc, argv, "erpf:n:o:i:Fhx:y:", opts, &gind);
                if (i == -1)
                        break;
                switch (i) {
                case 'r':
                        relative = 1;
                        break;
                case 'f':
                        hz = atof(optarg);
                        break;
                case 'F':
                        filter = 0;
                        break;
                case 'n':
                        len = atoi(optarg);
                        break;
                case 'o':
                        strncpy(output_path, optarg, PATH_MAX - 1);
                        break;
                case 'i':
                        strncpy(init_path, optarg, PATH_MAX - 1);
                        break;
                case 'p':
                        pss = 1;
                        break;
                case 'x':
                        scale_x = atof(optarg);
                        break;
                case 'y':
                        scale_y = atof(optarg);
                        break;
                case 'e':
                        entropy = 1;
                        break;
                case 'h':
                        fprintf(stderr, "Usage: %s [OPTIONS]\n", argv[0]);
                        fprintf(stderr, " --rel,     -r            Record time relative to recording\n");
                        fprintf(stderr, " --freq,    -f N          Sample frequency [%f]\n", hz);
                        fprintf(stderr, " --samples, -n N          Stop sampling at [%d] samples\n", len);
                        fprintf(stderr, " --scale-x, -x N          Scale the graph horizontally [%f] \n", scale_x);
                        fprintf(stderr, " --scale-y, -y N          Scale the graph vertically [%f] \n", scale_y);
                        fprintf(stderr, " --pss,     -p            Enable PSS graph (CPU intensive)\n");
                        fprintf(stderr, " --entropy, -e            Enable the entropy_avail graph\n");
                        fprintf(stderr, " --output,  -o [PATH]     Path to output files [%s]\n", output_path);
                        fprintf(stderr, " --init,    -i [PATH]     Path to init executable [%s]\n", init_path);
                        fprintf(stderr, " --filter,  -F            Disable filtering of processes from the graph\n");
                        fprintf(stderr, "                          that are of less importance or short-lived\n");
                        fprintf(stderr, " --help,    -h            Display this message\n");
                        fprintf(stderr, "See the installed README and bootchartd.conf.example for more information.\n");
                        exit (EXIT_SUCCESS);
                        break;
                default:
                        break;
                }
        }

        if (len > MAXSAMPLES) {
                fprintf(stderr, "Error: samples exceeds maximum\n");
                exit(EXIT_FAILURE);
        }

        if (hz <= 0.0) {
                fprintf(stderr, "Error: Frequency needs to be > 0\n");
                exit(EXIT_FAILURE);
        }

        /*
         * If the kernel executed us through init=/sbin/bootchartd, then
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
                        len = len + ((int)(newint_ns / interval));
                }

                samples++;

                if (samples > len)
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
        closedir(proc);

        t = time(NULL);
        strftime(datestr, sizeof(datestr), "%Y%m%d-%H%M", localtime(&t));
        snprintf(output_file, PATH_MAX, "%s/bootchart-%s.svg", output_path, datestr);

        of = fopen(output_file, "w");
        if (!of) {
                perror("open output_file");
                exit (EXIT_FAILURE);
        }

        svg_do();

        fprintf(stderr, "bootchartd: Wrote %s\n", output_file);
        fclose(of);

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
                fprintf(stderr, "bootchartd: Warning: sample time overrun %i times\n", overrun);

        return 0;
}
