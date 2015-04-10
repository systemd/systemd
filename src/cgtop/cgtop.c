/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#define __STDC_FORMAT_MACROS
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <alloca.h>
#include <getopt.h>

#include "path-util.h"
#include "terminal-util.h"
#include "util.h"
#include "hashmap.h"
#include "cgroup-util.h"
#include "build.h"
#include "fileio.h"

typedef struct Group {
        char *path;

        bool n_tasks_valid:1;
        bool cpu_valid:1;
        bool memory_valid:1;
        bool io_valid:1;

        unsigned n_tasks;

        unsigned cpu_iteration;
        uint64_t cpu_usage;
        struct timespec cpu_timestamp;
        double cpu_fraction;

        uint64_t memory;

        unsigned io_iteration;
        uint64_t io_input, io_output;
        struct timespec io_timestamp;
        uint64_t io_input_bps, io_output_bps;
} Group;

static unsigned arg_depth = 3;
static unsigned arg_iterations = 0;
static bool arg_batch = false;
static usec_t arg_delay = 1*USEC_PER_SEC;

static enum {
        ORDER_PATH,
        ORDER_TASKS,
        ORDER_CPU,
        ORDER_MEMORY,
        ORDER_IO
} arg_order = ORDER_CPU;

static enum {
        CPU_PERCENT,
        CPU_TIME,
} arg_cpu_type = CPU_PERCENT;

static void group_free(Group *g) {
        assert(g);

        free(g->path);
        free(g);
}

static void group_hashmap_clear(Hashmap *h) {
        Group *g;

        while ((g = hashmap_steal_first(h)))
                group_free(g);
}

static void group_hashmap_free(Hashmap *h) {
        group_hashmap_clear(h);
        hashmap_free(h);
}

static int process(const char *controller, const char *path, Hashmap *a, Hashmap *b, unsigned iteration) {
        Group *g;
        int r;
        FILE *f = NULL;
        pid_t pid;
        unsigned n;

        assert(controller);
        assert(path);
        assert(a);

        g = hashmap_get(a, path);
        if (!g) {
                g = hashmap_get(b, path);
                if (!g) {
                        g = new0(Group, 1);
                        if (!g)
                                return -ENOMEM;

                        g->path = strdup(path);
                        if (!g->path) {
                                group_free(g);
                                return -ENOMEM;
                        }

                        r = hashmap_put(a, g->path, g);
                        if (r < 0) {
                                group_free(g);
                                return r;
                        }
                } else {
                        r = hashmap_move_one(a, b, path);
                        if (r < 0)
                                return r;
                        g->cpu_valid = g->memory_valid = g->io_valid = g->n_tasks_valid = false;
                }
        }

        /* Regardless which controller, let's find the maximum number
         * of processes in any of it */

        r = cg_enumerate_processes(controller, path, &f);
        if (r < 0)
                return r;

        n = 0;
        while (cg_read_pid(f, &pid) > 0)
                n++;
        fclose(f);

        if (n > 0) {
                if (g->n_tasks_valid)
                        g->n_tasks = MAX(g->n_tasks, n);
                else
                        g->n_tasks = n;

                g->n_tasks_valid = true;
        }

        if (streq(controller, "cpuacct")) {
                uint64_t new_usage;
                char *p, *v;
                struct timespec ts;

                r = cg_get_path(controller, path, "cpuacct.usage", &p);
                if (r < 0)
                        return r;

                r = read_one_line_file(p, &v);
                free(p);
                if (r < 0)
                        return r;

                r = safe_atou64(v, &new_usage);
                free(v);
                if (r < 0)
                        return r;

                assert_se(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);

                if (g->cpu_iteration == iteration - 1) {
                        uint64_t x, y;

                        x = ((uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec) -
                                ((uint64_t) g->cpu_timestamp.tv_sec * 1000000000ULL + (uint64_t) g->cpu_timestamp.tv_nsec);

                        y = new_usage - g->cpu_usage;

                        if (y > 0) {
                                g->cpu_fraction = (double) y / (double) x;
                                g->cpu_valid = true;
                        }
                }

                g->cpu_usage = new_usage;
                g->cpu_timestamp = ts;
                g->cpu_iteration = iteration;

        } else if (streq(controller, "memory")) {
                char *p, *v;

                r = cg_get_path(controller, path, "memory.usage_in_bytes", &p);
                if (r < 0)
                        return r;

                r = read_one_line_file(p, &v);
                free(p);
                if (r < 0)
                        return r;

                r = safe_atou64(v, &g->memory);
                free(v);
                if (r < 0)
                        return r;

                if (g->memory > 0)
                        g->memory_valid = true;

        } else if (streq(controller, "blkio")) {
                char *p;
                uint64_t wr = 0, rd = 0;
                struct timespec ts;

                r = cg_get_path(controller, path, "blkio.io_service_bytes", &p);
                if (r < 0)
                        return r;

                f = fopen(p, "re");
                free(p);

                if (!f)
                        return -errno;

                for (;;) {
                        char line[LINE_MAX], *l;
                        uint64_t k, *q;

                        if (!fgets(line, sizeof(line), f))
                                break;

                        l = strstrip(line);
                        l += strcspn(l, WHITESPACE);
                        l += strspn(l, WHITESPACE);

                        if (first_word(l, "Read")) {
                                l += 4;
                                q = &rd;
                        } else if (first_word(l, "Write")) {
                                l += 5;
                                q = &wr;
                        } else
                                continue;

                        l += strspn(l, WHITESPACE);
                        r = safe_atou64(l, &k);
                        if (r < 0)
                                continue;

                        *q += k;
                }

                fclose(f);

                assert_se(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);

                if (g->io_iteration == iteration - 1) {
                        uint64_t x, yr, yw;

                        x = ((uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec) -
                                ((uint64_t) g->io_timestamp.tv_sec * 1000000000ULL + (uint64_t) g->io_timestamp.tv_nsec);

                        yr = rd - g->io_input;
                        yw = wr - g->io_output;

                        if (yr > 0 || yw > 0) {
                                g->io_input_bps = (yr * 1000000000ULL) / x;
                                g->io_output_bps = (yw * 1000000000ULL) / x;
                                g->io_valid = true;

                        }
                }

                g->io_input = rd;
                g->io_output = wr;
                g->io_timestamp = ts;
                g->io_iteration = iteration;
        }

        return 0;
}

static int refresh_one(
                const char *controller,
                const char *path,
                Hashmap *a,
                Hashmap *b,
                unsigned iteration,
                unsigned depth) {

        DIR *d = NULL;
        int r;

        assert(controller);
        assert(path);
        assert(a);

        if (depth > arg_depth)
                return 0;

        r = process(controller, path, a, b, iteration);
        if (r < 0)
                return r;

        r = cg_enumerate_subgroups(controller, path, &d);
        if (r < 0) {
                if (r == -ENOENT)
                        return 0;

                return r;
        }

        for (;;) {
                char *fn, *p;

                r = cg_read_subgroup(d, &fn);
                if (r <= 0)
                        goto finish;

                p = strjoin(path, "/", fn, NULL);
                free(fn);

                if (!p) {
                        r = -ENOMEM;
                        goto finish;
                }

                path_kill_slashes(p);

                r = refresh_one(controller, p, a, b, iteration, depth + 1);
                free(p);

                if (r < 0)
                        goto finish;
        }

finish:
        if (d)
                closedir(d);

        return r;
}

static int refresh(Hashmap *a, Hashmap *b, unsigned iteration) {
        int r;

        assert(a);

        r = refresh_one("name=systemd", "/", a, b, iteration, 0);
        if (r < 0)
                if (r != -ENOENT)
                    return r;
        r = refresh_one("cpuacct", "/", a, b, iteration, 0);
        if (r < 0)
                if (r != -ENOENT)
                    return r;
        r = refresh_one("memory", "/", a, b, iteration, 0);
        if (r < 0)
                if (r != -ENOENT)
                    return r;

        r = refresh_one("blkio", "/", a, b, iteration, 0);
        if (r < 0)
                if (r != -ENOENT)
                    return r;
        return 0;
}

static int group_compare(const void*a, const void *b) {
        const Group *x = *(Group**)a, *y = *(Group**)b;

        if (path_startswith(y->path, x->path))
                return -1;
        if (path_startswith(x->path, y->path))
                return 1;

        if (arg_order == ORDER_CPU) {
                if (arg_cpu_type == CPU_PERCENT) {
                        if (x->cpu_valid && y->cpu_valid) {
                                if (x->cpu_fraction > y->cpu_fraction)
                                        return -1;
                                else if (x->cpu_fraction < y->cpu_fraction)
                                        return 1;
                        } else if (x->cpu_valid)
                                return -1;
                        else if (y->cpu_valid)
                                return 1;
                } else {
                        if (x->cpu_usage > y->cpu_usage)
                                return -1;
                        else if (x->cpu_usage < y->cpu_usage)
                                return 1;
                }
        }

        if (arg_order == ORDER_TASKS) {

                if (x->n_tasks_valid && y->n_tasks_valid) {
                        if (x->n_tasks > y->n_tasks)
                                return -1;
                        else if (x->n_tasks < y->n_tasks)
                                return 1;
                } else if (x->n_tasks_valid)
                        return -1;
                else if (y->n_tasks_valid)
                        return 1;
        }

        if (arg_order == ORDER_MEMORY) {
                if (x->memory_valid && y->memory_valid) {
                        if (x->memory > y->memory)
                                return -1;
                        else if (x->memory < y->memory)
                                return 1;
                } else if (x->memory_valid)
                        return -1;
                else if (y->memory_valid)
                        return 1;
        }

        if (arg_order == ORDER_IO) {
                if (x->io_valid && y->io_valid) {
                        if (x->io_input_bps + x->io_output_bps > y->io_input_bps + y->io_output_bps)
                                return -1;
                        else if (x->io_input_bps + x->io_output_bps < y->io_input_bps + y->io_output_bps)
                                return 1;
                } else if (x->io_valid)
                        return -1;
                else if (y->io_valid)
                        return 1;
        }

        return strcmp(x->path, y->path);
}

#define ON ANSI_HIGHLIGHT_ON
#define OFF ANSI_HIGHLIGHT_OFF

static int display(Hashmap *a) {
        Iterator i;
        Group *g;
        Group **array;
        signed path_columns;
        unsigned rows, n = 0, j, maxtcpu = 0, maxtpath = 3; /* 3 for ellipsize() to work properly */
        char buffer[MAX3(21, FORMAT_BYTES_MAX, FORMAT_TIMESPAN_MAX)];

        assert(a);

        /* Set cursor to top left corner and clear screen */
        if (on_tty())
                fputs("\033[H"
                      "\033[2J", stdout);

        array = alloca(sizeof(Group*) * hashmap_size(a));

        HASHMAP_FOREACH(g, a, i)
                if (g->n_tasks_valid || g->cpu_valid || g->memory_valid || g->io_valid)
                        array[n++] = g;

        qsort_safe(array, n, sizeof(Group*), group_compare);

        /* Find the longest names in one run */
        for (j = 0; j < n; j++) {
                unsigned cputlen, pathtlen;

                format_timespan(buffer, sizeof(buffer), (nsec_t) (array[j]->cpu_usage / NSEC_PER_USEC), 0);
                cputlen = strlen(buffer);
                maxtcpu = MAX(maxtcpu, cputlen);
                pathtlen = strlen(array[j]->path);
                maxtpath = MAX(maxtpath, pathtlen);
        }

        if (arg_cpu_type == CPU_PERCENT)
                snprintf(buffer, sizeof(buffer), "%6s", "%CPU");
        else
                snprintf(buffer, sizeof(buffer), "%*s", maxtcpu, "CPU Time");

        rows = lines();
        if (rows <= 10)
                rows = 10;

        if (on_tty()) {
                path_columns = columns() - 36 - strlen(buffer);
                if (path_columns < 10)
                        path_columns = 10;

                printf("%s%-*s%s %s%7s%s %s%s%s %s%8s%s %s%8s%s %s%8s%s\n\n",
                       arg_order == ORDER_PATH ? ON : "", path_columns, "Path",
                       arg_order == ORDER_PATH ? OFF : "",
                       arg_order == ORDER_TASKS ? ON : "", "Tasks",
                       arg_order == ORDER_TASKS ? OFF : "",
                       arg_order == ORDER_CPU ? ON : "", buffer,
                       arg_order == ORDER_CPU ? OFF : "",
                       arg_order == ORDER_MEMORY ? ON : "", "Memory",
                       arg_order == ORDER_MEMORY ? OFF : "",
                       arg_order == ORDER_IO ? ON : "", "Input/s",
                       arg_order == ORDER_IO ? OFF : "",
                       arg_order == ORDER_IO ? ON : "", "Output/s",
                       arg_order == ORDER_IO ? OFF : "");
        } else
                path_columns = maxtpath;

        for (j = 0; j < n; j++) {
                char *p;

                if (on_tty() && j + 5 > rows)
                        break;

                g = array[j];

                p = ellipsize(g->path, path_columns, 33);
                printf("%-*s", path_columns, p ? p : g->path);
                free(p);

                if (g->n_tasks_valid)
                        printf(" %7u", g->n_tasks);
                else
                        fputs("       -", stdout);

                if (arg_cpu_type == CPU_PERCENT) {
                        if (g->cpu_valid)
                                printf(" %6.1f", g->cpu_fraction*100);
                        else
                                fputs("      -", stdout);
                } else
                        printf(" %*s", maxtcpu, format_timespan(buffer, sizeof(buffer), (nsec_t) (g->cpu_usage / NSEC_PER_USEC), 0));

                if (g->memory_valid)
                        printf(" %8s", format_bytes(buffer, sizeof(buffer), g->memory));
                else
                        fputs("        -", stdout);

                if (g->io_valid) {
                        printf(" %8s",
                               format_bytes(buffer, sizeof(buffer), g->io_input_bps));
                        printf(" %8s",
                               format_bytes(buffer, sizeof(buffer), g->io_output_bps));
                } else
                        fputs("        -        -", stdout);

                putchar('\n');
        }

        return 0;
}

static void help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Show top control groups by their resource usage.\n\n"
               "  -h --help           Show this help\n"
               "  --version           Print version and exit\n"
               "  -p                  Order by path\n"
               "  -t                  Order by number of tasks\n"
               "  -c                  Order by CPU load\n"
               "  -m                  Order by memory load\n"
               "  -i                  Order by IO load\n"
               "     --cpu[=TYPE]     Show CPU usage as time or percentage (default)\n"
               "  -d --delay=DELAY    Delay between updates\n"
               "  -n --iterations=N   Run for N iterations before exiting\n"
               "  -b --batch          Run in batch mode, accepting no input\n"
               "     --depth=DEPTH    Maximum traversal depth (default: %u)\n"
               , program_invocation_short_name, arg_depth);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_DEPTH,
                ARG_CPU_TYPE
        };

        static const struct option options[] = {
                { "help",       no_argument,       NULL, 'h'         },
                { "version",    no_argument,       NULL, ARG_VERSION },
                { "delay",      required_argument, NULL, 'd'         },
                { "iterations", required_argument, NULL, 'n'         },
                { "batch",      no_argument,       NULL, 'b'         },
                { "depth",      required_argument, NULL, ARG_DEPTH   },
                { "cpu",        optional_argument, NULL, ARG_CPU_TYPE},
                {}
        };

        int c;
        int r;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hptcmin:bd:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_CPU_TYPE:
                        if (optarg) {
                                if (strcmp(optarg, "time") == 0)
                                        arg_cpu_type = CPU_TIME;
                                else if (strcmp(optarg, "percentage") == 0)
                                        arg_cpu_type = CPU_PERCENT;
                                else
                                        return -EINVAL;
                        }
                        break;

                case ARG_DEPTH:
                        r = safe_atou(optarg, &arg_depth);
                        if (r < 0) {
                                log_error("Failed to parse depth parameter.");
                                return -EINVAL;
                        }

                        break;

                case 'd':
                        r = parse_sec(optarg, &arg_delay);
                        if (r < 0 || arg_delay <= 0) {
                                log_error("Failed to parse delay parameter.");
                                return -EINVAL;
                        }

                        break;

                case 'n':
                        r = safe_atou(optarg, &arg_iterations);
                        if (r < 0) {
                                log_error("Failed to parse iterations parameter.");
                                return -EINVAL;
                        }

                        break;

                case 'b':
                        arg_batch = true;
                        break;

                case 'p':
                        arg_order = ORDER_PATH;
                        break;

                case 't':
                        arg_order = ORDER_TASKS;
                        break;

                case 'c':
                        arg_order = ORDER_CPU;
                        break;

                case 'm':
                        arg_order = ORDER_MEMORY;
                        break;

                case 'i':
                        arg_order = ORDER_IO;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (optind < argc) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char *argv[]) {
        int r;
        Hashmap *a = NULL, *b = NULL;
        unsigned iteration = 0;
        usec_t last_refresh = 0;
        bool quit = false, immediate_refresh = false;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        a = hashmap_new(&string_hash_ops);
        b = hashmap_new(&string_hash_ops);
        if (!a || !b) {
                r = log_oom();
                goto finish;
        }

        signal(SIGWINCH, columns_lines_cache_reset);

        if (!on_tty())
                arg_iterations = 1;

        while (!quit) {
                Hashmap *c;
                usec_t t;
                char key;
                char h[FORMAT_TIMESPAN_MAX];

                t = now(CLOCK_MONOTONIC);

                if (t >= last_refresh + arg_delay || immediate_refresh) {

                        r = refresh(a, b, iteration++);
                        if (r < 0)
                                goto finish;

                        group_hashmap_clear(b);

                        c = a;
                        a = b;
                        b = c;

                        last_refresh = t;
                        immediate_refresh = false;
                }

                r = display(b);
                if (r < 0)
                        goto finish;

                if (arg_iterations && iteration >= arg_iterations)
                        break;

                if (arg_batch) {
                        usleep(last_refresh + arg_delay - t);
                } else {
                        r = read_one_char(stdin, &key,
                                          last_refresh + arg_delay - t, NULL);
                        if (r == -ETIMEDOUT)
                                continue;
                        if (r < 0) {
                                log_error_errno(r, "Couldn't read key: %m");
                                goto finish;
                        }
                }

                fputs("\r \r", stdout);
                fflush(stdout);

                if (arg_batch)
                        continue;

                switch (key) {

                case ' ':
                        immediate_refresh = true;
                        break;

                case 'q':
                        quit = true;
                        break;

                case 'p':
                        arg_order = ORDER_PATH;
                        break;

                case 't':
                        arg_order = ORDER_TASKS;
                        break;

                case 'c':
                        arg_order = ORDER_CPU;
                        break;

                case 'm':
                        arg_order = ORDER_MEMORY;
                        break;

                case 'i':
                        arg_order = ORDER_IO;
                        break;

                case '%':
                        arg_cpu_type = arg_cpu_type == CPU_TIME ? CPU_PERCENT : CPU_TIME;
                        break;

                case '+':
                        if (arg_delay < USEC_PER_SEC)
                                arg_delay += USEC_PER_MSEC*250;
                        else
                                arg_delay += USEC_PER_SEC;

                        fprintf(stdout, "\nIncreased delay to %s.", format_timespan(h, sizeof(h), arg_delay, 0));
                        fflush(stdout);
                        sleep(1);
                        break;

                case '-':
                        if (arg_delay <= USEC_PER_MSEC*500)
                                arg_delay = USEC_PER_MSEC*250;
                        else if (arg_delay < USEC_PER_MSEC*1250)
                                arg_delay -= USEC_PER_MSEC*250;
                        else
                                arg_delay -= USEC_PER_SEC;

                        fprintf(stdout, "\nDecreased delay to %s.", format_timespan(h, sizeof(h), arg_delay, 0));
                        fflush(stdout);
                        sleep(1);
                        break;

                case '?':
                case 'h':
                        fprintf(stdout,
                                "\t<" ON "p" OFF "> By path; <" ON "t" OFF "> By tasks; <" ON "c" OFF "> By CPU; <" ON "m" OFF "> By memory; <" ON "i" OFF "> By I/O\n"
                                "\t<" ON "+" OFF "> Increase delay; <" ON "-" OFF "> Decrease delay; <" ON "%%" OFF "> Toggle time\n"
                                "\t<" ON "q" OFF "> Quit; <" ON "SPACE" OFF "> Refresh");
                        fflush(stdout);
                        sleep(3);
                        break;

                default:
                        fprintf(stdout, "\nUnknown key '%c'. Ignoring.", key);
                        fflush(stdout);
                        sleep(1);
                        break;
                }
        }

        r = 0;

finish:
        group_hashmap_free(a);
        group_hashmap_free(b);

        if (r < 0) {
                log_error_errno(r, "Exiting with failure: %m");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
