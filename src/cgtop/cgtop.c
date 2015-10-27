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

#include <alloca.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "terminal-util.h"
#include "unit-name.h"
#include "util.h"

typedef struct Group {
        char *path;

        bool n_tasks_valid:1;
        bool cpu_valid:1;
        bool memory_valid:1;
        bool io_valid:1;

        uint64_t n_tasks;

        unsigned cpu_iteration;
        nsec_t cpu_usage;
        nsec_t cpu_timestamp;
        double cpu_fraction;

        uint64_t memory;

        unsigned io_iteration;
        uint64_t io_input, io_output;
        nsec_t io_timestamp;
        uint64_t io_input_bps, io_output_bps;
} Group;

static unsigned arg_depth = 3;
static unsigned arg_iterations = (unsigned) -1;
static bool arg_batch = false;
static bool arg_raw = false;
static usec_t arg_delay = 1*USEC_PER_SEC;
static char* arg_machine = NULL;

enum {
        COUNT_PIDS,
        COUNT_USERSPACE_PROCESSES,
        COUNT_ALL_PROCESSES,
} arg_count = COUNT_PIDS;
static bool arg_recursive = true;

static enum {
        ORDER_PATH,
        ORDER_TASKS,
        ORDER_CPU,
        ORDER_MEMORY,
        ORDER_IO,
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

static const char *maybe_format_bytes(char *buf, size_t l, bool is_valid, uint64_t t) {
        if (!is_valid)
                return "-";
        if (arg_raw) {
                snprintf(buf, l, "%jd", t);
                return buf;
        }
        return format_bytes(buf, l, t);
}

static int process(
                const char *controller,
                const char *path,
                Hashmap *a,
                Hashmap *b,
                unsigned iteration,
                Group **ret) {

        Group *g;
        int r;

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

        if (streq(controller, SYSTEMD_CGROUP_CONTROLLER) && IN_SET(arg_count, COUNT_ALL_PROCESSES, COUNT_USERSPACE_PROCESSES)) {
                _cleanup_fclose_ FILE *f = NULL;
                pid_t pid;

                r = cg_enumerate_processes(controller, path, &f);
                if (r == -ENOENT)
                        return 0;
                if (r < 0)
                        return r;

                g->n_tasks = 0;
                while (cg_read_pid(f, &pid) > 0) {

                        if (arg_count == COUNT_USERSPACE_PROCESSES && is_kernel_thread(pid) > 0)
                                continue;

                        g->n_tasks++;
                }

                if (g->n_tasks > 0)
                        g->n_tasks_valid = true;

        } else if (streq(controller, "pids") && arg_count == COUNT_PIDS) {
                _cleanup_free_ char *p = NULL, *v = NULL;

                r = cg_get_path(controller, path, "pids.current", &p);
                if (r < 0)
                        return r;

                r = read_one_line_file(p, &v);
                if (r == -ENOENT)
                        return 0;
                if (r < 0)
                        return r;

                r = safe_atou64(v, &g->n_tasks);
                if (r < 0)
                        return r;

                if (g->n_tasks > 0)
                        g->n_tasks_valid = true;

        } else if (streq(controller, "cpuacct") && cg_unified() <= 0) {
                _cleanup_free_ char *p = NULL, *v = NULL;
                uint64_t new_usage;
                nsec_t timestamp;

                r = cg_get_path(controller, path, "cpuacct.usage", &p);
                if (r < 0)
                        return r;

                r = read_one_line_file(p, &v);
                if (r == -ENOENT)
                        return 0;
                if (r < 0)
                        return r;

                r = safe_atou64(v, &new_usage);
                if (r < 0)
                        return r;

                timestamp = now_nsec(CLOCK_MONOTONIC);

                if (g->cpu_iteration == iteration - 1 &&
                    (nsec_t) new_usage > g->cpu_usage) {

                        nsec_t x, y;

                        x = timestamp - g->cpu_timestamp;
                        if (x < 1)
                                x = 1;

                        y = (nsec_t) new_usage - g->cpu_usage;
                        g->cpu_fraction = (double) y / (double) x;
                        g->cpu_valid = true;
                }

                g->cpu_usage = (nsec_t) new_usage;
                g->cpu_timestamp = timestamp;
                g->cpu_iteration = iteration;

        } else if (streq(controller, "memory")) {
                _cleanup_free_ char *p = NULL, *v = NULL;

                if (cg_unified() <= 0)
                        r = cg_get_path(controller, path, "memory.usage_in_bytes", &p);
                else
                        r = cg_get_path(controller, path, "memory.current", &p);
                if (r < 0)
                        return r;

                r = read_one_line_file(p, &v);
                if (r == -ENOENT)
                        return 0;
                if (r < 0)
                        return r;

                r = safe_atou64(v, &g->memory);
                if (r < 0)
                        return r;

                if (g->memory > 0)
                        g->memory_valid = true;

        } else if (streq(controller, "blkio") && cg_unified() <= 0) {
                _cleanup_fclose_ FILE *f = NULL;
                _cleanup_free_ char *p = NULL;
                uint64_t wr = 0, rd = 0;
                nsec_t timestamp;

                r = cg_get_path(controller, path, "blkio.io_service_bytes", &p);
                if (r < 0)
                        return r;

                f = fopen(p, "re");
                if (!f) {
                        if (errno == ENOENT)
                                return 0;
                        return -errno;
                }

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

                timestamp = now_nsec(CLOCK_MONOTONIC);

                if (g->io_iteration == iteration - 1) {
                        uint64_t x, yr, yw;

                        x = (uint64_t) (timestamp - g->io_timestamp);
                        if (x < 1)
                                x = 1;

                        if (rd > g->io_input)
                                yr = rd - g->io_input;
                        else
                                yr = 0;

                        if (wr > g->io_output)
                                yw = wr - g->io_output;
                        else
                                yw = 0;

                        if (yr > 0 || yw > 0) {
                                g->io_input_bps = (yr * 1000000000ULL) / x;
                                g->io_output_bps = (yw * 1000000000ULL) / x;
                                g->io_valid = true;
                        }
                }

                g->io_input = rd;
                g->io_output = wr;
                g->io_timestamp = timestamp;
                g->io_iteration = iteration;
        }

        if (ret)
                *ret = g;

        return 0;
}

static int refresh_one(
                const char *controller,
                const char *path,
                Hashmap *a,
                Hashmap *b,
                unsigned iteration,
                unsigned depth,
                Group **ret) {

        _cleanup_closedir_ DIR *d = NULL;
        Group *ours;
        int r;

        assert(controller);
        assert(path);
        assert(a);

        if (depth > arg_depth)
                return 0;

        r = process(controller, path, a, b, iteration, &ours);
        if (r < 0)
                return r;

        r = cg_enumerate_subgroups(controller, path, &d);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *fn = NULL, *p = NULL;
                Group *child = NULL;

                r = cg_read_subgroup(d, &fn);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                p = strjoin(path, "/", fn, NULL);
                if (!p)
                        return -ENOMEM;

                path_kill_slashes(p);

                r = refresh_one(controller, p, a, b, iteration, depth + 1, &child);
                if (r < 0)
                        return r;

                if (arg_recursive &&
                    IN_SET(arg_count, COUNT_ALL_PROCESSES, COUNT_USERSPACE_PROCESSES) &&
                    child &&
                    child->n_tasks_valid &&
                    streq(controller, SYSTEMD_CGROUP_CONTROLLER)) {

                        /* Recursively sum up processes */

                        if (ours->n_tasks_valid)
                                ours->n_tasks += child->n_tasks;
                        else {
                                ours->n_tasks = child->n_tasks;
                                ours->n_tasks_valid = true;
                        }
                }
        }

        if (ret)
                *ret = ours;

        return 1;
}

static int refresh(const char *root, Hashmap *a, Hashmap *b, unsigned iteration) {
        int r;

        assert(a);

        r = refresh_one(SYSTEMD_CGROUP_CONTROLLER, root, a, b, iteration, 0, NULL);
        if (r < 0)
                return r;
        r = refresh_one("cpuacct", root, a, b, iteration, 0, NULL);
        if (r < 0)
                return r;
        r = refresh_one("memory", root, a, b, iteration, 0, NULL);
        if (r < 0)
                return r;
        r = refresh_one("blkio", root, a, b, iteration, 0, NULL);
        if (r < 0)
                return r;
        r = refresh_one("pids", root, a, b, iteration, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int group_compare(const void*a, const void *b) {
        const Group *x = *(Group**)a, *y = *(Group**)b;

        if (arg_order != ORDER_TASKS || arg_recursive) {
                /* Let's make sure that the parent is always before
                 * the child. Except when ordering by tasks and
                 * recursive summing is off, since that is actually
                 * not accumulative for all children. */

                if (path_startswith(y->path, x->path))
                        return -1;
                if (path_startswith(x->path, y->path))
                        return 1;
        }

        switch (arg_order) {

        case ORDER_PATH:
                break;

        case ORDER_CPU:
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

                break;

        case ORDER_TASKS:
                if (x->n_tasks_valid && y->n_tasks_valid) {
                        if (x->n_tasks > y->n_tasks)
                                return -1;
                        else if (x->n_tasks < y->n_tasks)
                                return 1;
                } else if (x->n_tasks_valid)
                        return -1;
                else if (y->n_tasks_valid)
                        return 1;

                break;

        case ORDER_MEMORY:
                if (x->memory_valid && y->memory_valid) {
                        if (x->memory > y->memory)
                                return -1;
                        else if (x->memory < y->memory)
                                return 1;
                } else if (x->memory_valid)
                        return -1;
                else if (y->memory_valid)
                        return 1;

                break;

        case ORDER_IO:
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

        return path_compare(x->path, y->path);
}

static void display(Hashmap *a) {
        Iterator i;
        Group *g;
        Group **array;
        signed path_columns;
        unsigned rows, n = 0, j, maxtcpu = 0, maxtpath = 3; /* 3 for ellipsize() to work properly */
        char buffer[MAX3(21, FORMAT_BYTES_MAX, FORMAT_TIMESPAN_MAX)];

        assert(a);

        if (on_tty())
                fputs(ANSI_HOME_CLEAR, stdout);

        array = alloca(sizeof(Group*) * hashmap_size(a));

        HASHMAP_FOREACH(g, a, i)
                if (g->n_tasks_valid || g->cpu_valid || g->memory_valid || g->io_valid)
                        array[n++] = g;

        qsort_safe(array, n, sizeof(Group*), group_compare);

        /* Find the longest names in one run */
        for (j = 0; j < n; j++) {
                unsigned cputlen, pathtlen;

                format_timespan(buffer, sizeof(buffer), (usec_t) (array[j]->cpu_usage / NSEC_PER_USEC), 0);
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
                const char *on, *off;

                path_columns = columns() - 36 - strlen(buffer);
                if (path_columns < 10)
                        path_columns = 10;

                on = ansi_highlight_underline();
                off = ansi_underline();

                printf("%s%s%-*s%s %s%7s%s %s%s%s %s%8s%s %s%8s%s %s%8s%s%s\n",
                       ansi_underline(),
                       arg_order == ORDER_PATH ? on : "", path_columns, "Control Group",
                       arg_order == ORDER_PATH ? off : "",
                       arg_order == ORDER_TASKS ? on : "", arg_count == COUNT_PIDS ? "Tasks" : arg_count == COUNT_USERSPACE_PROCESSES ? "Procs" : "Proc+",
                       arg_order == ORDER_TASKS ? off : "",
                       arg_order == ORDER_CPU ? on : "", buffer,
                       arg_order == ORDER_CPU ? off : "",
                       arg_order == ORDER_MEMORY ? on : "", "Memory",
                       arg_order == ORDER_MEMORY ? off : "",
                       arg_order == ORDER_IO ? on : "", "Input/s",
                       arg_order == ORDER_IO ? off : "",
                       arg_order == ORDER_IO ? on : "", "Output/s",
                       arg_order == ORDER_IO ? off : "",
                       ansi_normal());
        } else
                path_columns = maxtpath;

        for (j = 0; j < n; j++) {
                _cleanup_free_ char *ellipsized = NULL;
                const char *path;

                if (on_tty() && j + 6 > rows)
                        break;

                g = array[j];

                path = isempty(g->path) ? "/" : g->path;
                ellipsized = ellipsize(path, path_columns, 33);
                printf("%-*s", path_columns, ellipsized ?: path);

                if (g->n_tasks_valid)
                        printf(" %7" PRIu64, g->n_tasks);
                else
                        fputs("       -", stdout);

                if (arg_cpu_type == CPU_PERCENT) {
                        if (g->cpu_valid)
                                printf(" %6.1f", g->cpu_fraction*100);
                        else
                                fputs("      -", stdout);
                } else
                        printf(" %*s", maxtcpu, format_timespan(buffer, sizeof(buffer), (usec_t) (g->cpu_usage / NSEC_PER_USEC), 0));

                printf(" %8s", maybe_format_bytes(buffer, sizeof(buffer), g->memory_valid, g->memory));
                printf(" %8s", maybe_format_bytes(buffer, sizeof(buffer), g->io_valid, g->io_input_bps));
                printf(" %8s", maybe_format_bytes(buffer, sizeof(buffer), g->io_valid, g->io_output_bps));

                putchar('\n');
        }
}

static void help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Show top control groups by their resource usage.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "  -p --order=path     Order by path\n"
               "  -t --order=tasks    Order by number of tasks/processes\n"
               "  -c --order=cpu      Order by CPU load (default)\n"
               "  -m --order=memory   Order by memory load\n"
               "  -i --order=io       Order by IO load\n"
               "  -r --raw            Provide raw (not human-readable) numbers\n"
               "     --cpu=percentage Show CPU usage as percentage (default)\n"
               "     --cpu=time       Show CPU usage as time\n"
               "  -P                  Count userspace processes instead of tasks (excl. kernel)\n"
               "  -k                  Count all processes instead of tasks (incl. kernel)\n"
               "     --recursive=BOOL Sum up process count recursively\n"
               "  -d --delay=DELAY    Delay between updates\n"
               "  -n --iterations=N   Run for N iterations before exiting\n"
               "  -b --batch          Run in batch mode, accepting no input\n"
               "     --depth=DEPTH    Maximum traversal depth (default: %u)\n"
               "  -M --machine=       Show container\n"
               , program_invocation_short_name, arg_depth);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_DEPTH,
                ARG_CPU_TYPE,
                ARG_ORDER,
                ARG_RECURSIVE,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'           },
                { "version",      no_argument,       NULL, ARG_VERSION   },
                { "delay",        required_argument, NULL, 'd'           },
                { "iterations",   required_argument, NULL, 'n'           },
                { "batch",        no_argument,       NULL, 'b'           },
                { "raw",          no_argument,       NULL, 'r'           },
                { "depth",        required_argument, NULL, ARG_DEPTH     },
                { "cpu",          optional_argument, NULL, ARG_CPU_TYPE  },
                { "order",        required_argument, NULL, ARG_ORDER     },
                { "recursive",    required_argument, NULL, ARG_RECURSIVE },
                { "machine",      required_argument, NULL, 'M'           },
                {}
        };

        bool recursive_unset = false;
        int c, r;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hptcmin:brd:kPM:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_CPU_TYPE:
                        if (optarg) {
                                if (streq(optarg, "time"))
                                        arg_cpu_type = CPU_TIME;
                                else if (streq(optarg, "percentage"))
                                        arg_cpu_type = CPU_PERCENT;
                                else {
                                        log_error("Unknown argument to --cpu=: %s", optarg);
                                        return -EINVAL;
                                }
                        } else
                                arg_cpu_type = CPU_TIME;

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

                case 'r':
                        arg_raw = true;
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

                case ARG_ORDER:
                        if (streq(optarg, "path"))
                                arg_order = ORDER_PATH;
                        else if (streq(optarg, "tasks"))
                                arg_order = ORDER_TASKS;
                        else if (streq(optarg, "cpu"))
                                arg_order = ORDER_CPU;
                        else if (streq(optarg, "memory"))
                                arg_order = ORDER_MEMORY;
                        else if (streq(optarg, "io"))
                                arg_order = ORDER_IO;
                        else {
                                log_error("Invalid argument to --order=: %s", optarg);
                                return -EINVAL;
                        }
                        break;

                case 'k':
                        arg_count = COUNT_ALL_PROCESSES;
                        break;

                case 'P':
                        arg_count = COUNT_USERSPACE_PROCESSES;
                        break;

                case ARG_RECURSIVE:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("Failed to parse --recursive= argument: %s", optarg);
                                return r;
                        }

                        arg_recursive = r;
                        recursive_unset = r == 0;
                        break;

                case 'M':
                        arg_machine = optarg;
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

        if (recursive_unset && arg_count == COUNT_PIDS) {
                log_error("Non-recursive counting is only supported when counting processes, not tasks. Use -P or -k.");
                return -EINVAL;
        }

        return 1;
}

static const char* counting_what(void) {
        if (arg_count == COUNT_PIDS)
                return "tasks";
        else if (arg_count == COUNT_ALL_PROCESSES)
                return "all processes (incl. kernel)";
        else
                return "userspace processes (excl. kernel)";
}

static int get_cgroup_root(char **ret) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
        _cleanup_free_ char *unit = NULL, *path = NULL;
        const char *m;
        int r;

        if (!arg_machine) {
                r = cg_get_root_path(ret);
                if (r < 0)
                        return log_error_errno(r, "Failed to get root control group path: %m");

                return 0;
        }

        m = strjoina("/run/systemd/machines/", arg_machine);
        r = parse_env_file(m, NEWLINE, "SCOPE", &unit, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load machine data: %m");

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return log_oom();

        r = bus_connect_transport_systemd(BUS_TRANSPORT_LOCAL, NULL, false, &bus);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        unit_dbus_interface_from_name(unit),
                        "ControlGroup",
                        &error,
                        ret);
        if (r < 0)
                return log_error_errno(r, "Failed to query unit control group path: %s", bus_error_message(&error, r));

        return 0;
}

int main(int argc, char *argv[]) {
        int r;
        Hashmap *a = NULL, *b = NULL;
        unsigned iteration = 0;
        usec_t last_refresh = 0;
        bool quit = false, immediate_refresh = false;
        _cleanup_free_ char *root = NULL;
        CGroupMask mask;

        log_parse_environment();
        log_open();

        r = cg_mask_supported(&mask);
        if (r < 0) {
                log_error_errno(r, "Failed to determine supported controllers: %m");
                goto finish;
        }

        arg_count = (mask & CGROUP_MASK_PIDS) ? COUNT_PIDS : COUNT_USERSPACE_PROCESSES;

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = get_cgroup_root(&root);
        if (r < 0) {
                log_error_errno(r, "Failed to get root control group path: %m");
                goto finish;
        }

        a = hashmap_new(&string_hash_ops);
        b = hashmap_new(&string_hash_ops);
        if (!a || !b) {
                r = log_oom();
                goto finish;
        }

        signal(SIGWINCH, columns_lines_cache_reset);

        if (arg_iterations == (unsigned) -1)
                arg_iterations = on_tty() ? 0 : 1;

        while (!quit) {
                Hashmap *c;
                usec_t t;
                char key;
                char h[FORMAT_TIMESPAN_MAX];

                t = now(CLOCK_MONOTONIC);

                if (t >= last_refresh + arg_delay || immediate_refresh) {

                        r = refresh(root, a, b, iteration++);
                        if (r < 0) {
                                log_error_errno(r, "Failed to refresh: %m");
                                goto finish;
                        }

                        group_hashmap_clear(b);

                        c = a;
                        a = b;
                        b = c;

                        last_refresh = t;
                        immediate_refresh = false;
                }

                display(b);

                if (arg_iterations && iteration >= arg_iterations)
                        break;

                if (!on_tty()) /* non-TTY: Empty newline as delimiter between polls */
                        fputs("\n", stdout);
                fflush(stdout);

                if (arg_batch)
                        (void) usleep(last_refresh + arg_delay - t);
                else {
                        r = read_one_char(stdin, &key, last_refresh + arg_delay - t, NULL);
                        if (r == -ETIMEDOUT)
                                continue;
                        if (r < 0) {
                                log_error_errno(r, "Couldn't read key: %m");
                                goto finish;
                        }
                }

                if (on_tty()) { /* TTY: Clear any user keystroke */
                        fputs("\r \r", stdout);
                        fflush(stdout);
                }

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

                case 'k':
                        arg_count = arg_count != COUNT_ALL_PROCESSES ? COUNT_ALL_PROCESSES : COUNT_PIDS;
                        fprintf(stdout, "\nCounting: %s.", counting_what());
                        fflush(stdout);
                        sleep(1);
                        break;

                case 'P':
                        arg_count = arg_count != COUNT_USERSPACE_PROCESSES ? COUNT_USERSPACE_PROCESSES : COUNT_PIDS;
                        fprintf(stdout, "\nCounting: %s.", counting_what());
                        fflush(stdout);
                        sleep(1);
                        break;

                case 'r':
                        if (arg_count == COUNT_PIDS)
                                fprintf(stdout, "\n\aCannot toggle recursive counting, not available in task counting mode.");
                        else {
                                arg_recursive = !arg_recursive;
                                fprintf(stdout, "\nRecursive process counting: %s", yes_no(arg_recursive));
                        }
                        fflush(stdout);
                        sleep(1);
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

#define ON ANSI_HIGHLIGHT
#define OFF ANSI_NORMAL

                        fprintf(stdout,
                                "\t<" ON "p" OFF "> By path; <" ON "t" OFF "> By tasks/procs; <" ON "c" OFF "> By CPU; <" ON "m" OFF "> By memory; <" ON "i" OFF "> By I/O\n"
                                "\t<" ON "+" OFF "> Inc. delay; <" ON "-" OFF "> Dec. delay; <" ON "%%" OFF "> Toggle time; <" ON "SPACE" OFF "> Refresh\n"
                                "\t<" ON "P" OFF "> Toggle count userspace processes; <" ON "k" OFF "> Toggle count all processes\n"
                                "\t<" ON "r" OFF "> Count processes recursively; <" ON "q" OFF "> Quit");
                        fflush(stdout);
                        sleep(3);
                        break;

                default:
                        if (key < ' ')
                                fprintf(stdout, "\nUnknown key '\\x%x'. Ignoring.", key);
                        else
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

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
