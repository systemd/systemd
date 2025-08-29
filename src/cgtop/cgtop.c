/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include "alloc-util.h"
#include "build.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "procfs-util.h"
#include "sort-util.h"
#include "string-table.h"
#include "terminal-util.h"
#include "time-util.h"
#include "virt.h"

typedef struct Group {
        char *path;

        bool n_tasks_valid;
        bool cpu_valid;
        bool memory_valid;
        bool io_valid;

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

/* Counted objects, enum order matters */
typedef enum PidsCount {
        COUNT_USERSPACE_PROCESSES,      /* least */
        COUNT_ALL_PROCESSES,
        COUNT_PIDS,                     /* most, requires pids controller */
} PidsCount;

typedef enum {
        ORDER_PATH,
        ORDER_TASKS,
        ORDER_CPU,
        ORDER_MEMORY,
        ORDER_IO,
        _ORDER_MAX,
        _ORDER_INVALID = -EINVAL,
} Order;

typedef enum {
        CPU_PERCENTAGE,
        CPU_TIME,
        _CPU_MAX,
        _CPU_INVALID = -EINVAL,
} CPUType;

static unsigned arg_depth = 3;
static unsigned arg_iterations = UINT_MAX;
static bool arg_batch = false;
static bool arg_raw = false;
static usec_t arg_delay = 1*USEC_PER_SEC;
static char* arg_machine = NULL;
static char* arg_root = NULL;
static bool arg_recursive = true;
static bool arg_recursive_unset = false;
static PidsCount arg_count = COUNT_PIDS;
static Order arg_order = ORDER_CPU;
static CPUType arg_cpu_type = CPU_PERCENTAGE;

static const char *order_table[_ORDER_MAX] = {
        [ORDER_PATH]   = "path",
        [ORDER_TASKS]  = "tasks",
        [ORDER_CPU]    = "cpu",
        [ORDER_MEMORY] = "memory",
        [ORDER_IO]     = "io",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(order, Order);

static const char *cpu_type_table[_CPU_MAX] = {
        [CPU_PERCENTAGE] = "percentage",
        [CPU_TIME]       = "time",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(cpu_type, CPUType);

static Group *group_free(Group *g) {
        if (!g)
                return NULL;

        free(g->path);
        return mfree(g);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(group_hash_ops, char, path_hash_func, path_compare, Group, group_free);

static const char *maybe_format_timespan(char *buf, size_t l, usec_t t, usec_t accuracy) {
        if (arg_raw) {
               (void) snprintf(buf, l, USEC_FMT, t);
               return buf;
        }
        return format_timespan(buf, l, t, accuracy);
}

#define BUFSIZE1 CONST_MAX(FORMAT_TIMESPAN_MAX, DECIMAL_STR_MAX(usec_t))
#define MAYBE_FORMAT_TIMESPAN(t, accuracy) \
        maybe_format_timespan((char[BUFSIZE1]){}, BUFSIZE1, t, accuracy)

static const char *maybe_format_bytes(char *buf, size_t l, bool is_valid, uint64_t t) {
        if (!is_valid)
                return "-";
        if (arg_raw) {
                (void) snprintf(buf, l, "%" PRIu64, t);
                return buf;
        }
        return format_bytes(buf, l, t);
}

#define BUFSIZE2 CONST_MAX(FORMAT_BYTES_MAX, DECIMAL_STR_MAX(uint64_t))
#define MAYBE_FORMAT_BYTES(is_valid, t) \
        maybe_format_bytes((char[BUFSIZE2]){}, BUFSIZE2, is_valid, t)

static bool is_root_cgroup(const char *path) {

        /* Returns true if the specified path belongs to the root cgroup. The root cgroup is special on cgroup v2 as it
         * carries only very few attributes in order not to export multiple truth about system state as most
         * information is available elsewhere in /proc anyway. We need to be able to deal with that, and need to get
         * our data from different sources in that case.
         *
         * There's one extra complication in all of this, though 😣: if the path to the cgroup indicates we are in the
         * root cgroup this might actually not be the case, because cgroup namespacing might be in effect
         * (CLONE_NEWCGROUP). Since there's no nice way to distinguish a real cgroup root from a fake namespaced one we
         * do an explicit container check here, under the assumption that CLONE_NEWCGROUP is generally used when
         * container managers are used too.
         *
         * Note that checking for a container environment is kinda ugly, since in theory people could use cgtop from
         * inside a container where cgroup namespacing is turned off to watch the host system. However, that's mostly a
         * theoretic use case, and if people actually try all they'll lose is accounting for the top-level cgroup. Which
         * isn't too bad. */

        if (detect_container() > 0)
                return false;

        return empty_or_root(path);
}

static int process_memory(Group *g) {
        int r;

        assert(g);

        if (is_root_cgroup(g->path))
                r = procfs_memory_get_used(&g->memory);
        else {
                _cleanup_free_ char *p = NULL, *v = NULL;

                r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, g->path, "memory.current", &p);
                if (r < 0)
                        return r;

                r = read_one_line_file(p, &v);
                if (r == -ENOENT)
                        return 0;
                if (r < 0)
                        return r;

                r = safe_atou64(v, &g->memory);
        }
        if (r < 0)
                return r;

        if (g->memory > 0)
                g->memory_valid = true;

        return 0;
}

static int process_io(Group *g, unsigned iteration) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        uint64_t wr = 0, rd = 0;
        nsec_t timestamp;
        int r;

        assert(g);

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, g->path, "io.stat", &p);
        if (r < 0)
                return r;

        f = fopen(p, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;
                uint64_t k;
                char *l;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Skip the device */
                l = line + strcspn(line, WHITESPACE);
                l += strspn(l, WHITESPACE);

                while (!isempty(l)) {
                        if (sscanf(l, "rbytes=%" SCNu64, &k) == 1)
                                rd += k;
                        else if (sscanf(l, "wbytes=%" SCNu64, &k) == 1)
                                wr += k;

                        l += strcspn(l, WHITESPACE);
                        l += strspn(l, WHITESPACE);
                }
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

        return 0;
}

static int process_cpu(Group *g, unsigned iteration) {
        nsec_t new_usage, timestamp;
        int r;

        assert(g);

        if (is_root_cgroup(g->path)) {
                r = procfs_cpu_get_usage(&new_usage);
                if (r < 0)
                        return r;
        } else {
                _cleanup_free_ char *val = NULL;
                uint64_t u;

                r = cg_get_keyed_attribute(g->path, "cpu.stat", STRV_MAKE("usage_usec"), &val);
                if (IN_SET(r, -ENOENT, -ENXIO))
                        return 0;
                if (r < 0)
                        return r;

                r = safe_atou64(val, &u);
                if (r < 0)
                        return r;

                new_usage = u * NSEC_PER_USEC;
        }

        timestamp = now_nsec(CLOCK_MONOTONIC);

        if (g->cpu_iteration == iteration - 1 && new_usage > g->cpu_usage) {
                nsec_t x, y;

                x = timestamp - g->cpu_timestamp;
                if (x < 1)
                        x = 1;

                y = new_usage - g->cpu_usage;
                g->cpu_fraction = (double) y / (double) x;
                g->cpu_valid = true;
        }

        g->cpu_usage = new_usage;
        g->cpu_timestamp = timestamp;
        g->cpu_iteration = iteration;

        return 0;
}

static int process(
                const char *path,
                Hashmap *a,
                Hashmap *b,
                unsigned iteration,
                Group **ret) {

        Group *g;
        int r;

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

        if (IN_SET(arg_count, COUNT_ALL_PROCESSES, COUNT_USERSPACE_PROCESSES)) {
                _cleanup_fclose_ FILE *f = NULL;
                pid_t pid;

                r = cg_enumerate_processes(path, &f);
                if (r < 0 && r != -ENOENT)
                        return r;
                if (r >= 0) {
                        g->n_tasks = 0;
                        while (cg_read_pid(f, &pid, CGROUP_DONT_SKIP_UNMAPPED) > 0) {

                                if (arg_count == COUNT_USERSPACE_PROCESSES && pid_is_kernel_thread(pid) > 0)
                                        continue;

                                g->n_tasks++;
                        }

                        if (g->n_tasks > 0)
                                g->n_tasks_valid = true;
                }

        } else if (arg_count == COUNT_PIDS) {

                if (is_root_cgroup(path)) {
                        r = procfs_tasks_get_current(&g->n_tasks);
                        if (r < 0)
                                return r;

                        g->n_tasks_valid = true;
                } else {
                        _cleanup_free_ char *p = NULL, *v = NULL;

                        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, path, "pids.current", &p);
                        if (r < 0)
                                return r;

                        r = read_one_line_file(p, &v);
                        if (r < 0 && r != -ENOENT)
                                return r;
                        if (r >= 0) {
                                r = safe_atou64(v, &g->n_tasks);
                                if (r < 0)
                                        return r;

                                if (g->n_tasks > 0)
                                        g->n_tasks_valid = true;
                        }
                }

        } else
                assert_not_reached();

        r = process_memory(g);
        if (r < 0)
                return r;

        r = process_io(g, iteration);
        if (r < 0)
                return r;

        r = process_cpu(g, iteration);
        if (r < 0)
                return r;

        if (ret)
                *ret = g;

        return 1;
}

static int refresh(
                const char *path,
                Hashmap *a,
                Hashmap *b,
                unsigned iteration,
                unsigned depth,
                Group **ret) {

        _cleanup_closedir_ DIR *d = NULL;
        Group *ours;
        int r;

        assert(path);
        assert(a);

        if (depth > arg_depth) {
                if (ret)
                        *ret = NULL;
                return 0;
        }

        r = process(path, a, b, iteration, &ours);
        if (r < 0)
                return r;

        r = cg_enumerate_subgroups(path, &d);
        if (r == -ENOENT) {
                if (ret)
                        *ret = NULL;
                return 0;
        }
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *fn = NULL, *p = NULL;
                Group *child;

                r = cg_read_subgroup(d, &fn);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                p = path_join(path, fn);
                if (!p)
                        return -ENOMEM;

                path_simplify(p);

                r = refresh(p, a, b, iteration, depth + 1, &child);
                if (r < 0)
                        return r;
                if (r > 0 &&
                    arg_recursive &&
                    IN_SET(arg_count, COUNT_ALL_PROCESSES, COUNT_USERSPACE_PROCESSES) &&
                    child->n_tasks_valid) {

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

static int group_compare(Group * const *a, Group * const *b) {
        const Group *x = *a, *y = *b;
        int r;

        if (arg_order != ORDER_TASKS || arg_recursive) {
                /* Let's make sure that the parent is always before
                 * the child. Except when ordering by tasks and
                 * recursive summing is off, since that is actually
                 * not accumulative for all children. */

                if (path_startswith(empty_to_root(y->path), empty_to_root(x->path)))
                        return -1;
                if (path_startswith(empty_to_root(x->path), empty_to_root(y->path)))
                        return 1;
        }

        switch (arg_order) {

        case ORDER_PATH:
                break;

        case ORDER_CPU:
                if (arg_cpu_type == CPU_PERCENTAGE) {
                        if (x->cpu_valid && y->cpu_valid) {
                                r = CMP(y->cpu_fraction, x->cpu_fraction);
                                if (r != 0)
                                        return r;
                        } else if (x->cpu_valid)
                                return -1;
                        else if (y->cpu_valid)
                                return 1;
                } else {
                        r = CMP(y->cpu_usage, x->cpu_usage);
                        if (r != 0)
                                return r;
                }

                break;

        case ORDER_TASKS:
                if (x->n_tasks_valid && y->n_tasks_valid) {
                        r = CMP(y->n_tasks, x->n_tasks);
                        if (r != 0)
                                return r;
                } else if (x->n_tasks_valid)
                        return -1;
                else if (y->n_tasks_valid)
                        return 1;

                break;

        case ORDER_MEMORY:
                if (x->memory_valid && y->memory_valid) {
                        r = CMP(y->memory, x->memory);
                        if (r != 0)
                                return r;
                } else if (x->memory_valid)
                        return -1;
                else if (y->memory_valid)
                        return 1;

                break;

        case ORDER_IO:
                if (x->io_valid && y->io_valid) {
                        r = CMP(y->io_input_bps + y->io_output_bps, x->io_input_bps + x->io_output_bps);
                        if (r != 0)
                                return r;
                } else if (x->io_valid)
                        return -1;
                else if (y->io_valid)
                        return 1;

                break;

        case _ORDER_MAX:
        case _ORDER_INVALID:
                assert_not_reached();
        }

        return path_compare(x->path, y->path);
}

static void display(Hashmap *a) {
        Group *g;
        Group **array;
        signed path_columns;
        unsigned rows, n = 0, maxtcpu = 0, maxtpath = 3; /* 3 for ellipsize() to work properly */

        assert(a);

        if (!terminal_is_dumb())
                fputs(ANSI_HOME_CLEAR, stdout);

        array = newa(Group*, hashmap_size(a));

        HASHMAP_FOREACH(g, a)
                if (g->n_tasks_valid || g->cpu_valid || g->memory_valid || g->io_valid)
                        array[n++] = g;

        typesafe_qsort(array, n, group_compare);

        /* Find the longest names in one run */
        for (unsigned j = 0; j < n; j++) {
                maxtcpu = MAX(maxtcpu,
                              strlen(MAYBE_FORMAT_TIMESPAN((usec_t) (array[j]->cpu_usage / NSEC_PER_USEC), 0)));
                maxtpath = MAX(maxtpath,
                               strlen(array[j]->path));
        }

        rows = lines();
        if (rows <= 10)
                rows = 10;

        if (on_tty()) {
                const char *on, *off;
                int cpu_len = arg_cpu_type == CPU_PERCENTAGE ? 6 : maxtcpu;

                path_columns = columns() - 36 - cpu_len;
                if (path_columns < 10)
                        path_columns = 10;

                on = ansi_highlight_underline();
                off = ansi_underline();

                printf("%s%s%-*s%s %s%7s%s %s%*s%s %s%8s%s %s%8s%s %s%8s%s%s\n",
                       ansi_underline(),
                       arg_order == ORDER_PATH ? on : "", path_columns, "CGroup",
                       arg_order == ORDER_PATH ? off : "",
                       arg_order == ORDER_TASKS ? on : "",
                       arg_count == COUNT_PIDS ? "Tasks" : arg_count == COUNT_USERSPACE_PROCESSES ? "Procs" : "Proc+",
                       arg_order == ORDER_TASKS ? off : "",
                       arg_order == ORDER_CPU ? on : "",
                       cpu_len,
                       arg_cpu_type == CPU_PERCENTAGE ? "%CPU" : "CPU Time",
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

        for (unsigned j = 0; j < n; j++) {
                _cleanup_free_ char *ellipsized = NULL;
                const char *path;

                if (on_tty() && j + 6 > rows)
                        break;

                g = array[j];

                path = empty_to_root(g->path);
                ellipsized = ellipsize(path, path_columns, 33);
                printf("%-*s", path_columns, ellipsized ?: path);

                if (g->n_tasks_valid)
                        printf(" %7" PRIu64, g->n_tasks);
                else
                        fputs("       -", stdout);

                if (arg_cpu_type == CPU_PERCENTAGE) {
                        if (g->cpu_valid)
                                printf(" %6.1f", g->cpu_fraction*100);
                        else
                                fputs("      -", stdout);
                } else
                        printf(" %*s",
                               (int) maxtcpu,
                               MAYBE_FORMAT_TIMESPAN((usec_t) (g->cpu_usage / NSEC_PER_USEC), 0));

                printf(" %8s", MAYBE_FORMAT_BYTES(g->memory_valid, g->memory));
                printf(" %8s", MAYBE_FORMAT_BYTES(g->io_valid, g->io_input_bps));
                printf(" %8s", MAYBE_FORMAT_BYTES(g->io_valid, g->io_output_bps));

                putchar('\n');
        }
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-cgtop", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [CGROUP]\n\n"
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
               "  -1                  Shortcut for --iterations=1\n"
               "  -b --batch          Run in batch mode, accepting no input\n"
               "     --depth=DEPTH    Maximum traversal depth (default: %u)\n"
               "  -M --machine=       Show container\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               arg_depth,
               link);

        return 0;
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

        int c, r;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hptcmin:brd:kPM:1", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_CPU_TYPE:
                        if (optarg) {
                                arg_cpu_type = cpu_type_from_string(optarg);
                                if (arg_cpu_type < 0)
                                        return log_error_errno(arg_cpu_type,
                                                               "Unknown argument to --cpu=: %s",
                                                               optarg);
                        } else
                                arg_cpu_type = CPU_TIME;

                        break;

                case ARG_DEPTH:
                        r = safe_atou(optarg, &arg_depth);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse depth parameter '%s': %m", optarg);

                        break;

                case 'd':
                        r = parse_sec(optarg, &arg_delay);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse delay parameter '%s': %m", optarg);
                        if (arg_delay <= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid delay parameter '%s'",
                                                       optarg);

                        break;

                case 'n':
                        r = safe_atou(optarg, &arg_iterations);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse iterations parameter '%s': %m", optarg);

                        break;

                case '1':
                        arg_iterations = 1;
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
                        arg_order = order_from_string(optarg);
                        if (arg_order < 0)
                                return log_error_errno(arg_order,
                                                       "Invalid argument to --order=: %s",
                                                       optarg);
                        break;

                case 'k':
                        arg_count = COUNT_ALL_PROCESSES;
                        break;

                case 'P':
                        arg_count = COUNT_USERSPACE_PROCESSES;
                        break;

                case ARG_RECURSIVE:
                        r = parse_boolean_argument("--recursive=", optarg, &arg_recursive);
                        if (r < 0)
                                return r;

                        arg_recursive_unset = !r;
                        break;

                case 'M':
                        arg_machine = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind == argc - 1)
                arg_root = argv[optind];
        else if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too many arguments.");

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

static int loop(const char *root) {
        _cleanup_hashmap_free_ Hashmap *a = NULL, *b = NULL;
        unsigned iteration = 0;
        usec_t last_refresh = 0;
        bool immediate_refresh = false;
        int r;

        a = hashmap_new(&group_hash_ops);
        b = hashmap_new(&group_hash_ops);
        if (!a || !b)
                return log_oom();

        for (;;) {
                usec_t t;
                char key;

                t = now(CLOCK_MONOTONIC);

                if (t >= usec_add(last_refresh, arg_delay) || immediate_refresh) {

                        r = refresh(root, a, b, iteration++, /* depth = */ 0, /* ret = */ NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to refresh: %m");

                        hashmap_clear(b);
                        SWAP_TWO(a, b);

                        last_refresh = t;
                        immediate_refresh = false;
                }

                display(b);

                if (arg_iterations && iteration >= arg_iterations)
                        return 0;

                if (!on_tty()) /* non-TTY: Empty newline as delimiter between polls */
                        fputs("\n", stdout);
                fflush(stdout);

                if (arg_batch)
                        (void) usleep_safe(usec_add(usec_sub_unsigned(last_refresh, t), arg_delay));
                else {
                        r = read_one_char(stdin, &key, usec_add(usec_sub_unsigned(last_refresh, t), arg_delay), /* echo= */ false, /* need_nl= */ NULL);
                        if (r == -ETIMEDOUT)
                                continue;
                        if (r < 0)
                                return log_error_errno(r, "Couldn't read key: %m");
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
                        return 0;

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
                        arg_cpu_type = arg_cpu_type == CPU_TIME ? CPU_PERCENTAGE : CPU_TIME;
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
                        arg_delay = usec_add(arg_delay, arg_delay < USEC_PER_SEC ? USEC_PER_MSEC * 250 : USEC_PER_SEC);

                        fprintf(stdout, "\nIncreased delay to %s.", FORMAT_TIMESPAN(arg_delay, 0));
                        fflush(stdout);
                        sleep(1);
                        break;

                case '-':
                        if (arg_delay <= USEC_PER_MSEC*500)
                                arg_delay = USEC_PER_MSEC*250;
                        else
                                arg_delay = usec_sub_unsigned(arg_delay, arg_delay < USEC_PER_MSEC * 1250 ? USEC_PER_MSEC * 250 : USEC_PER_SEC);

                        fprintf(stdout, "\nDecreased delay to %s.", FORMAT_TIMESPAN(arg_delay, 0));
                        fflush(stdout);
                        sleep(1);
                        break;

                case '?':
                case 'h':

                        fprintf(stdout,
                                "\t<%1$sp%2$s> By path; <%1$st%2$s> By tasks/procs; <%1$sc%2$s> By CPU; <%1$sm%2$s> By memory; <%1$si%2$s> By I/O\n"
                                "\t<%1$s+%2$s> Inc. delay; <%1$s-%2$s> Dec. delay; <%1$s%%%2$s> Toggle time; <%1$sSPACE%2$s> Refresh\n"
                                "\t<%1$sP%2$s> Toggle count userspace processes; <%1$sk%2$s> Toggle count all processes\n"
                                "\t<%1$sr%2$s> Count processes recursively; <%1$sq%2$s> Quit",
                                ansi_highlight(), ansi_normal());
                        fflush(stdout);
                        sleep(3);
                        break;

                default:
                        if (key < ' ')
                                fprintf(stdout, "\nUnknown key '\\x%x'. Ignoring.", (unsigned) key);
                        else
                                fprintf(stdout, "\nUnknown key '%c'. Ignoring.", key);
                        fflush(stdout);
                        sleep(1);
                }
        }
}

static int run(int argc, char *argv[]) {
        _cleanup_free_ char *root = NULL;
        CGroupMask mask;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = cg_mask_supported(&mask);
        if (r < 0)
                return log_error_errno(r, "Failed to determine supported controllers: %m");

        /* honor user selection unless pids controller is unavailable */
        PidsCount possible_count = (mask & CGROUP_MASK_PIDS) ? COUNT_PIDS : COUNT_ALL_PROCESSES;
        arg_count = MIN(possible_count, arg_count);

        if (arg_recursive_unset && arg_count == COUNT_PIDS)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Non-recursive counting is only supported when counting processes, not tasks. Use -P or -k.");

        r = show_cgroup_get_path_and_warn(arg_machine, arg_root, &root);
        if (r < 0)
                return log_error_errno(r, "Failed to get root control group path: %m");
        log_debug("CGroup path: %s", root);

        signal(SIGWINCH, columns_lines_cache_reset);

        if (arg_iterations == UINT_MAX)
                arg_iterations = on_tty() ? 0 : 1;

        return loop(root);
}

DEFINE_MAIN_FUNCTION(run);
