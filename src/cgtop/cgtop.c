/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-future.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "cpu-set-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "hashmap.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "procfs-util.h"
#include "signal-util.h"
#include "sort-util.h"
#include "string-table.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "utf8.h"
#include "verbs.h"
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
        COLUMN_PATH      = ORDER_PATH,
        COLUMN_TASKS     = ORDER_TASKS,
        COLUMN_CPU       = ORDER_CPU,
        COLUMN_MEMORY    = ORDER_MEMORY,
        COLUMN_IO_INPUT  = ORDER_IO,
        COLUMN_IO_OUTPUT = _ORDER_MAX,
        _COLUMN_MAX,
        _COLUMN_INVALID  = -EINVAL,
} Column;

typedef enum {
        CPU_PERCENTAGE,
        CPU_TIME,
        _CPU_MAX,
        _CPU_INVALID = -EINVAL,
} CPUType;

typedef struct Context {
        sd_future *fiber;
        sd_event_source *signal_sources[3]; /* SIGWINCH, SIGTSTP, SIGCONT */

        char *root;
        Hashmap *groups_by_path;

        /* Running sum of memory.current across depth-1 children, filled in by
         * process() during the refresh() walk and consumed by display() for
         * the root row when arg_root_memory_mode == ROOT_MEMORY_CGROUP. */
        uint64_t root_children_memory_sum;

        unsigned iteration;
        usec_t last_refresh;
        bool immediate_refresh;

        char **message;
        usec_t message_lifetime;

        usec_t next_display;

        int poll_fd;

        struct termios saved_termios;
        bool termios_saved;
} Context;

#define DEFAULT_MAXIMUM_DEPTH 3

static unsigned arg_depth = DEFAULT_MAXIMUM_DEPTH;
static unsigned arg_iterations = UINT_MAX;
static bool arg_batch = false;
static bool arg_raw = false;
static usec_t arg_delay = 1*USEC_PER_SEC;
static const char *arg_machine = NULL;
static char *arg_root = NULL;
static bool arg_recursive = true;
static bool arg_recursive_unset = false;
static PidsCount arg_count = COUNT_PIDS;
static Order arg_order = ORDER_CPU;
static CPUType arg_cpu_type = CPU_PERCENTAGE;
static bool arg_root_memory_system = false; /* false — default, sum of memory.current over direct children, */
                                            /* true — whole system, /proc/meminfo (MemTotal - MemAvailable) */

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);

COMMAND(
        "systemd-cgtop\0",
        "Show top control groups by their resource usage.",
        .argspec = "[CGROUP]\0",
        .man_pages = "systemd-cgtop(1)\0",
);

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

static void save_console(Context *c) {
        assert(c);

        if (c->termios_saved)
                return;

        if (tcgetattr(STDIN_FILENO, &c->saved_termios) >= 0)
                c->termios_saved = true;
}

static int modify_console(Context *c) {
        assert(c);

        if (!c->termios_saved)
                return 0;

        struct termios t = c->saved_termios;
        termios_disable_echo(&t);
        return RET_NERRNO(tcsetattr(STDIN_FILENO, TCSANOW, &t));
}

static void restore_console(Context *c) {
        assert(c);

        if (!c->termios_saved)
                return;

        (void) tcsetattr(STDIN_FILENO, TCSANOW, &c->saved_termios);
}

static void context_done(Context *c) {
        assert(c);

        restore_console(c);

        /* We live on the stack of the main fiber, but the event loop is not ours: it is the default one,
         * which outlives us. Make sure that no handler can be invoked with a dangling pointer to us. */
        FOREACH_ELEMENT(s, c->signal_sources)
                *s = sd_event_source_disable_unref(*s);

        free(c->root);
        hashmap_free(c->groups_by_path);
        strv_free(c->message);
}

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

                r = cg_get_path(g->path, "memory.current", &p);
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

        r = cg_get_path(g->path, "io.stat", &p);
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
                uint64_t u;

                r = cg_get_keyed_attribute_uint64(g->path, "cpu.stat", "usage_usec", &u);
                if (IN_SET(r, -ENOENT, -ENXIO))
                        return 0;
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
                uint64_t *root_children_memory_sum,
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
                        r = cg_get_attribute_as_uint64(path, "pids.current", &g->n_tasks);
                        if (r < 0 && r != -ENODATA)
                                return r;
                        if (r >= 0 && g->n_tasks > 0)
                                g->n_tasks_valid = true;
                }

        } else
                assert_not_reached();

        r = process_memory(g);
        if (r < 0)
                return r;

        /* Accumulate depth-1 cgroup memory into the root sum as we go, so
         * display() can paint the root row in O(1). The caller (refresh()
         * at depth 0, itself called from loop()) owns the sum and resets
         * it at the start of each cycle. */
        if (root_children_memory_sum &&
            g->memory_valid && !is_root_cgroup(path) && !strchr(path, '/'))
                *root_children_memory_sum += g->memory;

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
                uint64_t *root_children_memory_sum,
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

        r = process(path, a, b, iteration, root_children_memory_sum, &ours);
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

                r = refresh(p, a, b, iteration, depth + 1, root_children_memory_sum, &child);
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
        const Group *x = *ASSERT_PTR(a), *y = *ASSERT_PTR(b);
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

static int table_add_bytes(Table *table, bool is_valid, uint64_t t) {
        if (!is_valid)
                return table_add_cell(table, /* ret_cell= */ NULL, TABLE_EMPTY, /* data= */ NULL);
        if (arg_raw)
                return table_add_cell(table, /* ret_cell= */ NULL, TABLE_UINT64, &t);

        return table_add_cell(table, /* ret_cell= */ NULL, TABLE_SIZE, &t);
}

static int display(Context *c) {
        int r;

        assert(c);

        _cleanup_(table_unrefp) Table *table = table_new(
                        "CGroup",
                        arg_count == COUNT_PIDS ? "Tasks" : arg_count == COUNT_USERSPACE_PROCESSES ? "Procs" : "Proc+",
                        arg_cpu_type == CPU_PERCENTAGE ? "%CPU" : "CPU Time",
                        "Memory", "Input/s", "Output/s");
        if (!table)
                return log_oom();

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        if (on_tty())
                table_set_width(table, columns());
        else
                table_set_header(table, false);

        for (Column col = 0; col < _COLUMN_MAX; col++) {
                TableCell *cell = ASSERT_PTR(table_get_cell(table, 0, col));

                (void) table_set_uppercase(table, cell, false);

                if (col == (Column) arg_order ||
                    (IN_SET(col, COLUMN_IO_INPUT, COLUMN_IO_OUTPUT) && arg_order == ORDER_IO))
                        (void) table_set_color(table, cell, ansi_highlight());

                switch (col) {
                case COLUMN_PATH:
                        (void) table_set_weight(table, cell, 100000);
                        (void) table_set_ellipsize_percent(table, cell, 33);
                        break;

                case COLUMN_TASKS:
                        (void) table_set_minimum_width(table, cell, 7);
                        (void) table_set_align_percent(table, cell, 100);
                        (void) table_set_ellipsize_percent(table, cell, 100);
                        break;

                case COLUMN_CPU: {
                        unsigned n_cpus = 16;
                        (void) cpus_online(&n_cpus);
                        (void) table_set_minimum_width(table, cell, DECIMAL_STR_WIDTH(n_cpus) + STRLEN("00.0"));
                        (void) table_set_align_percent(table, cell, 100);
                        (void) table_set_ellipsize_percent(table, cell, 100);
                        break;
                }
                case COLUMN_MEMORY:
                case COLUMN_IO_INPUT:
                case COLUMN_IO_OUTPUT:
                        (void) table_set_minimum_width(table, cell, 8);
                        (void) table_set_align_percent(table, cell, 100);
                        (void) table_set_ellipsize_percent(table, cell, 100);
                        break;

                default:
                        assert_not_reached();
                }
        }

        Group **array = newa(Group*, hashmap_size(c->groups_by_path));

        unsigned n = 0;
        Group *g;
        HASHMAP_FOREACH(g, c->groups_by_path)
                if (g->n_tasks_valid || g->cpu_valid || g->memory_valid || g->io_valid)
                        array[n++] = g;

        typesafe_qsort(array, n, group_compare);

        unsigned rows = lines();
        if (rows <= 10)
                rows = 10;

        /* Keep lines for message and table header. */
        unsigned m = strv_length(c->message) + !strv_isempty(c->message) + on_tty() + 1;

        for (unsigned j = 0; j < n; j++) {
                if (on_tty() && j + m >= rows)
                        break;

                g = array[j];

                _cleanup_free_ char *escaped = utf8_escape_non_printable(empty_to_root(g->path));
                if (!escaped)
                        return log_oom();

                r = table_add_cell(table, /* ret_cell= */ NULL, TABLE_PATH, escaped);
                if (r < 0)
                        return table_log_add_error(r);

                if (g->n_tasks_valid)
                        r = table_add_cell(table, /* ret_cell= */ NULL, TABLE_UINT64, &g->n_tasks);
                else
                        r = table_add_cell(table, /* ret_cell= */ NULL, TABLE_EMPTY, /* data= */ NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (arg_cpu_type == CPU_PERCENTAGE) {
                        if (g->cpu_valid)
                                r = table_add_many(
                                                table,
                                                TABLE_DOUBLE, g->cpu_fraction * 100,
                                                TABLE_SET_DECIMALS, 1);
                        else
                                r = table_add_cell(table, /* ret_cell= */ NULL, TABLE_EMPTY, /* data= */ NULL);
                } else
                        r = table_add_many(
                                        table,
                                        arg_raw ? TABLE_UINT64 : TABLE_TIMESPAN,
                                        g->cpu_usage / NSEC_PER_USEC);
                if (r < 0)
                        return table_log_add_error(r);

                if (is_root_cgroup(g->path) && arg_root_memory_system) {
                        g->memory = c->root_children_memory_sum;
                        g->memory_valid = true;
                }

                r = table_add_bytes(table, g->memory_valid, g->memory);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_bytes(table, g->io_valid, g->io_input_bps);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_bytes(table, g->io_valid, g->io_output_bps);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!terminal_is_dumb())
                fputs(ANSI_HOME_CLEAR, stdout);

        r = table_print(table);
        if (r < 0)
                return table_log_print_error(r);

        STRV_FOREACH(s, c->message) {
                fputs("\n", stdout);
                fputs(*s, stdout);
        }

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 1);
        assert(argv);

        OptionParser opts = { argc, argv };
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("order", "PROPERTY",
                            "Order by specified property (path, tasks, cpu, memory, io)"):
                        arg_order = order_from_string(opts.arg);
                        if (arg_order < 0)
                                return log_error_errno(arg_order,
                                                       "Invalid argument to --order=: %s",
                                                       opts.arg);
                        break;

                OPTION_SHORT('p', NULL, "Same as --order=path, order by path"):
                        arg_order = ORDER_PATH;
                        break;

                OPTION_SHORT('t', NULL, "Same as --order=tasks, order by number of tasks/processes"):
                        arg_order = ORDER_TASKS;
                        break;

                OPTION_SHORT('c', NULL, "Same as --order=cpu, order by CPU load"):
                        arg_order = ORDER_CPU;
                        break;

                OPTION_SHORT('m', NULL, "Same as --order=memory, order by memory load"):
                        arg_order = ORDER_MEMORY;
                        break;

                OPTION_SHORT('i', NULL, "Same as --order=io, order by IO load"):
                        arg_order = ORDER_IO;
                        break;

                OPTION('r', "raw", NULL, "Provide raw (not human-readable) numbers"):
                        arg_raw = true;
                        break;

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "cpu", "percentage|time",
                                  "Show CPU usage as percentage (default) or time"):
                        if (opts.arg) {
                                arg_cpu_type = cpu_type_from_string(opts.arg);
                                if (arg_cpu_type < 0)
                                        return log_error_errno(arg_cpu_type,
                                                               "Unknown argument to --cpu=: %s",
                                                               opts.arg);
                        } else
                                arg_cpu_type = CPU_TIME;
                        break;

                OPTION_SHORT('P', NULL, "Count userspace processes instead of tasks (excl. kernel)"):
                        arg_count = COUNT_USERSPACE_PROCESSES;
                        break;

                OPTION_SHORT('k', NULL, "Count all processes instead of tasks (incl. kernel)"):
                        arg_count = COUNT_ALL_PROCESSES;
                        break;

                OPTION_LONG("recursive", "BOOL", "Sum up process count recursively"):
                        r = parse_boolean_argument("--recursive=", opts.arg, &arg_recursive);
                        if (r < 0)
                                return r;

                        arg_recursive_unset = !r;
                        break;

                OPTION('d', "delay", "DELAY", "Delay between updates"):
                        r = parse_sec(opts.arg, &arg_delay);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse delay parameter '%s': %m", opts.arg);
                        if (arg_delay <= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid delay parameter '%s'",
                                                       opts.arg);
                        break;

                OPTION('n', "iterations", "N", "Run for N iterations before exiting"):
                        r = safe_atou(opts.arg, &arg_iterations);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse iterations parameter '%s': %m", opts.arg);
                        break;

                OPTION_SHORT('1', NULL, "Shortcut for --iterations=1"):
                        arg_iterations = 1;
                        break;

                OPTION('b', "batch", NULL, "Run in batch mode, accepting no input"):
                        arg_batch = true;
                        break;

                OPTION_LONG("depth", "DEPTH",
                            "Maximum traversal depth (default: "STRINGIFY(DEFAULT_MAXIMUM_DEPTH)")"):
                        r = safe_atou(opts.arg, &arg_depth);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse depth parameter '%s': %m", opts.arg);
                        break;

                OPTION_LONG("root-memory", "MODE",
                            "Root row memory source (cgroup|system, default: cgroup)"):
                        if (streq(opts.arg, "cgroup"))
                                arg_root_memory_system = false;
                        else if (streq(opts.arg, "system"))
                                arg_root_memory_system = true;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid argument to --root-memory=: %s", opts.arg);
                        break;

                OPTION_COMMON_MACHINE:
                        arg_machine = opts.arg;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        size_t n_args = option_parser_get_n_args(&opts);
        if (n_args > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too many arguments.");
        if (n_args == 1) {
                const char *p = option_parser_get_args(&opts)[0];
                r = path_simplify_alloc(p, &arg_root);
                if (r < 0)
                        return log_oom();

                if (!path_is_normalized(arg_root))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "CGroup path '%s' cannot be normalized.", p);
        }

        return 1;
}

static int step(Context *c, usec_t t) {
        int r;

        assert(c);

        if (t >= usec_add(c->last_refresh, arg_delay) || c->immediate_refresh) {

                c->root_children_memory_sum = 0;

                _cleanup_hashmap_free_ Hashmap *previous = TAKE_PTR(c->groups_by_path);
                c->groups_by_path = hashmap_new(&group_hash_ops);
                if (!c->groups_by_path)
                        return log_oom();

                r = refresh(c->root, c->groups_by_path, previous, c->iteration++, /* depth= */ 0,
                            &c->root_children_memory_sum, /* ret= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to refresh: %m");

                c->last_refresh = t;
                c->immediate_refresh = false;
        }

        if (c->message_lifetime > 0 && c->message_lifetime <= t) {
                c->message = strv_free(c->message);
                c->message_lifetime = 0;
        }

        r = display(c);
        if (r < 0)
                return r;

        c->next_display = MIN(usec_add(c->last_refresh, arg_delay), c->message_lifetime ?: USEC_INFINITY);

        if (arg_iterations > 0 && c->iteration >= arg_iterations)
                return 0; /* finished */

        if (!on_tty()) /* non-TTY: Empty newline as delimiter between polls */
                fputs("\n", stdout);
        fflush(stdout);

        return 1;
}

static int redisplay(Context *c) {
        assert(c);

        c->next_display = 0;

        /* Only for the event source handlers below, which don't run on a fiber: the main fiber is suspended
         * in sd_fiber_ppoll() at this point, wake it up so that it looks at next_display again. The fiber
         * sees -EBUSY for such an unrelated wakeup. If it is not suspended (anymore), it looks at
         * next_display before it suspends the next time anyway, so a lost wakeup costs nothing. */
        return sd_fiber_resume(c->fiber, 0);
}

static int on_sigwinch(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        assert(si);
        assert(si->ssi_signo == SIGWINCH);

        columns_lines_cache_reset(si->ssi_signo);

        return redisplay(c);
}

static int on_sigtstp(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(si);
        assert(si->ssi_signo == SIGTSTP);

        /* restore console setting before raising SIGTSTP */
        restore_console(c);

        r = sigprocmask_many(SIG_UNBLOCK, /* ret_old_mask= */ NULL, SIGTSTP);
        if (r < 0)
                return sd_event_exit(sd_event_source_get_event(s), log_error_errno(r, "Failed to unblock SIGTSTP: %m"));

        if (raise(SIGTSTP) < 0)
                log_debug_errno(errno, "Failed to raise SIGTSTP, ignoring: %m");

        r = sigprocmask_many(SIG_BLOCK, /* ret_old_mask= */ NULL, SIGTSTP);
        if (r < 0)
                return sd_event_exit(sd_event_source_get_event(s), log_error_errno(r, "Failed to block SIGTSTP: %m"));

        r = modify_console(c);
        if (r < 0)
                return sd_event_exit(sd_event_source_get_event(s), log_error_errno(r, "Failed to update terminfo: %m"));

        return redisplay(c);
}

static int on_sigcont(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(si);
        assert(si->ssi_signo == SIGCONT);

        columns_lines_cache_reset(si->ssi_signo);

        r = modify_console(c);
        if (r < 0)
                return sd_event_exit(sd_event_source_get_event(s), log_error_errno(r, "Failed to update terminfo: %m"));

        return redisplay(c);
}

static const char* counting_what(void) {
        if (arg_count == COUNT_PIDS)
                return "tasks";
        else if (arg_count == COUNT_ALL_PROCESSES)
                return "all processes (incl. kernel)";
        else
                return "userspace processes (excl. kernel)";
}

_printf_(3, 4)
static int set_message(Context *c, usec_t t, const char *format, ...) {
        _cleanup_free_ char *str = NULL;
        va_list ap;
        int r;

        assert(c);
        assert(format);

        va_start(ap, format);
        r = vasprintf(&str, format, ap);
        va_end(ap);
        if (r < 0)
                return log_oom();

        char **v = strv_split_newlines(str);
        if (!v)
                return log_oom();

        strv_free_and_replace(c->message, v);
        c->message_lifetime = usec_add(now(CLOCK_MONOTONIC), t);
        return 0;
}

static int on_key(Context *c, char key) {
        int r = 0;

        assert(c);

        /* Returns 0 if the user asked us to quit, and > 0 otherwise. */

        if (on_tty()) { /* TTY: Clear any user keystroke */
                fputs("\r \r", stdout);
                fflush(stdout);
        }

        switch (key) {

        case ' ':
                c->immediate_refresh = true;
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

        case '/':
                arg_root_memory_system = !arg_root_memory_system;
                c->immediate_refresh = true;
                break;

        case 'k':
                arg_count = arg_count != COUNT_ALL_PROCESSES ? COUNT_ALL_PROCESSES : COUNT_PIDS;
                r = set_message(c, USEC_PER_SEC, "Counting: %s.", counting_what());
                break;

        case 'P':
                arg_count = arg_count != COUNT_USERSPACE_PROCESSES ? COUNT_USERSPACE_PROCESSES : COUNT_PIDS;
                r = set_message(c, USEC_PER_SEC, "Counting: %s.", counting_what());
                break;

        case 'r':
                if (arg_count == COUNT_PIDS)
                        r = set_message(c, USEC_PER_SEC, "\aCannot toggle recursive counting, not available in task counting mode.");
                else {
                        arg_recursive = !arg_recursive;
                        r = set_message(c, USEC_PER_SEC, "Recursive process counting: %s", yes_no(arg_recursive));
                }
                break;

        case '+':
                arg_delay = usec_add(arg_delay, arg_delay < USEC_PER_SEC ? USEC_PER_MSEC * 250 : USEC_PER_SEC);
                r = set_message(c, USEC_PER_SEC, "Increased delay to %s.", FORMAT_TIMESPAN(arg_delay, 0));
                break;

        case '-':
                if (arg_delay <= USEC_PER_MSEC*500)
                        arg_delay = USEC_PER_MSEC*250;
                else
                        arg_delay = usec_sub_unsigned(arg_delay, arg_delay < USEC_PER_MSEC * 1250 ? USEC_PER_MSEC * 250 : USEC_PER_SEC);

                r = set_message(c, USEC_PER_SEC, "Decreased delay to %s.", FORMAT_TIMESPAN(arg_delay, 0));
                break;

        case '?':
        case 'h':
                r = set_message(c, 3 * USEC_PER_SEC,
                                "\t<%1$sp%2$s> By path; <%1$st%2$s> By tasks/procs; <%1$sc%2$s> By CPU; <%1$sm%2$s> By memory; <%1$si%2$s> By I/O\n"
                                "\t<%1$s+%2$s> Inc. delay; <%1$s-%2$s> Dec. delay; <%1$s%%%2$s> Toggle time; <%1$sSPACE%2$s> Refresh\n"
                                "\t<%1$sP%2$s> Toggle count userspace processes; <%1$sk%2$s> Toggle count all processes\n"
                                "\t<%1$sr%2$s> Count processes recursively; <%1$s/%2$s> Toggle root row (meminfo/cgroup sum); <%1$sq%2$s> Quit",
                                ansi_highlight(), ansi_normal());
                break;

        default:
                if (key < ' ')
                        r = set_message(c, USEC_PER_SEC, "Unknown key '\\x%x'. Ignoring.", (unsigned) key);
                else
                        r = set_message(c, USEC_PER_SEC, "Unknown key '%c'. Ignoring.", key);
        }
        if (r < 0)
                return r;

        c->next_display = 0;
        return 1;
}

static int loop(Context *c) {
        int r;

        assert(c);

        for (;;) {
                usec_t t = now(CLOCK_MONOTONIC);

                if (t >= c->next_display) {
                        r = step(c, t);
                        if (r <= 0)
                                return r;

                        t = now(CLOCK_MONOTONIC);
                }

                /* This waits for a key or for the next redraw, whichever comes first. A negative fd is
                 * ignored by poll(), which is how we deal with batch mode and EOF on stdin.
                 *
                 * Never pass a zero timeout here: the fiber would not suspend, hence the event loop would
                 * not run and signals (e.g. SIGINT) might not be processed, if redrawing takes longer than
                 * the delay. Hence wait at least 1 usec. */
                r = fd_wait_for_event(c->poll_fd, POLLIN, MAX(usec_sub_unsigned(c->next_display, t), 1u));
                if (r == -EBUSY)
                        continue; /* A signal handler called redisplay(). */
                if (r == -ECANCELED)
                        return r; /* SIGINT or SIGTERM */
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for stdin: %m");
                if (r == 0)
                        continue; /* Time to redraw. */

                /* The fd is ready, hence this does not block. We deliberately don't use sd_fiber_read()
                 * here, which would flip O_NONBLOCK on the terminal, which is shared with the shell. */

                assert(c->poll_fd >= 0);

                char key;
                ssize_t n = read(c->poll_fd, &key, 1);
                if (n < 0) {
                        if (ERRNO_IS_TRANSIENT(errno))
                                continue;

                        return log_error_errno(errno, "Failed to read from stdin: %m");
                }
                if (n == 0) { /* EOF */
                        c->poll_fd = -EBADF;
                        continue;
                }

                r = on_key(c, key);
                if (r <= 0)
                        return r;
        }
}

static int setup_loop(Context *c) {
        sd_event *e = ASSERT_PTR(sd_fiber_get_event());
        int r;

        assert(c);

        c->fiber = sd_fiber_get_current();

        r = sd_event_set_signal_exit(e, true);
        if (r < 0)
                return r;

        /* on terminal size change */
        r = sd_event_add_signal(e, &c->signal_sources[0], SIGWINCH | SD_EVENT_SIGNAL_PROCMASK, on_sigwinch, c);
        if (r < 0)
                return r;

        /* on Ctrl+z */
        r = sd_event_add_signal(e, &c->signal_sources[1], SIGTSTP | SD_EVENT_SIGNAL_PROCMASK, on_sigtstp, c);
        if (r < 0)
                return r;

        /* on continue */
        r = sd_event_add_signal(e, &c->signal_sources[2], SIGCONT | SD_EVENT_SIGNAL_PROCMASK, on_sigcont, c);
        if (r < 0)
                return r;

        if (c->poll_fd >= 0) {
                save_console(c);

                r = modify_console(c);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int run(int argc, char *argv[]) {
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

        _cleanup_(context_done) Context c = {
                .immediate_refresh = true,
                .poll_fd = arg_batch ? -EBADF : STDIN_FILENO,
        };

        r = show_cgroup_get_path_and_warn(arg_machine, skip_leading_chars(arg_root, "/"), &c.root);
        if (r < 0)
                return log_error_errno(r, "Failed to get root control group path: %m");
        log_debug("CGroup path: %s", c.root);

        if (arg_iterations == UINT_MAX)
                arg_iterations = on_tty() ? 0 : 1;

        if (arg_iterations == 1)
                return step(&c, /* t= */ 0);

        r = setup_loop(&c);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize event loop: %m");

        r = loop(&c);

        if (on_tty()) {
                fputs("\n", stdout);
                fflush(stdout);
        }

        return r;
}

DEFINE_MAIN_FUNCTION_FIBER(run);
