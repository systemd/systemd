/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <unistd.h>

#include "alloc-util.h"
#include "build.h"
#include "conf-files.h"
#include "constants.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro-fundamental.h"
#include "macro.h"
#include "main-func.h"
#include "module-util.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "strv.h"

struct ModulesList {
        char **modules;
        unsigned num_modules;
};

static char **arg_proc_cmdline_modules = NULL;
static const char conf_file_dirs[] = CONF_PATHS_NULSTR("modules-load.d");

STATIC_DESTRUCTOR_REGISTER(arg_proc_cmdline_modules, strv_freep);

static int modules_list_append_take(struct ModulesList *list, char **modp) {
        _cleanup_free_ char *mod = NULL;
        char **m;

        assert(list);
        assert(modp);

        /* kmod will do it nayway later, so replace now dashes with
           underscores to detect duplications due to different spelling. */
        mod = string_replace_char(TAKE_PTR(*modp), '-', '_');

        /* Avoid duplicates */
        FOREACH_ARRAY(mn, list->modules, list->num_modules)
                if (streq_ptr(mod, *mn))
                        return 0;

        /* Add one element to the end of the list */
        m = reallocarray(list->modules, list->num_modules + 1, sizeof(char *));
        if (!m)
                return log_oom();

        list->modules = TAKE_PTR(m);

        list->modules[list->num_modules] = TAKE_PTR(mod);
        list->num_modules++;

        return 0;
}

static int modules_list_append_dup(struct ModulesList *list, const char *module) {
        _cleanup_free_ char *m = NULL;
        int r;

        assert(module);

        r = strdup_to(&m, module);
        if (r < 0)
                return r;

        return modules_list_append_take(list, &m);
}

static void module_list_free(struct ModulesList *list) {
        assert(list);

        FOREACH_ARRAY(i, list->modules, list->num_modules)
                free(*i);

        list->num_modules = 0;
        mfree(list->modules);
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        if (proc_cmdline_key_streq(key, "modules_load")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = strv_split_and_extend(&arg_proc_cmdline_modules, value, ",", /* filter_duplicates = */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse modules_load= kernel command line option: %m");
        }

        return 0;
}

static int apply_file(FILE *f, const char *filename, struct ModulesList *list) {
        int ret = 0, r;

        assert(f);

        log_debug("apply: %s", filename);
        for (;;) {
                _cleanup_free_ char *line = NULL;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read file '%s': %m", filename);
                if (r == 0)
                        break;

                if (isempty(line))
                        continue;
                if (strchr(COMMENTS, *line))
                        continue;

                r = modules_list_append_take(list, &line);
                if (r < 0)
                        RET_GATHER(ret, log_error_errno(r, "Failed to add module '%s': %m", line));
                else
                        log_debug("Added module '%s' to probe list", line);
        }

        return ret;
}

static int apply_file_from_path(const char *path, struct ModulesList *list) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *pp = NULL;
        int r;

        assert(path);

        r = search_and_fopen_nulstr(path, "re", NULL, conf_file_dirs, &f, &pp);
        if (r < 0)
                return log_error_errno(r, "Failed to open %s: %m", path);

        return apply_file(f, pp, list);
}

static int apply_conf_file(ConfFile *c, struct ModulesList *list) {
        _cleanup_fclose_ FILE *f = NULL;

        f = fopen(FORMAT_PROC_FD_PATH(c->fd), "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", c->original_path);
        }

        return apply_file(f, c->original_path, list);
}

static int run_prober(const struct ModulesList * const list) {
        _cleanup_(sym_kmod_unrefp) struct kmod_ctx *ctx = NULL;
        static atomic_uint list_idx = 0;
        int ret = 0, r;

        r = module_setup_context(&ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize libkmod context: %m");

        for (;;) {
                /* Fetch the next index through an atomic operation which also increments
                   the shared "current index" indicator. If the index is past the end of
                   the list of modules, the prober can terminate.
                   This assumes that struct ModulesList element does not change during
                   the entire probe operation. */
                unsigned idx = atomic_fetch_add(&list_idx, 1);
                if (idx >= list->num_modules)
                        break;

                r = module_load_and_warn(ctx, list->modules[idx], true);
                if (r != -ENOENT)
                        RET_GATHER(ret, r);
        }

        return ret;
}

static void *prober_thread(void *arg) {
        const struct ModulesList * const mod_list = (const struct ModulesList * const) arg;
        return INT_TO_PTR(run_prober(mod_list));
}

static int create_worker_threads(
                unsigned num_threads,
                void *arg,
                pthread_t **ret_threads,
                unsigned *ret_num_threads) {
        _cleanup_free_ pthread_t *new_threads = NULL;
        unsigned created_threads;
        sigset_t ss, saved_ss;
        int r;

        assert(ret_threads);
        assert(ret_num_threads);

        *ret_num_threads = 0;

        if (num_threads == 0)
                return 0;

        /* Create worker threads with masked signals */
        new_threads = new(pthread_t, num_threads);
        if (!new_threads)
                return log_oom();

        /* No signals in worker threads. */
        assert_se(sigfillset(&ss) >= 0);
        r = pthread_sigmask(SIG_BLOCK, &ss, &saved_ss);
        if (r != 0)
                return log_error_errno(r, "Failed to mask signals for workers: %m");

        for (created_threads = 0; created_threads < num_threads; ++created_threads) {
                r = pthread_create(&new_threads[created_threads], NULL, prober_thread, arg);
                if (r != 0) {
                        log_error_errno(r, "Failed to create worker thread %u: %m", created_threads);
                        break;
                }
        }

        *ret_threads = TAKE_PTR(new_threads);
        *ret_num_threads = created_threads;

        /* Restore the signal mask */
        r = pthread_sigmask(SIG_SETMASK, &saved_ss, NULL);
        if (r != 0)
                log_error_errno(r, "Failed to restore signal mask: %m, ignoring");

        return 0;
}

static int destroy_worker_threads(pthread_t **threads, unsigned num_threads) {
        int ret = 0, r;

        if (num_threads == 0)
                return 0;

        assert(threads);
        assert(*threads);

        for (unsigned i = 0; i < num_threads; ++i) {
                void *p;
                r = pthread_join((*threads)[i], &p);
                if (r != 0)
                        RET_GATHER(ret, log_error_errno(r, "Failed to join worker thread: %m"));
                else
                        RET_GATHER(ret, PTR_TO_INT(p));
        }

        *threads = mfree(*threads);

        return ret;
}

/* Determine number of workers, either from env or from online CPUs */
static unsigned determine_num_worker_threads(unsigned num_modules) {
        unsigned num_threads = 0;

        if (num_modules == 0)
                return 0;

        const char *e = secure_getenv("SYSTEMD_MODULES_LOAD_NUM_THREADS");
        if (e) {
                int r;

                r = safe_atou(e, &num_threads);
                if (r < 0)
                        log_debug_errno(r, "Invalid value in $SYSTEMD_MODULES_LOAD_NUM_THREADS: %s, ignoring", e);
        }

        if (num_threads <= 0) {
                /* By default, use a number of worker threads equal the number of online CPUs,
                 * but clamp it to avoid a probing storm on machines with many CPUs. */
                long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
                if (ncpus < 0)
                        log_warning_errno(errno, "Failed to get number of online CPUs: %m, ignoring");
                num_threads = CLAMP(ncpus, 1, 16);
        }

        /* There's no reason to spawn more threads than the modules that need to be loaded */
        num_threads = MIN(num_threads, num_modules);

        /* One of the probe threads is the main process */
        return (num_threads - 1);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-modules-load.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Loads statically configured kernel modules.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(module_list_free) struct ModulesList mod_list = {
                .modules = NULL,
                .num_modules = 0,
        };
        _cleanup_free_ pthread_t *threads = NULL;
        unsigned num_threads = 0;
        int ret = 0, r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        umask(0022);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        if (argc > optind) {
                for (int i = optind; i < argc; i++)
                        RET_GATHER(ret, apply_file_from_path(argv[i], &mod_list));
        } else {
                ConfFile **files = NULL;
                size_t n_files = 0;

                CLEANUP_ARRAY(files, n_files, conf_file_free_many);

                STRV_FOREACH(i, arg_proc_cmdline_modules) {
                        r = modules_list_append_dup(&mod_list, *i);
                        if (r < 0) {
                                log_error_errno(r, "Failed to add module '%s': %m", *i);
                                RET_GATHER(ret, r);
                        }
                }

                r = conf_files_list_nulstr_full(".conf", /* root = */ NULL,
                                                CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED,
                                                conf_file_dirs, &files, &n_files);
                if (r < 0)
                        RET_GATHER(ret, log_error_errno(r, "Failed to enumerate modules-load.d files: %m"));
                else
                        FOREACH_ARRAY(cf, files, n_files)
                                RET_GATHER(ret, apply_conf_file(*cf, &mod_list));
        }

        num_threads = determine_num_worker_threads(mod_list.num_modules);

        log_debug("Modules to load: %u", mod_list.num_modules);
        log_info("Using %u probe thread(s)", (num_threads + 1));

        r = create_worker_threads(num_threads, (void *)&mod_list, &threads, &num_threads);
        if (r < 0)
                log_warning("Failed to create probe threads, continuing as single-threaded probe");

        /* Run the prober function also in original thread; if num_threads == 0,
         * this is the only running instance */
        r = run_prober(&mod_list);
        RET_GATHER(ret, r);

        /* Wait for all threads (if any) to finish and gather errors */
        r = destroy_worker_threads(&threads, num_threads);
        RET_GATHER(ret, r);

        return ret;
}

DEFINE_MAIN_FUNCTION(run);
