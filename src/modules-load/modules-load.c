/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "build.h"
#include "conf-files.h"
#include "constants.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "module-util.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "strv.h"

#define MODULE_NAME_MAX_LEN (4103UL)

static char **arg_proc_cmdline_modules = NULL;
static const char conf_file_dirs[] = CONF_PATHS_NULSTR("modules-load.d");

STATIC_DESTRUCTOR_REGISTER(arg_proc_cmdline_modules, strv_freep);

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

static int send_module_to_load(int sock, const char *module) {
        ssize_t bytes;

        assert(sock >= 0);
        assert(module);

        if (strlen(module) > MODULE_NAME_MAX_LEN) {
                log_error("Module name max length (%lu) exceeded: %s", MODULE_NAME_MAX_LEN, module);
                return -1;
        }

        bytes = send(sock, module, strlen(module), 0);
        if (bytes < 0)
                return log_error_errno(errno, "Failed to send '%s' to thread pool: %m", module);

        return 0;
}

static int apply_file(int sock, FILE *f, const char *filename, unsigned *ret_num_modules) {
        int ret = 0, r;

        assert(sock >= 0);
        assert(f);

        *ret_num_modules = 0;

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

                r = send_module_to_load(sock, line);
                if (r == 0)
                        *ret_num_modules += 1;
                else
                        RET_GATHER(ret, r);
        }

        return ret;
}

static int apply_path(int sock, const char *path, unsigned *ret_num_modules) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *pp = NULL;
        int r;

        assert(sock >= 0);
        assert(path);

        *ret_num_modules = 0;

        r = search_and_fopen_nulstr(path, "re", NULL, conf_file_dirs, &f, &pp);
        if (r < 0)
                return log_error_errno(r, "Failed to open %s: %m", path);

        return apply_file(sock, f, pp, ret_num_modules);
}

static int apply_conf_file(int sock, ConfFile *c, unsigned *ret_num_modules) {
        _cleanup_fclose_ FILE *f = NULL;

        f = fopen(FORMAT_PROC_FD_PATH(c->fd), "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", c->original_path);
        }

        return apply_file(sock, f, c->original_path, ret_num_modules);
}

static int run_prober(int sock) {
        _cleanup_(sym_kmod_unrefp) struct kmod_ctx *ctx = NULL;
        char buffer[MODULE_NAME_MAX_LEN + 1];
        int ret = 0, r;

        r = module_setup_context(&ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize libkmod context: %m");

        for (;;) {
                ssize_t bytes_received;

                bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (bytes_received <= 0) {
                        if (bytes_received == 0) {
                                log_debug("No more queued modules, terminate thread");
                                break;
                        } else if (errno != EINTR) {
                                RET_GATHER(r, log_error_errno(errno, "Failed to receive from module queue: %m"));
                                break;
                        } else
                                continue;
                }

                buffer[bytes_received] = '\0';

                r = module_load_and_warn(ctx, buffer, true);
                if (r != -ENOENT)
                        RET_GATHER(ret, r);
        }

        return ret;
}

static void *prober_thread(void *arg) {
        int sock = PTR_TO_FD(arg);
        return INT_TO_PTR(run_prober(sock));
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
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        _cleanup_free_ pthread_t *threads = NULL;
        unsigned num_modules = 0, num_threads = 0;
        int ret = 0, r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        umask(0022);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        /* Create a socketpair for communication with probe workers */
        r = RET_NERRNO(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair));
        if (r < 0)
                return log_error_errno(r, "Failed to create socket pair: %m");

        if (argc > optind) {
                for (int i = optind; i < argc; i++) {
                        unsigned n = 0;
                        RET_GATHER(ret, apply_path(pair[0], argv[i], &n));
                        num_modules += n;
                }
        } else {
                ConfFile **files = NULL;
                size_t n_files = 0;

                CLEANUP_ARRAY(files, n_files, conf_file_free_many);

                STRV_FOREACH(i, arg_proc_cmdline_modules) {
                        r = send_module_to_load(pair[0], *i);
                        if (r == 0)
                                num_modules++;
                        else
                                RET_GATHER(ret, r);
                }

                r = conf_files_list_nulstr_full(".conf", /* root = */ NULL,
                                                CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED,
                                                conf_file_dirs, &files, &n_files);
                if (r < 0)
                        RET_GATHER(ret, log_error_errno(r, "Failed to enumerate modules-load.d files: %m"));
                else
                        STRV_FOREACH(fn, files) {
                                unsigned n = 0;
                                RET_GATHER(ret, apply_conf_file(pair[0], *fn, &n));
                                num_modules += n;
                        }
        }

        num_threads = determine_num_worker_threads(num_modules);

        log_debug("Modules to load: %u", num_modules);
        log_info("Using %u probe thread(s)", (num_threads + 1));

        r = create_worker_threads(num_threads, FD_TO_PTR(pair[1]), &threads, &num_threads);
        if (r < 0)
                log_warning("Failed to create probe threads, continuing as single-threaded probe");

        /* Close one end of the socketpair; workers will run until the queue is empty */
        pair[0] = safe_close(pair[0]);

        /* Run the prober function also in original thread; if num_threads == 0,
         * this is the only running instance */
        r = run_prober(pair[1]);
        RET_GATHER(ret, r);

        /* Wait for all threads (if any) to finish and gather errors */
        r = destroy_worker_threads(&threads, num_threads);
        RET_GATHER(ret, r);

        return ret;
}

DEFINE_MAIN_FUNCTION(run);
