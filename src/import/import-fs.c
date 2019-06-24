/* SPDX-License-Identifier: LGPL-2.1+ */

#include <getopt.h>
#include <locale.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "import-common.h"
#include "import-util.h"
#include "machine-image.h"
#include "mkdir.h"
#include "ratelimit.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "verbs.h"

static bool arg_force = false;
static bool arg_read_only = false;
static const char *arg_image_root = "/var/lib/machines";

typedef struct ProgressInfo {
        RateLimit limit;
        char *path;
        uint64_t size;
        bool started;
        bool logged_incomplete;
} ProgressInfo;

static volatile sig_atomic_t cancelled = false;

static void sigterm_sigint(int sig) {
        cancelled = true;
}

static void progress_info_free(ProgressInfo *p) {
        free(p->path);
}

static void progress_show(ProgressInfo *p) {
        assert(p);

        /* Show progress only every now and then. */
        if (!ratelimit_below(&p->limit))
                return;

        /* Suppress the first message, start with the second one */
        if (!p->started) {
                p->started = true;
                return;
        }

        /* Mention the list is incomplete before showing first output. */
        if (!p->logged_incomplete) {
                log_notice("(Note, file list shown below is incomplete, and is intended as sporadic progress report only.)");
                p->logged_incomplete = true;
        }

        if (p->size == 0)
                log_info("Copying tree, currently at '%s'...", p->path);
        else {
                char buffer[FORMAT_BYTES_MAX];

                log_info("Copying tree, currently at '%s' (@%s)...", p->path, format_bytes(buffer, sizeof(buffer), p->size));
        }
}

static int progress_path(const char *path, const struct stat *st, void *userdata) {
        ProgressInfo *p = userdata;
        int r;

        assert(p);

        if (cancelled)
                return -EOWNERDEAD;

        r = free_and_strdup(&p->path, path);
        if (r < 0)
                return r;

        p->size = 0;

        progress_show(p);
        return 0;
}

static int progress_bytes(uint64_t nbytes, void *userdata) {
        ProgressInfo *p = userdata;

        assert(p);
        assert(p->size != UINT64_MAX);

        if (cancelled)
                return -EOWNERDEAD;

        p->size += nbytes;

        progress_show(p);
        return 0;
}

static int import_fs(int argc, char *argv[], void *userdata) {
        _cleanup_(rm_rf_subvolume_and_freep) char *temp_path = NULL;
        _cleanup_(progress_info_free) ProgressInfo progress = {};
        const char *path = NULL, *local = NULL, *final_path;
        _cleanup_close_ int open_fd = -1;
        struct sigaction old_sigint_sa, old_sigterm_sa;
        static const struct sigaction sa = {
                .sa_handler = sigterm_sigint,
                .sa_flags = SA_RESTART,
        };
        int r, fd;

        if (argc >= 2)
                path = argv[1];
        path = empty_or_dash_to_null(path);

        if (argc >= 3)
                local = argv[2];
        else if (path)
                local = basename(path);
        local = empty_or_dash_to_null(local);

        if (local) {
                if (!machine_name_is_valid(local)) {
                        log_error("Local image name '%s' is not valid.", local);
                        return -EINVAL;
                }

                if (!arg_force) {
                        r = image_find(IMAGE_MACHINE, local, NULL);
                        if (r < 0) {
                                if (r != -ENOENT)
                                        return log_error_errno(r, "Failed to check whether image '%s' exists: %m", local);
                        } else {
                                log_error("Image '%s' already exists.", local);
                                return -EEXIST;
                        }
                }
        } else
                local = "imported";

        if (path) {
                open_fd = open(path, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
                if (open_fd < 0)
                        return log_error_errno(errno, "Failed to open directory to import: %m");

                fd = open_fd;

                log_info("Importing '%s', saving as '%s'.", path, local);
        } else {
                _cleanup_free_ char *pretty = NULL;

                fd = STDIN_FILENO;

                (void) fd_get_path(fd, &pretty);
                log_info("Importing '%s', saving as '%s'.", strempty(pretty), local);
        }

        final_path = prefix_roota(arg_image_root, local);

        r = tempfn_random(final_path, NULL, &temp_path);
        if (r < 0)
                return log_oom();

        (void) mkdir_parents_label(temp_path, 0700);

        RATELIMIT_INIT(progress.limit, 200*USEC_PER_MSEC, 1);

        /* Hook into SIGINT/SIGTERM, so that we can cancel things then */
        assert(sigaction(SIGINT, &sa, &old_sigint_sa) >= 0);
        assert(sigaction(SIGTERM, &sa, &old_sigterm_sa) >= 0);

        r = btrfs_subvol_snapshot_fd_full(
                        fd,
                        temp_path,
                        BTRFS_SNAPSHOT_FALLBACK_COPY|BTRFS_SNAPSHOT_RECURSIVE|BTRFS_SNAPSHOT_FALLBACK_DIRECTORY|BTRFS_SNAPSHOT_QUOTA,
                        progress_path,
                        progress_bytes,
                        &progress);
        if (r == -EOWNERDEAD) { /* SIGINT + SIGTERM cause this, see signal handler above */
                log_error("Copy cancelled.");
                goto finish;
        }
        if (r < 0) {
                log_error_errno(r, "Failed to copy directory: %m");
                goto finish;
        }

        r = import_mangle_os_tree(temp_path);
        if (r < 0)
                goto finish;

        (void) import_assign_pool_quota_and_warn(temp_path);

        if (arg_read_only) {
                r = import_make_read_only(temp_path);
                if (r < 0) {
                        log_error_errno(r, "Failed to make directory read-only: %m");
                        goto finish;
                }
        }

        if (arg_force)
                (void) rm_rf(final_path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);

        r = rename_noreplace(AT_FDCWD, temp_path, AT_FDCWD, final_path);
        if (r < 0) {
                log_error_errno(r, "Failed to move image into place: %m");
                goto finish;
        }

        temp_path = mfree(temp_path);

        log_info("Exiting.");

finish:
        /* Put old signal handlers into place */
        assert(sigaction(SIGINT, &old_sigint_sa, NULL) >= 0);
        assert(sigaction(SIGTERM, &old_sigterm_sa, NULL) >= 0);

        return 0;
}

static int help(int argc, char *argv[], void *userdata) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Import container images from a file system.\n\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --force                  Force creation of image\n"
               "     --image-root=PATH        Image root directory\n"
               "     --read-only              Create a read-only image\n\n"
               "Commands:\n"
               "  run DIRECTORY [NAME]             Import a directory\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_FORCE,
                ARG_IMAGE_ROOT,
                ARG_READ_ONLY,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "force",           no_argument,       NULL, ARG_FORCE           },
                { "image-root",      required_argument, NULL, ARG_IMAGE_ROOT      },
                { "read-only",       no_argument,       NULL, ARG_READ_ONLY       },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_FORCE:
                        arg_force = true;
                        break;

                case ARG_IMAGE_ROOT:
                        arg_image_root = optarg;
                        break;

                case ARG_READ_ONLY:
                        arg_read_only = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

static int import_fs_main(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "help", VERB_ANY, VERB_ANY, 0, help      },
                { "run",  2,        3,        0, import_fs },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

int main(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = import_fs_main(argc, argv);

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
