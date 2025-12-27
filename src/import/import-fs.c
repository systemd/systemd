/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "btrfs-util.h"
#include "build.h"
#include "copy.h"
#include "discover-image.h"
#include "fd-util.h"
#include "format-util.h"
#include "import-common.h"
#include "import-util.h"
#include "install-file.h"
#include "log.h"
#include "main-func.h"
#include "mkdir-label.h"
#include "parse-argument.h"
#include "path-util.h"
#include "ratelimit.h"
#include "rm-rf.h"
#include "runtime-scope.h"
#include "signal-util.h"
#include "string-util.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "verbs.h"

static bool arg_force = false;
static bool arg_read_only = false;
static bool arg_btrfs_subvol = true;
static bool arg_btrfs_quota = true;
static bool arg_sync = true;
static bool arg_direct = false;
static char *arg_image_root = NULL;
static ImageClass arg_class = IMAGE_MACHINE;
static RuntimeScope arg_runtime_scope = _RUNTIME_SCOPE_INVALID;

STATIC_DESTRUCTOR_REGISTER(arg_image_root, freep);

typedef struct ProgressInfo {
        RateLimit limit;
        char *path;
        uint64_t size;
        bool started;
        bool logged_incomplete;
        uint64_t bps;
} ProgressInfo;

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
                log_notice("(Note: file list shown below is incomplete, and is intended as sporadic progress report only.)");
                p->logged_incomplete = true;
        }

        if (p->size == 0)
                log_info("Copying tree, currently at '%s'...", p->path);
        else if (p->bps == UINT64_MAX)
                log_info("Copying tree, currently at '%s' (@%s)...", p->path, FORMAT_BYTES(p->size));
        else
                log_info("Copying tree, currently at '%s' (@%s, %s/s)...", p->path, FORMAT_BYTES(p->size), FORMAT_BYTES(p->bps));
}

static int progress_path(const char *path, const struct stat *st, void *userdata) {
        ProgressInfo *p = ASSERT_PTR(userdata);
        int r;

        r = free_and_strdup(&p->path, path);
        if (r < 0)
                return r;

        p->size = 0;

        progress_show(p);
        return 0;
}

static int progress_bytes(uint64_t nbytes, uint64_t bps, void *userdata) {
        ProgressInfo *p = ASSERT_PTR(userdata);

        assert(p->size != UINT64_MAX);

        p->size += nbytes;
        p->bps = bps;

        progress_show(p);
        return 0;
}

static int import_fs(int argc, char *argv[], void *userdata) {
        _cleanup_(rm_rf_subvolume_and_freep) char *temp_path = NULL;
        _cleanup_(progress_info_free) ProgressInfo progress = { .bps = UINT64_MAX };
        _cleanup_free_ char *l = NULL, *final_path = NULL;
        const char *path = NULL, *local = NULL, *dest = NULL;
        _cleanup_close_ int open_fd = -EBADF;
        int r, fd;

        if (argc >= 2)
                path = empty_or_dash_to_null(argv[1]);

        if (argc >= 3)
                local = empty_or_dash_to_null(argv[2]);
        else if (path) {
                r = path_extract_filename(path, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from path '%s': %m", path);

                local = l;
        }

        if (arg_direct) {
                if (!local)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No local path specified.");

                if (path_is_absolute(local))
                        final_path = strdup(local);
                else
                        final_path = path_join(arg_image_root, local);
                if (!final_path)
                        return log_oom();

                if (!path_is_valid(final_path))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Local path name '%s' is not valid.", final_path);
        } else {
                if (local) {
                        if (!image_name_is_valid(local))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Local image name '%s' is not valid.", local);
                } else
                        local = "imported";

                final_path = path_join(arg_image_root, local);
                if (!final_path)
                        return log_oom();

                if (!arg_force) {
                        r = image_find(arg_runtime_scope, arg_class, local, NULL, NULL);
                        if (r < 0) {
                                if (r != -ENOENT)
                                        return log_error_errno(r, "Failed to check whether image '%s' exists: %m", local);
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "Image '%s' already exists.", local);
                }
        }

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

        log_info("Operating on image directory '%s'.", arg_image_root);

        if (!arg_sync)
                log_info("File system synchronization on completion is off.");

        if (arg_direct) {
                if (arg_force)
                        (void) rm_rf(final_path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);

                dest = final_path;
        } else {
                r = tempfn_random(final_path, NULL, &temp_path);
                if (r < 0)
                        return log_oom();

                dest = temp_path;
        }

        (void) mkdir_parents_label(dest, 0700);

        progress.limit = (const RateLimit) { 200*USEC_PER_MSEC, 1 };

        {
                BLOCK_SIGNALS(SIGINT, SIGTERM);

                if (arg_btrfs_subvol)
                        r = btrfs_subvol_snapshot_at_full(
                                        fd, NULL,
                                        AT_FDCWD, dest,
                                        BTRFS_SNAPSHOT_FALLBACK_COPY|
                                        BTRFS_SNAPSHOT_FALLBACK_DIRECTORY|
                                        BTRFS_SNAPSHOT_RECURSIVE|
                                        BTRFS_SNAPSHOT_SIGINT|
                                        BTRFS_SNAPSHOT_SIGTERM,
                                        progress_path,
                                        progress_bytes,
                                        &progress);
                else
                        r = copy_directory_at_full(
                                        fd, NULL,
                                        AT_FDCWD, dest,
                                        /* override_uid= */ UID_INVALID,
                                        /* override_gid= */ GID_INVALID,
                                        COPY_REFLINK|
                                        COPY_SAME_MOUNT|
                                        COPY_HARDLINKS|
                                        COPY_SIGINT|
                                        COPY_SIGTERM|
                                        (arg_direct ? COPY_MERGE_EMPTY : 0),
                                        progress_path,
                                        progress_bytes,
                                        &progress);
                if (r == -EINTR) /* SIGINT/SIGTERM hit */
                        return log_error_errno(r, "Copy cancelled.");
                if (r < 0)
                        return log_error_errno(r, "Failed to copy directory: %m");
        }

        r = import_mangle_os_tree(dest, /* userns_fd= */ -EBADF, /* flags= */ 0);
        if (r < 0)
                return r;

        if (arg_btrfs_quota) {
                if (!arg_direct)
                        (void) import_assign_pool_quota_and_warn(arg_image_root);
                (void) import_assign_pool_quota_and_warn(dest);
        }

        r = install_file(AT_FDCWD, dest,
                         AT_FDCWD, arg_direct ? NULL : final_path, /* pass NULL as target in case of direct
                                                                    * mode since file is already in place */
                         (arg_force ? INSTALL_REPLACE : 0) |
                         (arg_read_only ? INSTALL_READ_ONLY : 0) |
                         (arg_sync ? INSTALL_SYNCFS : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to install directory as '%s': %m", final_path);

        temp_path = mfree(temp_path);

        log_info("Directory '%s successfully installed. Exiting.", final_path);
        return 0;
}

static int help(int argc, char *argv[], void *userdata) {

        printf("%1$s [OPTIONS...] {COMMAND} ...\n"
               "\n%4$sImport container images from a file system directories.%5$s\n"
               "\n%2$sCommands:%3$s\n"
               "  run DIRECTORY [NAME]        Import a directory\n"
               "\n%2$sOptions:%3$s\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --force                  Force creation of image\n"
               "     --image-root=PATH        Image root directory\n"
               "     --read-only              Create a read-only image\n"
               "     --direct                 Import directly to specified directory\n"
               "     --btrfs-subvol=BOOL      Controls whether to create a btrfs subvolume\n"
               "                              instead of a directory\n"
               "     --btrfs-quota=BOOL       Controls whether to set up quota for btrfs\n"
               "                              subvolume\n"
               "     --sync=BOOL              Controls whether to sync() before completing\n"
               "     --class=CLASS            Select image class (machine, sysext, confext,\n"
               "                              portable)\n"
               "     --system                 Operate in per-system mode\n"
               "     --user                   Operate in per-user mode\n",
               program_invocation_short_name,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_FORCE,
                ARG_IMAGE_ROOT,
                ARG_READ_ONLY,
                ARG_DIRECT,
                ARG_BTRFS_SUBVOL,
                ARG_BTRFS_QUOTA,
                ARG_SYNC,
                ARG_CLASS,
                ARG_SYSTEM,
                ARG_USER,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "force",           no_argument,       NULL, ARG_FORCE           },
                { "image-root",      required_argument, NULL, ARG_IMAGE_ROOT      },
                { "read-only",       no_argument,       NULL, ARG_READ_ONLY       },
                { "direct",          no_argument,       NULL, ARG_DIRECT          },
                { "btrfs-subvol",    required_argument, NULL, ARG_BTRFS_SUBVOL    },
                { "btrfs-quota",     required_argument, NULL, ARG_BTRFS_QUOTA     },
                { "sync",            required_argument, NULL, ARG_SYNC            },
                { "class",           required_argument, NULL, ARG_CLASS           },
                { "system",          no_argument,       NULL, ARG_SYSTEM          },
                { "user",            no_argument,       NULL, ARG_USER            },
                {}
        };

        int c, r;

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
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_image_root);
                        if (r < 0)
                                return r;

                        break;

                case ARG_READ_ONLY:
                        arg_read_only = true;
                        break;

                case ARG_DIRECT:
                        arg_direct = true;
                        break;

                case ARG_BTRFS_SUBVOL:
                        r = parse_boolean_argument("--btrfs-subvol=", optarg, &arg_btrfs_subvol);
                        if (r < 0)
                                return r;

                        break;

                case ARG_BTRFS_QUOTA:
                        r = parse_boolean_argument("--btrfs-quota=", optarg, &arg_btrfs_quota);
                        if (r < 0)
                                return r;

                        break;

                case ARG_SYNC:
                        r = parse_boolean_argument("--sync=", optarg, &arg_sync);
                        if (r < 0)
                                return r;

                        break;

                case ARG_CLASS:
                        arg_class = image_class_from_string(optarg);
                        if (arg_class < 0)
                                return log_error_errno(arg_class, "Failed to parse --class= argument: %s", optarg);

                        break;

                case ARG_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                case ARG_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (!arg_image_root) {
                r = image_root_pick(arg_runtime_scope < 0 ? RUNTIME_SCOPE_SYSTEM : arg_runtime_scope, arg_class, /* runtime= */ false, &arg_image_root);
                if (r < 0)
                        return log_error_errno(r, "Failed to pick image root: %m");
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

static int run(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return import_fs_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
