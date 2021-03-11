/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <linux/loop.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mount.h>

#include "architecture.h"
#include "copy.h"
#include "dissect-image.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "loop-util.h"
#include "main-func.h"
#include "mkdir.h"
#include "mount-util.h"
#include "namespace-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "util.h"

static enum {
        ACTION_DISSECT,
        ACTION_MOUNT,
        ACTION_COPY_FROM,
        ACTION_COPY_TO,
} arg_action = ACTION_DISSECT;
static const char *arg_image = NULL;
static const char *arg_path = NULL;
static const char *arg_source = NULL;
static const char *arg_target = NULL;
static DissectImageFlags arg_flags = DISSECT_IMAGE_REQUIRE_ROOT|DISSECT_IMAGE_DISCARD_ON_LOOP|DISSECT_IMAGE_RELAX_VAR_CHECK|DISSECT_IMAGE_FSCK;
static VeritySettings arg_verity_settings = VERITY_SETTINGS_DEFAULT;
static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;

STATIC_DESTRUCTOR_REGISTER(arg_verity_settings, verity_settings_done);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-dissect", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] IMAGE\n"
               "%1$s [OPTIONS...] --mount IMAGE PATH\n"
               "%1$s [OPTIONS...] --copy-from IMAGE PATH [TARGET]\n"
               "%1$s [OPTIONS...] --copy-to IMAGE [SOURCE] PATH\n\n"
               "%5$sDissect a file system OS image.%6$s\n\n"
               "%3$sOptions:%4$s\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --no-legend          Do not show the headers and footers\n"
               "  -r --read-only          Mount read-only\n"
               "     --fsck=BOOL          Run fsck before mounting\n"
               "     --mkdir              Make mount directory before mounting, if missing\n"
               "     --discard=MODE       Choose 'discard' mode (disabled, loop, all, crypto)\n"
               "     --root-hash=HASH     Specify root hash for verity\n"
               "     --root-hash-sig=SIG  Specify pkcs7 signature of root hash for verity\n"
               "                          as a DER encoded PKCS7, either as a path to a file\n"
               "                          or as an ASCII base64 encoded string prefixed by\n"
               "                          'base64:'\n"
               "     --verity-data=PATH   Specify data file with hash tree for verity if it is\n"
               "                          not embedded in IMAGE\n"
               "     --json=pretty|short|off\n"
               "                          Generate JSON output\n"
               "\n%3$sCommands:%4$s\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "  -m --mount              Mount the image to the specified directory\n"
               "  -M                      Shortcut for --mount --mkdir\n"
               "  -x --copy-from          Copy files from image to host\n"
               "  -a --copy-to            Copy files from host to image\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_DISCARD,
                ARG_FSCK,
                ARG_ROOT_HASH,
                ARG_ROOT_HASH_SIG,
                ARG_VERITY_DATA,
                ARG_MKDIR,
                ARG_JSON,
        };

        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'               },
                { "version",       no_argument,       NULL, ARG_VERSION       },
                { "no-pager",      no_argument,       NULL, ARG_NO_PAGER      },
                { "no-legend",     no_argument,       NULL, ARG_NO_LEGEND     },
                { "mount",         no_argument,       NULL, 'm'               },
                { "read-only",     no_argument,       NULL, 'r'               },
                { "discard",       required_argument, NULL, ARG_DISCARD       },
                { "fsck",          required_argument, NULL, ARG_FSCK          },
                { "root-hash",     required_argument, NULL, ARG_ROOT_HASH     },
                { "root-hash-sig", required_argument, NULL, ARG_ROOT_HASH_SIG },
                { "verity-data",   required_argument, NULL, ARG_VERITY_DATA   },
                { "mkdir",         no_argument,       NULL, ARG_MKDIR         },
                { "copy-from",     no_argument,       NULL, 'x'               },
                { "copy-to",       no_argument,       NULL, 'a'               },
                { "json",          required_argument, NULL, ARG_JSON          },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hmrMxa", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case 'm':
                        arg_action = ACTION_MOUNT;
                        break;

                case ARG_MKDIR:
                        arg_flags |= DISSECT_IMAGE_MKDIR;
                        break;

                case 'M':
                        /* Shortcut combination of the above two */
                        arg_action = ACTION_MOUNT;
                        arg_flags |= DISSECT_IMAGE_MKDIR;
                        break;

                case 'x':
                        arg_action = ACTION_COPY_FROM;
                        arg_flags |= DISSECT_IMAGE_READ_ONLY;
                        break;

                case 'a':
                        arg_action = ACTION_COPY_TO;
                        break;

                case 'r':
                        arg_flags |= DISSECT_IMAGE_READ_ONLY;
                        break;

                case ARG_DISCARD: {
                        DissectImageFlags flags;

                        if (streq(optarg, "disabled"))
                                flags = 0;
                        else if (streq(optarg, "loop"))
                                flags = DISSECT_IMAGE_DISCARD_ON_LOOP;
                        else if (streq(optarg, "all"))
                                flags = DISSECT_IMAGE_DISCARD_ON_LOOP | DISSECT_IMAGE_DISCARD;
                        else if (streq(optarg, "crypt"))
                                flags = DISSECT_IMAGE_DISCARD_ANY;
                        else if (streq(optarg, "list")) {
                                puts("disabled\n"
                                     "all\n"
                                     "crypt\n"
                                     "loop");
                                return 0;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown --discard= parameter: %s",
                                                       optarg);
                        arg_flags = (arg_flags & ~DISSECT_IMAGE_DISCARD_ANY) | flags;

                        break;
                }

                case ARG_ROOT_HASH: {
                        _cleanup_free_ void *p = NULL;
                        size_t l;

                        r = unhexmem(optarg, strlen(optarg), &p, &l);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse root hash '%s': %m", optarg);
                        if (l < sizeof(sd_id128_t))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Root hash must be at least 128bit long: %s", optarg);

                        free_and_replace(arg_verity_settings.root_hash, p);
                        arg_verity_settings.root_hash_size = l;
                        break;
                }

                case ARG_ROOT_HASH_SIG: {
                        char *value;
                        size_t l;
                        void *p;

                        if ((value = startswith(optarg, "base64:"))) {
                                r = unbase64mem(value, strlen(value), &p, &l);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse root hash signature '%s': %m", optarg);
                        } else {
                                r = read_full_file(optarg, (char**) &p, &l);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to read root hash signature file '%s': %m", optarg);
                        }

                        free_and_replace(arg_verity_settings.root_hash_sig, p);
                        arg_verity_settings.root_hash_sig_size = l;
                        break;
                }

                case ARG_VERITY_DATA:
                        r = parse_path_argument(optarg, false, &arg_verity_settings.data_path);
                        if (r < 0)
                                return r;
                        break;

                case ARG_FSCK:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --fsck= parameter: %s", optarg);

                        SET_FLAG(arg_flags, DISSECT_IMAGE_FSCK, r);
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        }

        switch (arg_action) {

        case ACTION_DISSECT:
                if (optind + 1 != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Expected an image file path as only argument.");

                arg_image = argv[optind];
                arg_flags |= DISSECT_IMAGE_READ_ONLY;
                break;

        case ACTION_MOUNT:
                if (optind + 2 != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Expected an image file path and mount point path as only arguments.");

                arg_image = argv[optind];
                arg_path = argv[optind + 1];
                break;

        case ACTION_COPY_FROM:
                if (argc < optind + 2 || argc > optind + 3)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Expected an image file path, a source path and an optional destination path as only arguments.");

                arg_image = argv[optind];
                arg_source = argv[optind + 1];
                arg_target = argc > optind + 2 ? argv[optind + 2] : "-" /* this means stdout */ ;

                arg_flags |= DISSECT_IMAGE_READ_ONLY;
                break;

        case ACTION_COPY_TO:
                if (argc < optind + 2 || argc > optind + 3)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Expected an image file path, an optional source path and a destination path as only arguments.");

                arg_image = argv[optind];

                if (argc > optind + 2) {
                        arg_source = argv[optind + 1];
                        arg_target = argv[optind + 2];
                } else {
                        arg_source = "-"; /* this means stdin */
                        arg_target = argv[optind + 1];
                }

                break;

        default:
                assert_not_reached("Unknown action.");
        }

        return 1;
}

static int strv_pair_to_json(char **l, JsonVariant **ret) {
        _cleanup_strv_free_ char **jl = NULL;
        char **a, **b;

        STRV_FOREACH_PAIR(a, b, l) {
                char *j;

                j = strjoin(*a, "=", *b);
                if (!j)
                        return log_oom();

                if (strv_consume(&jl, j) < 0)
                        return log_oom();
        }

        return json_variant_new_array_strv(ret, jl);
}

static int action_dissect(DissectedImage *m, LoopDevice *d) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;
        uint64_t size = UINT64_MAX;
        int r;

        assert(m);
        assert(d);

        if (arg_json_format_flags & (JSON_FORMAT_OFF|JSON_FORMAT_PRETTY|JSON_FORMAT_PRETTY_AUTO))
                (void) pager_open(arg_pager_flags);

        if (arg_json_format_flags & JSON_FORMAT_OFF)
                printf("      Name: %s\n", basename(arg_image));

        if (ioctl(d->fd, BLKGETSIZE64, &size) < 0)
                log_debug_errno(errno, "Failed to query size of loopback device: %m");
        else if (arg_json_format_flags & JSON_FORMAT_OFF) {
                char s[FORMAT_BYTES_MAX];
                printf("      Size: %s\n", format_bytes(s, sizeof(s), size));
        }

        if (arg_json_format_flags & JSON_FORMAT_OFF)
                putc('\n', stdout);

        r = dissected_image_acquire_metadata(m);
        if (r == -ENXIO)
                return log_error_errno(r, "No root partition discovered.");
        if (r == -EUCLEAN)
                return log_error_errno(r, "File system check of image failed.");
        if (r == -EMEDIUMTYPE)
                log_warning_errno(r, "Not a valid OS image, no os-release file included. Proceeding anyway.");
        else if (r == -EUNATCH)
                log_warning_errno(r, "OS image is encrypted, proceeding without showing OS image metadata.");
        else if (r == -EBUSY)
                log_warning_errno(r, "OS image is currently in use, proceeding without showing OS image metadata.");
        else if (r < 0)
                return log_error_errno(r, "Failed to acquire image metadata: %m");
        else if (arg_json_format_flags & JSON_FORMAT_OFF) {
                if (m->hostname)
                        printf("  Hostname: %s\n", m->hostname);

                if (!sd_id128_is_null(m->machine_id))
                        printf("Machine ID: " SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(m->machine_id));

                if (!strv_isempty(m->machine_info)) {
                        char **p, **q;

                        STRV_FOREACH_PAIR(p, q, m->machine_info)
                                printf("%s %s=%s\n",
                                       p == m->machine_info ? "Mach. Info:" : "           ",
                                       *p, *q);
                }

                if (!strv_isempty(m->os_release)) {
                        char **p, **q;

                        STRV_FOREACH_PAIR(p, q, m->os_release)
                                printf("%s %s=%s\n",
                                       p == m->os_release ? "OS Release:" : "           ",
                                       *p, *q);
                }

                if (!strv_isempty(m->extension_release)) {
                        char **p, **q;

                        STRV_FOREACH_PAIR(p, q, m->extension_release)
                                printf("%s %s=%s\n",
                                       p == m->extension_release ? "Extension Release:" : "                  ",
                                       *p, *q);
                }

                if (m->hostname ||
                    !sd_id128_is_null(m->machine_id) ||
                    !strv_isempty(m->machine_info) ||
                    !strv_isempty(m->extension_release) ||
                    !strv_isempty(m->os_release))
                        putc('\n', stdout);
        } else {
                _cleanup_(json_variant_unrefp) JsonVariant *mi = NULL, *osr = NULL, *exr = NULL;

                if (!strv_isempty(m->machine_info)) {
                        r = strv_pair_to_json(m->machine_info, &mi);
                        if (r < 0)
                                return log_oom();
                }

                if (!strv_isempty(m->os_release)) {
                        r = strv_pair_to_json(m->os_release, &osr);
                        if (r < 0)
                                return log_oom();
                }

                if (!strv_isempty(m->extension_release)) {
                        r = strv_pair_to_json(m->extension_release, &exr);
                        if (r < 0)
                                return log_oom();
                }

                r = json_build(&v, JSON_BUILD_OBJECT(
                                               JSON_BUILD_PAIR("name", JSON_BUILD_STRING(basename(arg_image))),
                                               JSON_BUILD_PAIR("size", JSON_BUILD_INTEGER(size)),
                                               JSON_BUILD_PAIR_CONDITION(m->hostname, "hostname", JSON_BUILD_STRING(m->hostname)),
                                               JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(m->machine_id), "machineId", JSON_BUILD_ID128(m->machine_id)),
                                               JSON_BUILD_PAIR_CONDITION(mi, "machineInfo", JSON_BUILD_VARIANT(mi)),
                                               JSON_BUILD_PAIR_CONDITION(osr, "osRelease", JSON_BUILD_VARIANT(osr)),
                                               JSON_BUILD_PAIR_CONDITION(exr, "extensionRelease", JSON_BUILD_VARIANT(exr))));
                if (r < 0)
                        return log_oom();
        }

        t = table_new("rw", "designator", "partition uuid", "fstype", "architecture", "verity", "node", "partno");
        if (!t)
                return log_oom();

        (void) table_set_empty_string(t, "-");
        (void) table_set_align_percent(t, table_get_cell(t, 0, 7), 100);

        for (PartitionDesignator i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                DissectedPartition *p = m->partitions + i;

                if (!p->found)
                        continue;

                r = table_add_many(
                                t,
                                TABLE_STRING, p->rw ? "rw" : "ro",
                                TABLE_STRING, partition_designator_to_string(i));
                if (r < 0)
                        return table_log_add_error(r);

                if (sd_id128_is_null(p->uuid))
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                else
                        r = table_add_cell(t, NULL, TABLE_UUID, &p->uuid);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_many(
                                t,
                                TABLE_STRING, p->fstype,
                                TABLE_STRING, architecture_to_string(p->architecture));
                if (r < 0)
                        return table_log_add_error(r);

                if (arg_verity_settings.data_path)
                        r = table_add_cell(t, NULL, TABLE_STRING, "external");
                else if (dissected_image_can_do_verity(m, i))
                        r = table_add_cell(t, NULL, TABLE_STRING, yes_no(dissected_image_has_verity(m, i)));
                else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (p->partno < 0) /* no partition table, naked file system */ {
                        r = table_add_cell(t, NULL, TABLE_STRING, arg_image);
                        if (r < 0)
                                return table_log_add_error(r);

                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                } else {
                        r = table_add_cell(t, NULL, TABLE_STRING, p->node);
                        if (r < 0)
                                return table_log_add_error(r);

                        r = table_add_cell(t, NULL, TABLE_INT, &p->partno);
                }
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (arg_json_format_flags & JSON_FORMAT_OFF) {
                (void) table_set_header(t, arg_legend);

                r = table_print(t, NULL);
                if (r < 0)
                        return table_log_print_error(r);
        } else {
                _cleanup_(json_variant_unrefp) JsonVariant *jt = NULL;

                r = table_to_json(t, &jt);
                if (r < 0)
                        return log_error_errno(r, "Failed to convert table to JSON: %m");

                r = json_variant_set_field(&v, "mounts", jt);
                if (r < 0)
                        return log_oom();

                json_variant_dump(v, arg_json_format_flags, stdout, NULL);
        }

        return 0;
}

static int action_mount(DissectedImage *m, LoopDevice *d) {
        _cleanup_(decrypted_image_unrefp) DecryptedImage *di = NULL;
        int r;

        assert(m);
        assert(d);

        r = dissected_image_decrypt_interactively(
                        m, NULL,
                        &arg_verity_settings,
                        arg_flags,
                        &di);
        if (r < 0)
                return r;

        r = dissected_image_mount_and_warn(m, arg_path, UID_INVALID, arg_flags);
        if (r < 0)
                return r;

        if (di) {
                r = decrypted_image_relinquish(di);
                if (r < 0)
                        return log_error_errno(r, "Failed to relinquish DM devices: %m");
        }

        loop_device_relinquish(d);
        return 0;
}

static int action_copy(DissectedImage *m, LoopDevice *d) {
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *di = NULL;
        _cleanup_(rmdir_and_freep) char *created_dir = NULL;
        _cleanup_free_ char *temp = NULL;
        int r;

        assert(m);
        assert(d);

        r = dissected_image_decrypt_interactively(
                        m, NULL,
                        &arg_verity_settings,
                        arg_flags,
                        &di);
        if (r < 0)
                return r;

        r = detach_mount_namespace();
        if (r < 0)
                return log_error_errno(r, "Failed to detach mount namespace: %m");

        r = tempfn_random_child(NULL, program_invocation_short_name, &temp);
        if (r < 0)
                return log_error_errno(r, "Failed to generate temporary mount directory: %m");

        r = mkdir_p(temp, 0700);
        if (r < 0)
                return log_error_errno(r, "Failed to create mount point: %m");

        created_dir = TAKE_PTR(temp);

        r = dissected_image_mount_and_warn(m, created_dir, UID_INVALID, arg_flags);
        if (r < 0)
                return r;

        mounted_dir = TAKE_PTR(created_dir);

        if (di) {
                r = decrypted_image_relinquish(di);
                if (r < 0)
                        return log_error_errno(r, "Failed to relinquish DM devices: %m");
        }

        loop_device_relinquish(d);

        if (arg_action == ACTION_COPY_FROM) {
                _cleanup_close_ int source_fd = -1, target_fd = -1;

                source_fd = chase_symlinks_and_open(arg_source, mounted_dir, CHASE_PREFIX_ROOT|CHASE_WARN, O_RDONLY|O_CLOEXEC|O_NOCTTY, NULL);
                if (source_fd < 0)
                        return log_error_errno(source_fd, "Failed to open source path '%s' in image '%s': %m", arg_source, arg_image);

                /* Copying to stdout? */
                if (streq(arg_target, "-")) {
                        r = copy_bytes(source_fd, STDOUT_FILENO, UINT64_MAX, COPY_REFLINK);
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy bytes from %s in mage '%s' to stdout: %m", arg_source, arg_image);

                        /* When we copy to stdout we don't copy any attributes (i.e. no access mode, no ownership, no xattr, no times) */
                        return 0;
                }

                /* Try to copy as directory? */
                r = copy_directory_fd(source_fd, arg_target, COPY_REFLINK|COPY_MERGE_EMPTY|COPY_SIGINT|COPY_HARDLINKS);
                if (r >= 0)
                        return 0;
                if (r != -ENOTDIR)
                        return log_error_errno(r, "Failed to copy %s in image '%s' to '%s': %m", arg_source, arg_image, arg_target);

                r = fd_verify_regular(source_fd);
                if (r == -EISDIR)
                        return log_error_errno(r, "Target '%s' exists already and is not a directory.", arg_target);
                if (r < 0)
                        return log_error_errno(r, "Source path %s in image '%s' is neither regular file nor directory, refusing: %m", arg_source, arg_image);

                /* Nah, it's a plain file! */
                target_fd = open(arg_target, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0600);
                if (target_fd < 0)
                        return log_error_errno(errno, "Failed to create regular file at target path '%s': %m", arg_target);

                r = copy_bytes(source_fd, target_fd, UINT64_MAX, COPY_REFLINK);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy bytes from %s in mage '%s' to '%s': %m", arg_source, arg_image, arg_target);

                (void) copy_xattr(source_fd, target_fd);
                (void) copy_access(source_fd, target_fd);
                (void) copy_times(source_fd, target_fd, 0);

                /* When this is a regular file we don't copy ownership! */

        } else {
                _cleanup_close_ int source_fd = -1, target_fd = -1;
                _cleanup_close_ int dfd = -1;
                _cleanup_free_ char *dn = NULL;

                assert(arg_action == ACTION_COPY_TO);

                dn = dirname_malloc(arg_target);
                if (!dn)
                        return log_oom();

                r = chase_symlinks(dn, mounted_dir, CHASE_PREFIX_ROOT|CHASE_WARN, NULL, &dfd);
                if (r < 0)
                        return log_error_errno(r, "Failed to open '%s': %m", dn);

                /* Are we reading from stdin? */
                if (streq(arg_source, "-")) {
                        target_fd = openat(dfd, basename(arg_target), O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY|O_EXCL, 0644);
                        if (target_fd < 0)
                                return log_error_errno(errno, "Failed to open target file '%s': %m", arg_target);

                        r = copy_bytes(STDIN_FILENO, target_fd, UINT64_MAX, COPY_REFLINK);
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy bytes from stdin to '%s' in image '%s': %m", arg_target, arg_image);

                        /* When we copy from stdin we don't copy any attributes (i.e. no access mode, no ownership, no xattr, no times) */
                        return 0;
                }

                source_fd = open(arg_source, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (source_fd < 0)
                        return log_error_errno(source_fd, "Failed to open source path '%s': %m", arg_source);

                r = fd_verify_regular(source_fd);
                if (r < 0) {
                        if (r != -EISDIR)
                                return log_error_errno(r, "Source '%s' is neither regular file nor directory: %m", arg_source);

                        /* We are looking at a directory. */

                        target_fd = openat(dfd, basename(arg_target), O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                        if (target_fd < 0) {
                                if (errno != ENOENT)
                                        return log_error_errno(errno, "Failed to open destination '%s': %m", arg_target);

                                r = copy_tree_at(source_fd, ".", dfd, basename(arg_target), UID_INVALID, GID_INVALID, COPY_REFLINK|COPY_REPLACE|COPY_SIGINT|COPY_HARDLINKS);
                        } else
                                r = copy_tree_at(source_fd, ".", target_fd, ".", UID_INVALID, GID_INVALID, COPY_REFLINK|COPY_REPLACE|COPY_SIGINT|COPY_HARDLINKS);
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy '%s' to '%s' in image '%s': %m", arg_source, arg_target, arg_image);

                        return 0;
                }

                /* We area looking at a regular file */
                target_fd = openat(dfd, basename(arg_target), O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY|O_EXCL, 0600);
                if (target_fd < 0)
                        return log_error_errno(errno, "Failed to open target file '%s': %m", arg_target);

                r = copy_bytes(source_fd, target_fd, UINT64_MAX, COPY_REFLINK);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy bytes from '%s' to '%s' in image '%s': %m", arg_source, arg_target, arg_image);

                (void) copy_xattr(source_fd, target_fd);
                (void) copy_access(source_fd, target_fd);
                (void) copy_times(source_fd, target_fd, 0);

                /* When this is a regular file we don't copy ownership! */
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = verity_settings_load(
                        &arg_verity_settings,
                        arg_image, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read verity artifacts for %s: %m", arg_image);

        if (arg_verity_settings.data_path)
                arg_flags |= DISSECT_IMAGE_NO_PARTITION_TABLE; /* We only support Verity per file system,
                                                                * hence if there's external Verity data
                                                                * available we turn off partition table
                                                                * support */

        r = loop_device_make_by_path(
                        arg_image,
                        FLAGS_SET(arg_flags, DISSECT_IMAGE_READ_ONLY) ? O_RDONLY : O_RDWR,
                        FLAGS_SET(arg_flags, DISSECT_IMAGE_NO_PARTITION_TABLE) ? 0 : LO_FLAGS_PARTSCAN,
                        &d);
        if (r < 0)
                return log_error_errno(r, "Failed to set up loopback device: %m");

        r = dissect_image_and_warn(
                        d->fd,
                        arg_image,
                        &arg_verity_settings,
                        NULL,
                        arg_flags,
                        &m);
        if (r < 0)
                return r;

        switch (arg_action) {

        case ACTION_DISSECT:
                r = action_dissect(m, d);
                break;

        case ACTION_MOUNT:
                r = action_mount(m, d);
                break;

        case ACTION_COPY_FROM:
        case ACTION_COPY_TO:
                r = action_copy(m, d);
                break;

        default:
                assert_not_reached("Unknown action.");
        }

        return r;
}

DEFINE_MAIN_FUNCTION(run);
