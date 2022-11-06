/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <linux/loop.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mount.h>

#include "sd-device.h"

#include "architecture.h"
#include "blockdev-util.h"
#include "chase-symlinks.h"
#include "copy.h"
#include "device-util.h"
#include "devnum-util.h"
#include "dissect-image.h"
#include "env-util.h"
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
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "recurse-dir.h"
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
        ACTION_UMOUNT,
        ACTION_LIST,
        ACTION_COPY_FROM,
        ACTION_COPY_TO,
} arg_action = ACTION_DISSECT;
static const char *arg_image = NULL;
static const char *arg_path = NULL;
static const char *arg_source = NULL;
static const char *arg_target = NULL;
static DissectImageFlags arg_flags =
        DISSECT_IMAGE_GENERIC_ROOT |
        DISSECT_IMAGE_DISCARD_ON_LOOP |
        DISSECT_IMAGE_RELAX_VAR_CHECK |
        DISSECT_IMAGE_FSCK |
        DISSECT_IMAGE_USR_NO_ROOT |
        DISSECT_IMAGE_GROWFS;
static VeritySettings arg_verity_settings = VERITY_SETTINGS_DEFAULT;
static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static bool arg_rmdir = false;

STATIC_DESTRUCTOR_REGISTER(arg_verity_settings, verity_settings_done);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-dissect", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] IMAGE\n"
               "%1$s [OPTIONS...] --mount IMAGE PATH\n"
               "%1$s [OPTIONS...] --umount PATH\n"
               "%1$s [OPTIONS...] --list IMAGE\n"
               "%1$s [OPTIONS...] --copy-from IMAGE PATH [TARGET]\n"
               "%1$s [OPTIONS...] --copy-to IMAGE [SOURCE] PATH\n\n"
               "%5$sDissect a Discoverable Disk Image (DDI).%6$s\n\n"
               "%3$sOptions:%4$s\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --no-legend          Do not show the headers and footers\n"
               "  -r --read-only          Mount read-only\n"
               "     --fsck=BOOL          Run fsck before mounting\n"
               "     --growfs=BOOL        Grow file system to partition size, if marked\n"
               "     --mkdir              Make mount directory before mounting, if missing\n"
               "     --rmdir              Remove mount directory after unmounting\n"
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
               "  -u --umount             Unmount the image from the specified directory\n"
               "  -U                      Shortcut for --umount --rmdir\n"
               "  -l --list               List all the files and directories of the specified\n"
               "                          OS image\n"
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
                ARG_GROWFS,
                ARG_ROOT_HASH,
                ARG_ROOT_HASH_SIG,
                ARG_VERITY_DATA,
                ARG_MKDIR,
                ARG_RMDIR,
                ARG_JSON,
        };

        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'               },
                { "version",       no_argument,       NULL, ARG_VERSION       },
                { "no-pager",      no_argument,       NULL, ARG_NO_PAGER      },
                { "no-legend",     no_argument,       NULL, ARG_NO_LEGEND     },
                { "mount",         no_argument,       NULL, 'm'               },
                { "umount",        no_argument,       NULL, 'u'               },
                { "read-only",     no_argument,       NULL, 'r'               },
                { "discard",       required_argument, NULL, ARG_DISCARD       },
                { "fsck",          required_argument, NULL, ARG_FSCK          },
                { "growfs",        required_argument, NULL, ARG_GROWFS        },
                { "root-hash",     required_argument, NULL, ARG_ROOT_HASH     },
                { "root-hash-sig", required_argument, NULL, ARG_ROOT_HASH_SIG },
                { "verity-data",   required_argument, NULL, ARG_VERITY_DATA   },
                { "mkdir",         no_argument,       NULL, ARG_MKDIR         },
                { "rmdir",         no_argument,       NULL, ARG_RMDIR         },
                { "list",          no_argument,       NULL, 'l'               },
                { "copy-from",     no_argument,       NULL, 'x'               },
                { "copy-to",       no_argument,       NULL, 'a'               },
                { "json",          required_argument, NULL, ARG_JSON          },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hmurMUlxa", options, NULL)) >= 0) {

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

                case 'u':
                        arg_action = ACTION_UMOUNT;
                        break;

                case ARG_RMDIR:
                        arg_rmdir = true;
                        break;

                case 'U':
                        /* Shortcut combination of the above two */
                        arg_action = ACTION_UMOUNT;
                        arg_rmdir = true;
                        break;

                case 'l':
                        arg_action = ACTION_LIST;
                        arg_flags |= DISSECT_IMAGE_READ_ONLY;
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

                case ARG_GROWFS:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --growfs= parameter: %s", optarg);

                        SET_FLAG(arg_flags, DISSECT_IMAGE_GROWFS, r);
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
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
                arg_flags |= DISSECT_IMAGE_REQUIRE_ROOT;
                break;

        case ACTION_UMOUNT:
                if (optind + 1 != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Expected a mount point path as only argument.");

                arg_path = argv[optind];
                break;

        case ACTION_LIST:
                if (optind + 1 != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Expected an image file path as only argument.");

                arg_image = argv[optind];
                arg_flags |= DISSECT_IMAGE_READ_ONLY | DISSECT_IMAGE_REQUIRE_ROOT;
                break;

        case ACTION_COPY_FROM:
                if (argc < optind + 2 || argc > optind + 3)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Expected an image file path, a source path and an optional destination path as only arguments.");

                arg_image = argv[optind];
                arg_source = argv[optind + 1];
                arg_target = argc > optind + 2 ? argv[optind + 2] : "-" /* this means stdout */ ;

                arg_flags |= DISSECT_IMAGE_READ_ONLY | DISSECT_IMAGE_REQUIRE_ROOT;
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

                arg_flags |= DISSECT_IMAGE_REQUIRE_ROOT;
                break;

        default:
                assert_not_reached();
        }

        return 1;
}

static int strv_pair_to_json(char **l, JsonVariant **ret) {
        _cleanup_strv_free_ char **jl = NULL;

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

static void strv_pair_print(char **l, const char *prefix) {
        assert(prefix);

        STRV_FOREACH_PAIR(p, q, l)
                if (p == l)
                        printf("%s %s=%s\n", prefix, *p, *q);
                else
                        printf("%*s %s=%s\n", (int) strlen(prefix), "", *p, *q);
}

static int get_sysext_scopes(DissectedImage *m, char ***ret_scopes) {
        _cleanup_strv_free_ char **l = NULL;
        const char *e;

        assert(m);
        assert(ret_scopes);

        /* If there's no extension-release file its not a system extension. Otherwise the SYSEXT_SCOPE field
         * indicates which scope it is for — and it defaults to "system" + "portable" if unset. */

        if (!m->extension_release) {
                *ret_scopes = NULL;
                return 0;
        }

        e = strv_env_pairs_get(m->extension_release, "SYSEXT_SCOPE");
        if (e)
                l = strv_split(e, WHITESPACE);
        else
                l = strv_new("system", "portable");
        if (!l)
                return -ENOMEM;

        *ret_scopes = TAKE_PTR(l);
        return 1;
}

static int action_dissect(DissectedImage *m, LoopDevice *d) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *bn = NULL;
        uint64_t size = UINT64_MAX;
        int r;

        assert(m);
        assert(d);

        r = path_extract_filename(arg_image, &bn);
        if (r < 0)
                return log_error_errno(r, "Failed to extract file name from image path '%s': %m", arg_image);

        if (arg_json_format_flags & (JSON_FORMAT_OFF|JSON_FORMAT_PRETTY|JSON_FORMAT_PRETTY_AUTO))
                pager_open(arg_pager_flags);

        if (arg_json_format_flags & JSON_FORMAT_OFF)
                printf("      Name: %s\n", bn);

        if (ioctl(d->fd, BLKGETSIZE64, &size) < 0)
                log_debug_errno(errno, "Failed to query size of loopback device: %m");
        else if (arg_json_format_flags & JSON_FORMAT_OFF)
                printf("      Size: %s\n", FORMAT_BYTES(size));

        if (arg_json_format_flags & JSON_FORMAT_OFF)
                putc('\n', stdout);

        r = dissected_image_acquire_metadata(m, 0);
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
                _cleanup_strv_free_ char **sysext_scopes = NULL;

                if (m->hostname)
                        printf("  Hostname: %s\n", m->hostname);

                if (!sd_id128_is_null(m->machine_id))
                        printf("Machine ID: " SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(m->machine_id));

                strv_pair_print(m->machine_info,
                               "Mach. Info:");
                strv_pair_print(m->os_release,
                               "OS Release:");
                strv_pair_print(m->extension_release,
                               " Ext. Rel.:");

                if (m->hostname ||
                    !sd_id128_is_null(m->machine_id) ||
                    !strv_isempty(m->machine_info) ||
                    !strv_isempty(m->os_release) ||
                    !strv_isempty(m->extension_release))
                        putc('\n', stdout);

                printf("    Use As: %s bootable system for UEFI\n", COLOR_MARK_BOOL(m->partitions[PARTITION_ESP].found));

                if (m->has_init_system >= 0)
                        printf("            %s bootable system for container\n", COLOR_MARK_BOOL(m->has_init_system));

                printf("            %s portable service\n",
                       COLOR_MARK_BOOL(strv_env_pairs_get(m->os_release, "PORTABLE_PREFIXES")));

                r = get_sysext_scopes(m, &sysext_scopes);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse SYSEXT_SCOPE: %m");

                printf("            %s extension for system\n",
                       COLOR_MARK_BOOL(strv_contains(sysext_scopes, "system")));
                printf("            %s extension for initrd\n",
                       COLOR_MARK_BOOL(strv_contains(sysext_scopes, "initrd")));
                printf("            %s extension for portable service\n",
                       COLOR_MARK_BOOL(strv_contains(sysext_scopes, "portable")));

                putc('\n', stdout);
        } else {
                _cleanup_(json_variant_unrefp) JsonVariant *mi = NULL, *osr = NULL, *exr = NULL;
                _cleanup_strv_free_ char **sysext_scopes = NULL;

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

                r = get_sysext_scopes(m, &sysext_scopes);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse SYSEXT_SCOPE: %m");

                r = json_build(&v, JSON_BUILD_OBJECT(
                                               JSON_BUILD_PAIR("name", JSON_BUILD_STRING(bn)),
                                               JSON_BUILD_PAIR("size", JSON_BUILD_INTEGER(size)),
                                               JSON_BUILD_PAIR_CONDITION(m->hostname, "hostname", JSON_BUILD_STRING(m->hostname)),
                                               JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(m->machine_id), "machineId", JSON_BUILD_ID128(m->machine_id)),
                                               JSON_BUILD_PAIR_CONDITION(mi, "machineInfo", JSON_BUILD_VARIANT(mi)),
                                               JSON_BUILD_PAIR_CONDITION(osr, "osRelease", JSON_BUILD_VARIANT(osr)),
                                               JSON_BUILD_PAIR_CONDITION(exr, "extensionRelease", JSON_BUILD_VARIANT(exr)),
                                               JSON_BUILD_PAIR("useBootableUefi", JSON_BUILD_BOOLEAN(m->partitions[PARTITION_ESP].found)),
                                               JSON_BUILD_PAIR_CONDITION(m->has_init_system >= 0, "useBootableContainer", JSON_BUILD_BOOLEAN(m->has_init_system)),
                                               JSON_BUILD_PAIR("usePortableService", JSON_BUILD_BOOLEAN(strv_env_pairs_get(m->os_release, "PORTABLE_MATCHES"))),
                                               JSON_BUILD_PAIR("useSystemExtension", JSON_BUILD_BOOLEAN(strv_contains(sysext_scopes, "system"))),
                                               JSON_BUILD_PAIR("useInitRDExtension", JSON_BUILD_BOOLEAN(strv_contains(sysext_scopes, "initrd"))),
                                               JSON_BUILD_PAIR("usePortableExtension", JSON_BUILD_BOOLEAN(strv_contains(sysext_scopes, "portable")))));
                if (r < 0)
                        return log_oom();
        }

        t = table_new("rw", "designator", "partition uuid", "partition label", "fstype", "architecture", "verity", "growfs", "node", "partno");
        if (!t)
                return log_oom();

        table_set_ersatz_string(t, TABLE_ERSATZ_DASH);
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
                                TABLE_STRING, p->label,
                                TABLE_STRING, p->fstype,
                                TABLE_STRING, architecture_to_string(p->architecture));
                if (r < 0)
                        return table_log_add_error(r);

                if (arg_verity_settings.data_path)
                        r = table_add_cell(t, NULL, TABLE_STRING, "external");
                else if (dissected_image_verity_candidate(m, i))
                        r = table_add_cell(t, NULL, TABLE_STRING,
                                           dissected_image_verity_sig_ready(m, i) ? "signed" :
                                           yes_no(dissected_image_verity_ready(m, i)));
                else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_many(t, TABLE_BOOLEAN, (int) p->growfs);
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
        int r;

        assert(m);
        assert(d);

        r = dissected_image_decrypt_interactively(
                        m, NULL,
                        &arg_verity_settings,
                        arg_flags);
        if (r < 0)
                return r;

        r = dissected_image_mount_and_warn(m, arg_path, UID_INVALID, UID_INVALID, arg_flags);
        if (r < 0)
                return r;

        r = loop_device_flock(d, LOCK_UN);
        if (r < 0)
                return log_error_errno(r, "Failed to unlock loopback block device: %m");

        r = dissected_image_relinquish(m);
        if (r < 0)
                return log_error_errno(r, "Failed to relinquish DM and loopback block devices: %m");

        return 0;
}

static int list_print_item(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        assert_se(path);

        if (event == RECURSE_DIR_ENTER)
                printf("%s/\n", path);
        else if (event == RECURSE_DIR_ENTRY)
                printf("%s\n", path);

        return RECURSE_DIR_CONTINUE;
}

static int action_list_or_copy(DissectedImage *m, LoopDevice *d) {
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_(rmdir_and_freep) char *created_dir = NULL;
        _cleanup_free_ char *temp = NULL;
        int r;

        assert(m);
        assert(d);

        r = dissected_image_decrypt_interactively(
                        m, NULL,
                        &arg_verity_settings,
                        arg_flags);
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

        r = dissected_image_mount_and_warn(m, created_dir, UID_INVALID, UID_INVALID, arg_flags);
        if (r < 0)
                return r;

        mounted_dir = TAKE_PTR(created_dir);

        r = loop_device_flock(d, LOCK_UN);
        if (r < 0)
                return log_error_errno(r, "Failed to unlock loopback block device: %m");

        r = dissected_image_relinquish(m);
        if (r < 0)
                return log_error_errno(r, "Failed to relinquish DM and loopback block devices: %m");

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

                (void) copy_xattr(source_fd, target_fd, 0);
                (void) copy_access(source_fd, target_fd);
                (void) copy_times(source_fd, target_fd, 0);

                /* When this is a regular file we don't copy ownership! */

        } else if (arg_action == ACTION_COPY_TO) {
                _cleanup_close_ int source_fd = -1, target_fd = -1, dfd = -1;
                _cleanup_free_ char *dn = NULL, *bn = NULL;

                r = path_extract_directory(arg_target, &dn);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract directory from target path '%s': %m", arg_target);
                r = path_extract_filename(arg_target, &bn);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from target path '%s': %m", arg_target);

                r = chase_symlinks(dn, mounted_dir, CHASE_PREFIX_ROOT|CHASE_WARN, NULL, &dfd);
                if (r < 0)
                        return log_error_errno(r, "Failed to open '%s': %m", dn);

                /* Are we reading from stdin? */
                if (streq(arg_source, "-")) {
                        target_fd = openat(dfd, bn, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY|O_EXCL, 0644);
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

                        target_fd = openat(dfd, bn, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                        if (target_fd < 0) {
                                if (errno != ENOENT)
                                        return log_error_errno(errno, "Failed to open destination '%s': %m", arg_target);

                                r = copy_tree_at(source_fd, ".", dfd, bn, UID_INVALID, GID_INVALID, COPY_REFLINK|COPY_REPLACE|COPY_SIGINT|COPY_HARDLINKS);
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

                (void) copy_xattr(source_fd, target_fd, 0);
                (void) copy_access(source_fd, target_fd);
                (void) copy_times(source_fd, target_fd, 0);

                /* When this is a regular file we don't copy ownership! */

        } else {
                _cleanup_close_ int dfd = -1;
                _cleanup_strv_free_ char **list_dir = NULL;

                assert(arg_action == ACTION_LIST);

                dfd = open(mounted_dir, O_DIRECTORY|O_CLOEXEC|O_RDONLY);
                if (dfd < 0)
                        return log_error_errno(errno, "Failed to open mount directory: %m");

                r = recurse_dir(dfd, NULL, 0, UINT_MAX, RECURSE_DIR_SORT|RECURSE_DIR_ENSURE_TYPE|RECURSE_DIR_SAME_MOUNT, list_print_item, &list_dir);
                if (r < 0)
                        return log_error_errno(r, "Failed to list image: %m");
        }

        return 0;
}

static int action_umount(const char *path) {
        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *canonical = NULL, *devname = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
        dev_t devno;
        int r;

        fd = chase_symlinks_and_open(path, NULL, 0, O_DIRECTORY, &canonical);
        if (fd == -ENOTDIR)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTDIR), "'%s' is not a directory", path);
        if (fd < 0)
                return log_error_errno(fd, "Failed to resolve path '%s': %m", path);

        r = fd_is_mount_point(fd, NULL, 0);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "'%s' is not a mount point", canonical);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether '%s' is a mount point: %m", canonical);

        r = fd_get_whole_disk(fd, /*backing=*/ true, &devno);
        if (r < 0)
                return log_error_errno(r, "Failed to find backing block device for '%s': %m", canonical);

        r = devname_from_devnum(S_IFBLK, devno, &devname);
        if (r < 0)
                return log_error_errno(r, "Failed to get devname of block device " DEVNUM_FORMAT_STR ": %m",
                                       DEVNUM_FORMAT_VAL(devno));

        r = loop_device_open_from_path(devname, 0, LOCK_EX, &d);
        if (r < 0)
                return log_error_errno(r, "Failed to open loop device '%s': %m", devname);

        /* We've locked the loop device, now we're ready to unmount. To allow the unmount to succeed, we have
         * to close the O_PATH fd we opened earlier. */
        fd = safe_close(fd);

        r = umount_recursive(canonical, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to unmount '%s': %m", canonical);

        /* We managed to lock and unmount successfully? That means we can try to remove the loop device.*/
        loop_device_unrelinquish(d);

        if (arg_rmdir) {
                r = RET_NERRNO(rmdir(canonical));
                if (r < 0)
                        return log_error_errno(r, "Failed to remove mount directory '%s': %m", canonical);
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

        if (arg_action == ACTION_UMOUNT)
                return action_umount(arg_path);

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
                        FLAGS_SET(arg_flags, DISSECT_IMAGE_DEVICE_READ_ONLY) ? O_RDONLY : O_RDWR,
                        FLAGS_SET(arg_flags, DISSECT_IMAGE_NO_PARTITION_TABLE) ? 0 : LO_FLAGS_PARTSCAN,
                        LOCK_SH,
                        &d);
        if (r < 0)
                return log_error_errno(r, "Failed to set up loopback device for %s: %m", arg_image);

        r = dissect_loop_device_and_warn(
                        d,
                        &arg_verity_settings,
                        NULL,
                        arg_flags,
                        &m);
        if (r < 0)
                return r;

        r = dissected_image_load_verity_sig_partition(
                        m,
                        d->fd,
                        &arg_verity_settings);
        if (r < 0)
                return log_error_errno(r, "Failed to load verity signature partition: %m");

        switch (arg_action) {

        case ACTION_DISSECT:
                r = action_dissect(m, d);
                break;

        case ACTION_MOUNT:
                r = action_mount(m, d);
                break;

        case ACTION_LIST:
        case ACTION_COPY_FROM:
        case ACTION_COPY_TO:
                r = action_list_or_copy(m, d);
                break;

        default:
                assert_not_reached();
        }

        return r;
}

DEFINE_MAIN_FUNCTION(run);
