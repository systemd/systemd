/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <getopt.h>
#include <linux/loop.h>
#include <stdio.h>

#include "architecture.h"
#include "dissect-image.h"
#include "hexdecoct.h"
#include "log.h"
#include "loop-util.h"
#include "main-func.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"

static enum {
        ACTION_DISSECT,
        ACTION_MOUNT,
} arg_action = ACTION_DISSECT;
static const char *arg_image = NULL;
static const char *arg_path = NULL;
static DissectImageFlags arg_flags = DISSECT_IMAGE_REQUIRE_ROOT|DISSECT_IMAGE_DISCARD_ON_LOOP|DISSECT_IMAGE_RELAX_VAR_CHECK|DISSECT_IMAGE_FSCK;
static void *arg_root_hash = NULL;
static char *arg_verity_data = NULL;
static size_t arg_root_hash_size = 0;
static char *arg_root_hash_sig_path = NULL;
static void *arg_root_hash_sig = NULL;
static size_t arg_root_hash_sig_size = 0;

STATIC_DESTRUCTOR_REGISTER(arg_root_hash, freep);
STATIC_DESTRUCTOR_REGISTER(arg_verity_data, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_hash_sig_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_hash_sig, freep);

static void help(void) {
        printf("%s [OPTIONS...] IMAGE\n"
               "%s [OPTIONS...] --mount IMAGE PATH\n"
               "Dissect a file system OS image.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "  -m --mount              Mount the image to the specified directory\n"
               "  -r --read-only          Mount read-only\n"
               "     --fsck=BOOL          Run fsck before mounting\n"
               "     --discard=MODE       Choose 'discard' mode (disabled, loop, all, crypto)\n"
               "     --root-hash=HASH     Specify root hash for verity\n"
               "     --root-hash-sig=SIG  Specify pkcs7 signature of root hash for verity\n"
               "                          as a DER encoded PKCS7, either as a path to a file\n"
               "                          or as an ASCII base64 encoded string prefixed by\n"
               "                          'base64:'\n"
               "     --verity-data=PATH   Specify data file with hash tree for verity if it is\n"
               "                          not embedded in IMAGE\n",
               program_invocation_short_name,
               program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_DISCARD,
                ARG_ROOT_HASH,
                ARG_FSCK,
                ARG_VERITY_DATA,
                ARG_ROOT_HASH_SIG,
        };

        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'               },
                { "version",       no_argument,       NULL, ARG_VERSION       },
                { "mount",         no_argument,       NULL, 'm'               },
                { "read-only",     no_argument,       NULL, 'r'               },
                { "discard",       required_argument, NULL, ARG_DISCARD       },
                { "root-hash",     required_argument, NULL, ARG_ROOT_HASH     },
                { "fsck",          required_argument, NULL, ARG_FSCK          },
                { "verity-data",   required_argument, NULL, ARG_VERITY_DATA   },
                { "root-hash-sig", required_argument, NULL, ARG_ROOT_HASH_SIG },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hmr", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case 'm':
                        arg_action = ACTION_MOUNT;
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
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown --discard= parameter: %s",
                                                       optarg);
                        arg_flags = (arg_flags & ~DISSECT_IMAGE_DISCARD_ANY) | flags;

                        break;
                }

                case ARG_ROOT_HASH: {
                        void *p;
                        size_t l;

                        r = unhexmem(optarg, strlen(optarg), &p, &l);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse root hash '%s': %m", optarg);
                        if (l < sizeof(sd_id128_t)) {
                                log_error("Root hash must be at least 128bit long: %s", optarg);
                                free(p);
                                return -EINVAL;
                        }

                        free(arg_root_hash);
                        arg_root_hash = p;
                        arg_root_hash_size = l;
                        break;
                }

                case ARG_VERITY_DATA:
                        r = parse_path_argument_and_warn(optarg, false, &arg_verity_data);
                        if (r < 0)
                                return r;
                        break;

                case ARG_ROOT_HASH_SIG: {
                        char *value;

                        if ((value = startswith(optarg, "base64:"))) {
                                void *p;
                                size_t l;

                                r = unbase64mem(value, strlen(value), &p, &l);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse root hash signature '%s': %m", optarg);

                                free_and_replace(arg_root_hash_sig, p);
                                arg_root_hash_sig_size = l;
                                arg_root_hash_sig_path = mfree(arg_root_hash_sig_path);
                        } else {
                                r = parse_path_argument_and_warn(optarg, false, &arg_root_hash_sig_path);
                                if (r < 0)
                                        return r;
                                arg_root_hash_sig = mfree(arg_root_hash_sig);
                                arg_root_hash_sig_size = 0;
                        }

                        break;
                }

                case ARG_FSCK:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --fsck= parameter: %s", optarg);

                        SET_FLAG(arg_flags, DISSECT_IMAGE_FSCK, r);
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
                                               "Expected a file path as only argument.");

                arg_image = argv[optind];
                arg_flags |= DISSECT_IMAGE_READ_ONLY;
                break;

        case ACTION_MOUNT:
                if (optind + 2 != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Expected a file path and mount point path as only arguments.");

                arg_image = argv[optind];
                arg_path = argv[optind + 1];
                break;

        default:
                assert_not_reached("Unknown action.");
        }

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *di = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = loop_device_make_by_path(arg_image, (arg_flags & DISSECT_IMAGE_READ_ONLY) ? O_RDONLY : O_RDWR, LO_FLAGS_PARTSCAN, &d);
        if (r < 0)
                return log_error_errno(r, "Failed to set up loopback device: %m");

        r = verity_metadata_load(arg_image, NULL, arg_root_hash ? NULL : &arg_root_hash, &arg_root_hash_size,
                           arg_verity_data ? NULL : &arg_verity_data,
                           arg_root_hash_sig_path || arg_root_hash_sig ? NULL : &arg_root_hash_sig_path);
        if (r < 0)
                return log_error_errno(r, "Failed to read verity artefacts for %s: %m", arg_image);
        arg_flags |= arg_verity_data ? DISSECT_IMAGE_NO_PARTITION_TABLE : 0;

        r = dissect_image_and_warn(d->fd, arg_image, arg_root_hash, arg_root_hash_size, arg_verity_data, arg_flags, &m);
        if (r < 0)
                return r;

        switch (arg_action) {

        case ACTION_DISSECT: {
                unsigned i;

                for (i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                        DissectedPartition *p = m->partitions + i;

                        if (!p->found)
                                continue;

                        printf("Found %s '%s' partition",
                               p->rw ? "writable" : "read-only",
                               partition_designator_to_string(i));

                        if (!sd_id128_is_null(p->uuid))
                                printf(" (UUID " SD_ID128_FORMAT_STR ")", SD_ID128_FORMAT_VAL(p->uuid));

                        if (p->fstype)
                                printf(" of type %s", p->fstype);

                        if (p->architecture != _ARCHITECTURE_INVALID)
                                printf(" for %s", architecture_to_string(p->architecture));

                        if (dissected_image_can_do_verity(m, i))
                                printf(" %s verity", dissected_image_has_verity(m, i) ? "with" : "without");

                        if (p->partno >= 0)
                                printf(" on partition #%i", p->partno);

                        if (p->node)
                                printf(" (%s)", p->node);

                        putchar('\n');
                }

                r = dissected_image_acquire_metadata(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire image metadata: %m");

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

                break;
        }

        case ACTION_MOUNT:
                r = dissected_image_decrypt_interactively(m, NULL, arg_root_hash, arg_root_hash_size, arg_verity_data, arg_root_hash_sig_path, arg_root_hash_sig, arg_root_hash_sig_size, arg_flags, &di);
                if (r < 0)
                        return r;

                r = dissected_image_mount(m, arg_path, UID_INVALID, arg_flags);
                if (r == -EUCLEAN)
                        return log_error_errno(r, "File system check on image failed: %m");
                if (r < 0)
                        return log_error_errno(r, "Failed to mount image: %m");

                if (di) {
                        r = decrypted_image_relinquish(di);
                        if (r < 0)
                                return log_error_errno(r, "Failed to relinquish DM devices: %m");
                }

                loop_device_relinquish(d);
                break;

        default:
                assert_not_reached("Unknown action.");
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
