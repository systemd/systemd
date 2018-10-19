/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <stdio.h>
#include <getopt.h>

#include "architecture.h"
#include "dissect-image.h"
#include "hexdecoct.h"
#include "log.h"
#include "loop-util.h"
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
static DissectImageFlags arg_flags = DISSECT_IMAGE_REQUIRE_ROOT|DISSECT_IMAGE_DISCARD_ON_LOOP;
static void *arg_root_hash = NULL;
static size_t arg_root_hash_size = 0;

static void help(void) {
        printf("%s [OPTIONS...] IMAGE\n"
               "%s [OPTIONS...] --mount IMAGE PATH\n"
               "Dissect a file system OS image.\n\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "  -m --mount           Mount the image to the specified directory\n"
               "  -r --read-only       Mount read-only\n"
               "     --discard=MODE    Choose 'discard' mode (disabled, loop, all, crypto)\n"
               "     --root-hash=HASH  Specify root hash for verity\n",
               program_invocation_short_name,
               program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_DISCARD,
                ARG_ROOT_HASH,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "mount",     no_argument,       NULL, 'm'           },
                { "read-only", no_argument,       NULL, 'r'           },
                { "discard",   required_argument, NULL, ARG_DISCARD   },
                { "root-hash", required_argument, NULL, ARG_ROOT_HASH },
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
                        else {
                                log_error("Unknown --discard= parameter: %s", optarg);
                                return -EINVAL;
                        }
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

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        }

        switch (arg_action) {

        case ACTION_DISSECT:
                if (optind + 1 != argc) {
                        log_error("Expected a file path as only argument.");
                        return -EINVAL;
                }

                arg_image = argv[optind];
                arg_flags |= DISSECT_IMAGE_READ_ONLY;
                break;

        case ACTION_MOUNT:
                if (optind + 2 != argc) {
                        log_error("Expected a file path and mount point path as only arguments.");
                        return -EINVAL;
                }

                arg_image = argv[optind];
                arg_path = argv[optind + 1];
                break;

        default:
                assert_not_reached("Unknown action.");
        }

        return 1;
}

int main(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *di = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = loop_device_make_by_path(arg_image, (arg_flags & DISSECT_IMAGE_READ_ONLY) ? O_RDONLY : O_RDWR, &d);
        if (r < 0) {
                log_error_errno(r, "Failed to set up loopback device: %m");
                goto finish;
        }

        if (!arg_root_hash) {
                r = root_hash_load(arg_image, &arg_root_hash, &arg_root_hash_size);
                if (r < 0) {
                        log_error_errno(r, "Failed to read root hash file for %s: %m", arg_image);
                        goto finish;
                }
        }

        r = dissect_image_and_warn(d->fd, arg_image, arg_root_hash, arg_root_hash_size, arg_flags, &m);
        if (r < 0)
                goto finish;

        switch (arg_action) {

        case ACTION_DISSECT: {
                unsigned i;

                for (i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                        DissectedPartition *p = m->partitions + i;
                        int k;

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

                        k = PARTITION_VERITY_OF(i);
                        if (k >= 0)
                                printf(" %s verity", m->partitions[k].found ? "with" : "without");

                        if (p->partno >= 0)
                                printf(" on partition #%i", p->partno);

                        if (p->node)
                                printf(" (%s)", p->node);

                        putchar('\n');
                }

                r = dissected_image_acquire_metadata(m);
                if (r < 0) {
                        log_error_errno(r, "Failed to acquire image metadata: %m");
                        goto finish;
                }

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
                r = dissected_image_decrypt_interactively(m, NULL, arg_root_hash, arg_root_hash_size, arg_flags, &di);
                if (r < 0)
                        goto finish;

                r = dissected_image_mount(m, arg_path, UID_INVALID, arg_flags);
                if (r < 0) {
                        log_error_errno(r, "Failed to mount image: %m");
                        goto finish;
                }

                if (di) {
                        r = decrypted_image_relinquish(di);
                        if (r < 0) {
                                log_error_errno(r, "Failed to relinquish DM devices: %m");
                                goto finish;
                        }
                }

                loop_device_relinquish(d);
                break;

        default:
                assert_not_reached("Unknown action.");
        }

finish:
        free(arg_root_hash);
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
