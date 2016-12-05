/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <fcntl.h>
#include <stdio.h>
#include <getopt.h>

#include "architecture.h"
#include "dissect-image.h"
#include "log.h"
#include "loop-util.h"
#include "string-util.h"
#include "util.h"

static enum {
        ACTION_DISSECT,
        ACTION_MOUNT,
} arg_action = ACTION_DISSECT;
static const char *arg_image = NULL;
static const char *arg_path = NULL;
static DissectImageFlags arg_flags = DISSECT_IMAGE_DISCARD_ON_LOOP;

static void help(void) {
        printf("%s [OPTIONS...] IMAGE\n"
               "%s [OPTIONS...] --mount IMAGE PATH\n"
               "Dissect a file system OS image.\n\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "  -m --mount           Mount the image to the specified directory\n"
               "  -r --read-only       Mount read-only\n"
               "     --discard=MODE    Choose 'discard' mode (disabled, loop, all, crypto)\n",
               program_invocation_short_name,
               program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_DISCARD,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "mount",     no_argument,       NULL, 'm'           },
                { "read-only", no_argument,       NULL, 'r'           },
                { "discard",   required_argument, NULL, ARG_DISCARD   },
                {}
        };

        int c;

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

                case ARG_DISCARD:
                        if (streq(optarg, "disabled"))
                                arg_flags &= ~(DISSECT_IMAGE_DISCARD_ON_LOOP|DISSECT_IMAGE_DISCARD|DISSECT_IMAGE_DISCARD_ON_CRYPTO);
                        else if (streq(optarg, "loop"))
                                arg_flags = (arg_flags & ~(DISSECT_IMAGE_DISCARD|DISSECT_IMAGE_DISCARD_ON_CRYPTO)) | DISSECT_IMAGE_DISCARD_ON_LOOP;
                        else if (streq(optarg, "all"))
                                arg_flags = (arg_flags & ~(DISSECT_IMAGE_DISCARD_ON_CRYPTO)) | DISSECT_IMAGE_DISCARD_ON_LOOP | DISSECT_IMAGE_DISCARD;
                        else if (streq(optarg, "crypt"))
                                arg_flags |= DISSECT_IMAGE_DISCARD_ON_LOOP | DISSECT_IMAGE_DISCARD | DISSECT_IMAGE_DISCARD_ON_CRYPTO;
                        else {
                                log_error("Unknown --discard= parameter: %s", optarg);
                                return -EINVAL;
                        }

                        break;

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

        r = dissect_image(d->fd, &m);
        if (r == -ENOPKG) {
                log_error_errno(r, "Couldn't identify a suitable partition table or file system in %s.", arg_image);
                goto finish;
        }
        if (r < 0) {
                log_error_errno(r, "Failed to dissect image: %m");
                goto finish;
        }

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

                        if (p->fstype)
                                printf(" of type %s", p->fstype);

                        if (p->architecture != _ARCHITECTURE_INVALID)
                                printf(" for %s", architecture_to_string(p->architecture));

                        if (p->partno >= 0)
                                printf(" on partition #%i", p->partno);

                        if (p->node)
                                printf(" (%s)", p->node);

                        putchar('\n');
                }

                break;
        }

        case ACTION_MOUNT:
                r = dissected_image_decrypt_interactively(m, NULL, arg_flags, &di);
                if (r < 0)
                        goto finish;

                r = dissected_image_mount(m, arg_path, arg_flags);
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
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
