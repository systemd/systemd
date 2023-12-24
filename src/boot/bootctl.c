/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "blockdev-util.h"
#include "bootctl.h"
#include "bootctl-install.h"
#include "bootctl-random-seed.h"
#include "bootctl-reboot-to-firmware.h"
#include "bootctl-set-efivar.h"
#include "bootctl-status.h"
#include "bootctl-systemd-efi-options.h"
#include "bootctl-uki.h"
#include "build.h"
#include "devnum-util.h"
#include "dissect-image.h"
#include "escape.h"
#include "find-esp.h"
#include "main-func.h"
#include "mount-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "utf8.h"
#include "verbs.h"
#include "virt.h"

/* EFI_BOOT_OPTION_DESCRIPTION_MAX sets the maximum length for the boot option description
 * stored in NVRAM. The UEFI spec does not specify a minimum or maximum length for this
 * string, but we limit the length to something reasonable to prevent from the firmware
 * having to deal with a potentially too long string. */
#define EFI_BOOT_OPTION_DESCRIPTION_MAX ((size_t) 255)

char *arg_esp_path = NULL;
char *arg_xbootldr_path = NULL;
bool arg_print_esp_path = false;
bool arg_print_dollar_boot_path = false;
unsigned arg_print_root_device = 0;
bool arg_touch_variables = true;
PagerFlags arg_pager_flags = 0;
bool arg_graceful = false;
bool arg_quiet = false;
int arg_make_entry_directory = false; /* tri-state: < 0 for automatic logic */
sd_id128_t arg_machine_id = SD_ID128_NULL;
char *arg_install_layout = NULL;
BootEntryTokenType arg_entry_token_type = BOOT_ENTRY_TOKEN_AUTO;
char *arg_entry_token = NULL;
JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
bool arg_arch_all = false;
char *arg_root = NULL;
char *arg_image = NULL;
InstallSource arg_install_source = ARG_INSTALL_SOURCE_AUTO;
char *arg_efi_boot_option_description = NULL;
bool arg_dry_run = false;
ImagePolicy *arg_image_policy = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_esp_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_xbootldr_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_install_layout, freep);
STATIC_DESTRUCTOR_REGISTER(arg_entry_token, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_efi_boot_option_description, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);

int acquire_esp(
                int unprivileged_mode,
                bool graceful,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        char *np;
        int r;

        /* Find the ESP, and log about errors. Note that find_esp_and_warn() will log in all error cases on
         * its own, except for ENOKEY (which is good, we want to show our own message in that case,
         * suggesting use of --esp-path=) and EACCESS (only when we request unprivileged mode; in this case
         * we simply eat up the error here, so that --list and --status work too, without noise about
         * this). */

        r = find_esp_and_warn(arg_root, arg_esp_path, unprivileged_mode, &np, ret_part, ret_pstart, ret_psize, ret_uuid, ret_devid);
        if (r == -ENOKEY) {
                if (graceful)
                        return log_full_errno(arg_quiet ? LOG_DEBUG : LOG_INFO, r,
                                              "Couldn't find EFI system partition, skipping.");

                return log_error_errno(r,
                                       "Couldn't find EFI system partition. It is recommended to mount it to /boot or /efi.\n"
                                       "Alternatively, use --esp-path= to specify path to mount point.");
        }
        if (r < 0)
                return r;

        free_and_replace(arg_esp_path, np);
        log_debug("Using EFI System Partition at %s.", arg_esp_path);

        return 0;
}

int acquire_xbootldr(
                int unprivileged_mode,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        char *np;
        int r;

        r = find_xbootldr_and_warn(arg_root, arg_xbootldr_path, unprivileged_mode, &np, ret_uuid, ret_devid);
        if (r == -ENOKEY) {
                log_debug_errno(r, "Didn't find an XBOOTLDR partition, using the ESP as $BOOT.");
                arg_xbootldr_path = mfree(arg_xbootldr_path);

                if (ret_uuid)
                        *ret_uuid = SD_ID128_NULL;
                if (ret_devid)
                        *ret_devid = 0;
                return 0;
        }
        if (r < 0)
                return r;

        free_and_replace(arg_xbootldr_path, np);
        log_debug("Using XBOOTLDR partition at %s as $BOOT.", arg_xbootldr_path);

        return 1;
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("bootctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n"
               "\n%5$sControl EFI firmware boot settings and manage boot loader.%6$s\n"
               "\n%3$sGeneric EFI Firmware/Boot Loader Commands:%4$s\n"
               "  status               Show status of installed boot loader and EFI variables\n"
               "  reboot-to-firmware [BOOL]\n"
               "                       Query or set reboot-to-firmware EFI flag\n"
               "\n%3$sBoot Loader Specification Commands:%4$s\n"
               "  list                 List boot loader entries\n"
               "  unlink ID            Remove boot loader entry\n"
               "  cleanup              Remove files in ESP not referenced in any boot entry\n"
               "\n%3$sBoot Loader Interface Commands:%4$s\n"
               "  set-default ID       Set default boot loader entry\n"
               "  set-oneshot ID       Set default boot loader entry, for next boot only\n"
               "  set-timeout SECONDS  Set the menu timeout\n"
               "  set-timeout-oneshot SECONDS\n"
               "                       Set the menu timeout for the next boot only\n"
               "\n%3$ssystemd-boot Commands:%4$s\n"
               "  install              Install systemd-boot to the ESP and EFI variables\n"
               "  update               Update systemd-boot in the ESP and EFI variables\n"
               "  remove               Remove systemd-boot from the ESP and EFI variables\n"
               "  is-installed         Test whether systemd-boot is installed in the ESP\n"
               "  random-seed          Initialize or refresh random seed in ESP and EFI\n"
               "                       variables\n"
               "\n%3$sKernel Image Commands:%4$s\n"
               "  kernel-identify      Identify kernel image type\n"
               "  kernel-inspect       Prints details about the kernel image\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help            Show this help\n"
               "     --version         Print version\n"
               "     --esp-path=PATH   Path to the EFI System Partition (ESP)\n"
               "     --boot-path=PATH  Path to the $BOOT partition\n"
               "     --root=PATH       Operate on an alternate filesystem root\n"
               "     --image=PATH      Operate on disk image as filesystem root\n"
               "     --image-policy=POLICY\n"
               "                       Specify disk image dissection policy\n"
               "     --install-source=auto|image|host\n"
               "                       Where to pick files when using --root=/--image=\n"
               "  -p --print-esp-path  Print path to the EFI System Partition mount point\n"
               "  -x --print-boot-path Print path to the $BOOT partition mount point\n"
               "  -R --print-root-device\n"
               "                       Print path to the block device node backing the\n"
               "                       root file system (returns e.g. /dev/nvme0n1p5)\n"
               "  -RR                  Print path to the whole disk block device node\n"
               "                       backing the root FS (returns e.g. /dev/nvme0n1)\n"
               "     --no-variables    Don't touch EFI variables\n"
               "     --no-pager        Do not pipe output into a pager\n"
               "     --graceful        Don't fail when the ESP cannot be found or EFI\n"
               "                       variables cannot be written\n"
               "  -q --quiet           Suppress output\n"
               "     --make-entry-directory=yes|no|auto\n"
               "                       Create $BOOT/ENTRY-TOKEN/ directory\n"
               "     --entry-token=machine-id|os-id|os-image-id|auto|literal:…\n"
               "                       Entry token to use for this installation\n"
               "     --json=pretty|short|off\n"
               "                       Generate JSON output\n"
               "     --all-architectures\n"
               "                       Install all supported EFI architectures\n"
               "     --efi-boot-option-description=DESCRIPTION\n"
               "                       Description of the entry in the boot option list\n"
               "     --dry-run         Dry run (unlink and cleanup)\n"
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
                ARG_ESP_PATH = 0x100,
                ARG_BOOT_PATH,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
                ARG_INSTALL_SOURCE,
                ARG_VERSION,
                ARG_NO_VARIABLES,
                ARG_NO_PAGER,
                ARG_GRACEFUL,
                ARG_MAKE_ENTRY_DIRECTORY,
                ARG_ENTRY_TOKEN,
                ARG_JSON,
                ARG_ARCH_ALL,
                ARG_EFI_BOOT_OPTION_DESCRIPTION,
                ARG_DRY_RUN,
        };

        static const struct option options[] = {
                { "help",                        no_argument,       NULL, 'h'                             },
                { "version",                     no_argument,       NULL, ARG_VERSION                     },
                { "esp-path",                    required_argument, NULL, ARG_ESP_PATH                    },
                { "path",                        required_argument, NULL, ARG_ESP_PATH                    }, /* Compatibility alias */
                { "boot-path",                   required_argument, NULL, ARG_BOOT_PATH                   },
                { "root",                        required_argument, NULL, ARG_ROOT                        },
                { "image",                       required_argument, NULL, ARG_IMAGE                       },
                { "image-policy",                required_argument, NULL, ARG_IMAGE_POLICY                },
                { "install-source",              required_argument, NULL, ARG_INSTALL_SOURCE              },
                { "print-esp-path",              no_argument,       NULL, 'p'                             },
                { "print-path",                  no_argument,       NULL, 'p'                             }, /* Compatibility alias */
                { "print-boot-path",             no_argument,       NULL, 'x'                             },
                { "print-root-device",           no_argument,       NULL, 'R'                             },
                { "no-variables",                no_argument,       NULL, ARG_NO_VARIABLES                },
                { "no-pager",                    no_argument,       NULL, ARG_NO_PAGER                    },
                { "graceful",                    no_argument,       NULL, ARG_GRACEFUL                    },
                { "quiet",                       no_argument,       NULL, 'q'                             },
                { "make-entry-directory",        required_argument, NULL, ARG_MAKE_ENTRY_DIRECTORY        },
                { "make-machine-id-directory",   required_argument, NULL, ARG_MAKE_ENTRY_DIRECTORY        }, /* Compatibility alias */
                { "entry-token",                 required_argument, NULL, ARG_ENTRY_TOKEN                 },
                { "json",                        required_argument, NULL, ARG_JSON                        },
                { "all-architectures",           no_argument,       NULL, ARG_ARCH_ALL                    },
                { "efi-boot-option-description", required_argument, NULL, ARG_EFI_BOOT_OPTION_DESCRIPTION },
                { "dry-run",                     no_argument,       NULL, ARG_DRY_RUN                     },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hpxRq", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help(0, NULL, NULL);
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_ESP_PATH:
                        r = free_and_strdup(&arg_esp_path, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

                case ARG_BOOT_PATH:
                        r = free_and_strdup(&arg_xbootldr_path, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

                case ARG_ROOT:
                        r = parse_path_argument(optarg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE_POLICY:
                        r = parse_image_policy_argument(optarg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                case ARG_INSTALL_SOURCE:
                        if (streq(optarg, "auto"))
                                arg_install_source = ARG_INSTALL_SOURCE_AUTO;
                        else if (streq(optarg, "image"))
                                arg_install_source = ARG_INSTALL_SOURCE_IMAGE;
                        else if (streq(optarg, "host"))
                                arg_install_source = ARG_INSTALL_SOURCE_HOST;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected parameter for --install-source=: %s", optarg);

                        break;

                case 'p':
                        arg_print_esp_path = true;
                        break;

                case 'x':
                        arg_print_dollar_boot_path = true;
                        break;

                case 'R':
                        arg_print_root_device++;
                        break;

                case ARG_NO_VARIABLES:
                        arg_touch_variables = false;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_GRACEFUL:
                        arg_graceful = true;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_ENTRY_TOKEN:
                        r = parse_boot_entry_token_type(optarg, &arg_entry_token_type, &arg_entry_token);
                        if (r < 0)
                                return r;
                        break;

                case ARG_MAKE_ENTRY_DIRECTORY:
                        if (streq(optarg, "auto"))  /* retained for backwards compatibility */
                                arg_make_entry_directory = -1; /* yes if machine-id is permanent */
                        else {
                                r = parse_boolean_argument("--make-entry-directory=", optarg, NULL);
                                if (r < 0)
                                        return r;

                                arg_make_entry_directory = r;
                        }
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                case ARG_ARCH_ALL:
                        arg_arch_all = true;
                        break;

                case ARG_EFI_BOOT_OPTION_DESCRIPTION:
                        if (isempty(optarg) || !(string_is_safe(optarg) && utf8_is_valid(optarg))) {
                                _cleanup_free_ char *escaped = NULL;

                                escaped = cescape(optarg);
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid --efi-boot-option-description=: %s", strna(escaped));
                        }
                        if (strlen(optarg) > EFI_BOOT_OPTION_DESCRIPTION_MAX)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--efi-boot-option-description= too long: %zu > %zu",
                                                       strlen(optarg), EFI_BOOT_OPTION_DESCRIPTION_MAX);
                        r = free_and_strdup_warn(&arg_efi_boot_option_description, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_DRY_RUN:
                        arg_dry_run = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (!!arg_print_esp_path + !!arg_print_dollar_boot_path + (arg_print_root_device > 0) > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--print-esp-path/-p, --print-boot-path/-x, --print-root-device=/-R cannot be combined.");

        if ((arg_root || arg_image) && argv[optind] && !STR_IN_SET(argv[optind], "status", "list",
                        "install", "update", "remove", "is-installed", "random-seed", "unlink", "cleanup"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Options --root= and --image= are not supported with verb %s.",
                                       argv[optind]);

        if (arg_root && arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        if (arg_install_source != ARG_INSTALL_SOURCE_AUTO && !arg_root && !arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--install-from-host is only supported with --root= or --image=.");

        if (arg_dry_run && argv[optind] && !STR_IN_SET(argv[optind], "unlink", "cleanup"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--dry is only supported with --unlink or --cleanup");

        return 1;
}

static int bootctl_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",                VERB_ANY, VERB_ANY, 0,            help                     },
                { "status",              VERB_ANY, 1,        VERB_DEFAULT, verb_status              },
                { "install",             VERB_ANY, 1,        0,            verb_install             },
                { "update",              VERB_ANY, 1,        0,            verb_install             },
                { "remove",              VERB_ANY, 1,        0,            verb_remove              },
                { "is-installed",        VERB_ANY, 1,        0,            verb_is_installed        },
                { "kernel-identify",     2,        2,        0,            verb_kernel_identify     },
                { "kernel-inspect",      2,        2,        0,            verb_kernel_inspect      },
                { "list",                VERB_ANY, 1,        0,            verb_list                },
                { "unlink",              2,        2,        0,            verb_unlink              },
                { "cleanup",             VERB_ANY, 1,        0,            verb_list                },
                { "set-default",         2,        2,        0,            verb_set_efivar          },
                { "set-oneshot",         2,        2,        0,            verb_set_efivar          },
                { "set-timeout",         2,        2,        0,            verb_set_efivar          },
                { "set-timeout-oneshot", 2,        2,        0,            verb_set_efivar          },
                { "random-seed",         VERB_ANY, 1,        0,            verb_random_seed         },
                { "systemd-efi-options", VERB_ANY, 2,        0,            verb_systemd_efi_options },
                { "reboot-to-firmware",  VERB_ANY, 2,        0,            verb_reboot_to_firmware  },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        int r;

        log_setup();

        /* If we run in a container, automatically turn off EFI file system access */
        if (detect_container() > 0)
                arg_touch_variables = false;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_print_root_device > 0) {
                _cleanup_free_ char *path = NULL;
                dev_t devno;

                r = blockdev_get_root(LOG_ERR, &devno);
                if (r < 0)
                        return r;
                if (r == 0) {
                        log_error("Root file system not backed by a (single) whole block device.");
                        return 80; /* some recognizable error code */
                }

                if (arg_print_root_device > 1) {
                        r = block_get_whole_disk(devno, &devno);
                        if (r < 0)
                                log_debug_errno(r, "Unable to find whole block device for root block device, ignoring: %m");
                }

                r = device_path_make_canonical(S_IFBLK, devno, &path);
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to format canonical device path for devno '" DEVNUM_FORMAT_STR "': %m",
                                               DEVNUM_FORMAT_VAL(devno));

                puts(path);
                return 0;
        }

        /* Open up and mount the image */
        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_RELAX_VAR_CHECK,
                                &mounted_dir,
                                /* ret_dir_fd= */ NULL,
                                &loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(mounted_dir);
                if (!arg_root)
                        return log_oom();
        }

        return bootctl_main(argc, argv);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
