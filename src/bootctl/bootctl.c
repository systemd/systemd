/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <sys/stat.h>

#include "sd-varlink.h"

#include "blockdev-util.h"
#include "boot-entry.h"
#include "bootctl.h"
#include "bootctl-cleanup.h"
#include "bootctl-install.h"
#include "bootctl-random-seed.h"
#include "bootctl-reboot-to-firmware.h"
#include "bootctl-set-efivar.h"
#include "bootctl-status.h"
#include "bootctl-uki.h"
#include "bootctl-unlink.h"
#include "build.h"
#include "devnum-util.h"
#include "dissect-image.h"
#include "efi-loader.h"
#include "efivars.h"
#include "escape.h"
#include "find-esp.h"
#include "image-policy.h"
#include "log.h"
#include "loop-util.h"
#include "main-func.h"
#include "mount-util.h"
#include "openssl-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "path-util.h"
#include "pretty-print.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"
#include "varlink-io.systemd.BootControl.h"
#include "varlink-util.h"
#include "verbs.h"
#include "virt.h"

static GracefulMode _arg_graceful = ARG_GRACEFUL_NO;

char *arg_esp_path = NULL;
char *arg_xbootldr_path = NULL;
bool arg_print_esp_path = false;
bool arg_print_dollar_boot_path = false;
bool arg_print_loader_path = false;
bool arg_print_stub_path = false;
unsigned arg_print_root_device = 0;
int arg_touch_variables = -1;
bool arg_install_random_seed = true;
PagerFlags arg_pager_flags = 0;
bool arg_quiet = false;
int arg_make_entry_directory = false; /* tri-state: < 0 for automatic logic */
sd_id128_t arg_machine_id = SD_ID128_NULL;
char *arg_install_layout = NULL;
BootEntryTokenType arg_entry_token_type = BOOT_ENTRY_TOKEN_AUTO;
char *arg_entry_token = NULL;
sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
bool arg_arch_all = false;
char *arg_root = NULL;
char *arg_image = NULL;
InstallSource arg_install_source = INSTALL_SOURCE_AUTO;
char *arg_efi_boot_option_description = NULL;
bool arg_efi_boot_option_description_with_device = false;
bool arg_dry_run = false;
ImagePolicy *arg_image_policy = NULL;
bool arg_varlink = false;
bool arg_secure_boot_auto_enroll = false;
char *arg_certificate = NULL;
CertificateSourceType arg_certificate_source_type = OPENSSL_CERTIFICATE_SOURCE_FILE;
char *arg_certificate_source = NULL;
char *arg_private_key = NULL;
KeySourceType arg_private_key_source_type = OPENSSL_KEY_SOURCE_FILE;
char *arg_private_key_source = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_esp_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_xbootldr_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_install_layout, freep);
STATIC_DESTRUCTOR_REGISTER(arg_entry_token, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_efi_boot_option_description, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key_source, freep);

static const char* const install_source_table[_INSTALL_SOURCE_MAX] = {
        [INSTALL_SOURCE_IMAGE] = "image",
        [INSTALL_SOURCE_HOST]  = "host",
        [INSTALL_SOURCE_AUTO]  = "auto",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(install_source, InstallSource);

#include "bootctl.args.inc"

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
                                       "Couldn't find EFI system partition. It is recommended to mount it to /boot/ or /efi/.\n"
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

static int print_loader_or_stub_path(void) {
        _cleanup_free_ char *p = NULL;
        sd_id128_t uuid;
        int r;

        if (arg_print_loader_path) {
                r = efi_loader_get_device_part_uuid(&uuid);
                if (r == -ENOENT)
                        return log_error_errno(r, "No loader partition UUID passed.");
                if (r < 0)
                        return log_error_errno(r, "Unable to determine loader partition UUID: %m");

                r = efi_get_variable_path(EFI_LOADER_VARIABLE_STR("LoaderImageIdentifier"), &p);
                if (r == -ENOENT)
                        return log_error_errno(r, "No loader EFI binary path passed.");
                if (r < 0)
                        return log_error_errno(r, "Unable to determine loader EFI binary path: %m");
        } else {
                assert(arg_print_stub_path);

                r = efi_stub_get_device_part_uuid(&uuid);
                if (r == -ENOENT)
                        return log_error_errno(r, "No stub partition UUID passed.");
                if (r < 0)
                        return log_error_errno(r, "Unable to determine stub partition UUID: %m");

                r = efi_get_variable_path(EFI_LOADER_VARIABLE_STR("StubImageIdentifier"), &p);
                if (r == -ENOENT)
                        return log_error_errno(r, "No stub EFI binary path passed.");
                if (r < 0)
                        return log_error_errno(r, "Unable to determine stub EFI binary path: %m");
        }

        sd_id128_t esp_uuid;
        r = acquire_esp(/* unprivileged_mode= */ false, /* graceful= */ false,
                        /* ret_part= */ NULL, /* ret_pstart= */ NULL, /* ret_psize= */ NULL,
                        &esp_uuid, /* ret_devid= */ NULL);
        if (r < 0)
                return r;

        const char *found_path = NULL;
        if (sd_id128_equal(esp_uuid, uuid))
                found_path = arg_esp_path;
        else if (arg_print_stub_path) { /* In case of the stub, also look for things in the xbootldr partition */
                sd_id128_t xbootldr_uuid;

                r = acquire_xbootldr(/* unprivileged_mode= */ false, &xbootldr_uuid, /* ret_devid= */ NULL);
                if (r < 0)
                        return r;

                if (sd_id128_equal(xbootldr_uuid, uuid))
                        found_path = arg_xbootldr_path;
        }

        if (!found_path)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Failed to discover partition " SD_ID128_FORMAT_STR " among mounted boot partitions.", SD_ID128_FORMAT_VAL(uuid));

        _cleanup_free_ char *j = path_join(found_path, p);
        if (!j)
                return log_oom();

        puts(j);
        return 0;
}

bool touch_variables(void) {
        /* If we run in a container or on a non-EFI system, automatically turn off EFI file system access,
         * unless explicitly overridden. */

        if (arg_touch_variables >= 0)
                return arg_touch_variables;

        if (arg_root) {
                log_once(LOG_NOTICE,
                         "Operating on %s, skipping EFI variable modifications.",
                         arg_image ? "image" : "root directory");
                return false;
        }

        if (!is_efi_boot()) { /* NB: this internally checks if we run in a container */
                log_once(LOG_NOTICE,
                         "Not booted with EFI or running in a container, skipping EFI variable modifications.");
                return false;
        }

        return true;
}

GracefulMode arg_graceful(void) {
        static bool chroot_checked = false;

        if (!chroot_checked && running_in_chroot() > 0) {
                if (_arg_graceful == ARG_GRACEFUL_NO)
                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Running in a chroot, enabling --graceful.");

                _arg_graceful = ARG_GRACEFUL_FORCE;
        }

        chroot_checked = true;

        return _arg_graceful;
}

static int help(void) {
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
               "  set-sysfail ID       Set boot loader entry used in case of a system failure\n"
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
               "  kernel-identify KERNEL-IMAGE\n"
               "                       Identify kernel image type\n"
               "  kernel-inspect KERNEL-IMAGE\n"
               "                       Prints details about the kernel image\n"
               "\n%3$sBlock Device Discovery Commands:%4$s\n"
               OPTION_HELP_GENERATED_BLOCK_DEVICE_DISCOVERY
               "\n%3$sOptions:%4$s\n"
               OPTION_HELP_GENERATED
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
        int r;

        r = parse_argv_generated(argc, argv);
        if (r <= 0)
                return r;

        if (!!arg_print_esp_path + !!arg_print_dollar_boot_path + (arg_print_root_device > 0) + arg_print_loader_path + arg_print_stub_path > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--print-esp-path/-p, --print-boot-path/-x, --print-root-device=/-R, --print-loader-path, --print-stub-path cannot be combined.");

        if ((arg_root || arg_image) && argv[optind] && !STR_IN_SET(argv[optind], "status", "list",
                        "install", "update", "remove", "is-installed", "random-seed", "unlink", "cleanup"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Options --root= and --image= are not supported with verb %s.",
                                       argv[optind]);

        if (arg_root && arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        if (arg_install_source != INSTALL_SOURCE_AUTO && !arg_root && !arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--install-from-host is only supported with --root= or --image=.");

        if (arg_dry_run && argv[optind] && !STR_IN_SET(argv[optind], "unlink", "cleanup"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--dry-run is only supported with --unlink or --cleanup");

        if (arg_secure_boot_auto_enroll) {
#if HAVE_OPENSSL
                if (!arg_certificate)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Secure boot auto-enrollment requested but no certificate provided.");

                if (!arg_private_key)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Secure boot auto-enrollment requested but no private key provided.");
#else
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Secure boot auto-enrollment requested but OpenSSL support is disabled.");
#endif
        }

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0) {
                arg_varlink = true;
                arg_pager_flags |= PAGER_DISABLE;
        }

        return 1;
}

static int bootctl_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",                VERB_ANY, VERB_ANY, 0,            verb_help                },
                { "status",              VERB_ANY, 1,        VERB_DEFAULT, verb_status              },
                { "install",             VERB_ANY, 1,        0,            verb_install             },
                { "update",              VERB_ANY, 1,        0,            verb_install             },
                { "remove",              VERB_ANY, 1,        0,            verb_remove              },
                { "is-installed",        VERB_ANY, 1,        0,            verb_is_installed        },
                { "kernel-identify",     2,        2,        0,            verb_kernel_identify     },
                { "kernel-inspect",      2,        2,        0,            verb_kernel_inspect      },
                { "list",                VERB_ANY, 1,        0,            verb_list                },
                { "unlink",              2,        2,        0,            verb_unlink              },
                { "cleanup",             VERB_ANY, 1,        0,            verb_cleanup             },
                { "set-default",         2,        2,        0,            verb_set_efivar          },
                { "set-oneshot",         2,        2,        0,            verb_set_efivar          },
                { "set-timeout",         2,        2,        0,            verb_set_efivar          },
                { "set-timeout-oneshot", 2,        2,        0,            verb_set_efivar          },
                { "set-sysfail",         2,        2,        0,            verb_set_efivar          },
                { "random-seed",         VERB_ANY, 1,        0,            verb_random_seed         },
                { "reboot-to-firmware",  VERB_ANY, 2,        0,            verb_reboot_to_firmware  },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        int r;

        /* Invocation as Varlink service */

        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_ROOT_ONLY|SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT,
                        /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_BootControl);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.BootControl.ListBootEntries",     vl_method_list_boot_entries,
                        "io.systemd.BootControl.SetRebootToFirmware", vl_method_set_reboot_to_firmware,
                        "io.systemd.BootControl.GetRebootToFirmware", vl_method_get_reboot_to_firmware,
                        "io.systemd.BootControl.Install",             vl_method_install);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_varlink)
                return vl_server();

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

        if (arg_print_loader_path || arg_print_stub_path)
                return print_loader_or_stub_path();

        /* Open up and mount the image */
        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_USR_NO_ROOT |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_ALLOW_USERSPACE_VERITY,
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
