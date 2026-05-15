/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "sd-varlink.h"

#include "blockdev-util.h"
#include "boot-entry.h"
#include "bootctl.h"
#include "bootctl-cleanup.h"
#include "bootctl-install.h"
#include "bootctl-link.h"
#include "bootctl-random-seed.h"
#include "bootctl-reboot-to-firmware.h"
#include "bootctl-set-efivar.h"
#include "bootctl-status.h"
#include "bootctl-uki.h"
#include "bootctl-unlink.h"
#include "bootctl-util.h"
#include "bootspec-util.h"
#include "build.h"
#include "crypto-util.h"
#include "devnum-util.h"
#include "dissect-image.h"
#include "efi-loader.h"
#include "efivars.h"
#include "escape.h"
#include "fd-util.h"
#include "find-esp.h"
#include "format-table.h"
#include "image-policy.h"
#include "log.h"
#include "loop-util.h"
#include "main-func.h"
#include "mount-util.h"
#include "options.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
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
bool arg_print_efi_architecture = false;
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
bool arg_oldest = false;
uint64_t arg_keep_free = KEEP_FREE_BYTES_DEFAULT;
char *arg_entry_title = NULL;
char *arg_entry_version = NULL;
uint64_t arg_entry_commit = 0;
char **arg_extras = NULL;
unsigned arg_tries_left = UINT_MAX;

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
STATIC_DESTRUCTOR_REGISTER(arg_entry_title, freep);
STATIC_DESTRUCTOR_REGISTER(arg_entry_version, freep);
STATIC_DESTRUCTOR_REGISTER(arg_extras, strv_freep);

static const char* const install_source_table[_INSTALL_SOURCE_MAX] = {
        [INSTALL_SOURCE_IMAGE] = "image",
        [INSTALL_SOURCE_HOST]  = "host",
        [INSTALL_SOURCE_AUTO]  = "auto",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(install_source, InstallSource);

int acquire_esp(int unprivileged_mode,
                bool graceful,
                int *ret_fd,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        _cleanup_free_ char *np = NULL;
        int r;

        /* Find the ESP, and log about errors. Note that find_esp_and_warn() will log in all error cases on
         * its own, except for ENOKEY (which is good, we want to show our own message in that case,
         * suggesting use of --esp-path=) and EACCESS (only when we request unprivileged mode; in this case
         * we simply eat up the error here, so that --list and --status work too, without noise about
         * this). */

        r = find_esp_and_warn_full(arg_root, arg_esp_path, unprivileged_mode, &np, ret_fd, ret_part, ret_pstart, ret_psize, ret_uuid, ret_devid);
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

        return 1; /* for symmetry with acquire_xbootldr() below: found */
}

int acquire_xbootldr(
                int unprivileged_mode,
                int *ret_fd,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        int r;

        _cleanup_free_ char *np = NULL;
        _cleanup_close_ int fd = -EBADF;
        r = find_xbootldr_and_warn_full(
                        arg_root,
                        arg_xbootldr_path,
                        unprivileged_mode,
                        &np,
                        ret_fd ? &fd : NULL,
                        ret_uuid,
                        ret_devid);
        if (r == -ENOKEY || (r >= 0 && arg_esp_path && path_equal(np, arg_esp_path))) {

                if (arg_esp_path)
                        log_debug("Didn't find an XBOOTLDR partition, using the ESP as $BOOT.");
                else
                        log_debug("Found neither an XBOOTLDR partition, nor an ESP.");

                arg_xbootldr_path = mfree(arg_xbootldr_path);

                if (ret_fd)
                        *ret_fd = -EBADF;
                if (ret_uuid)
                        *ret_uuid = SD_ID128_NULL;
                if (ret_devid)
                        *ret_devid = 0;

                return 0; /* not found */
        }
        if (r < 0)
                return r;

        free_and_replace(arg_xbootldr_path, np);
        log_debug("Using XBOOTLDR partition at %s as $BOOT.", arg_xbootldr_path);

        if (ret_fd)
                *ret_fd = TAKE_FD(fd);

        return 1; /* found */
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
        r = acquire_esp(/* unprivileged_mode= */ false,
                        /* graceful= */ false,
                        /* ret_fd= */ NULL,
                        /* ret_part= */ NULL,
                        /* ret_pstart= */ NULL,
                        /* ret_psize= */ NULL,
                        &esp_uuid,
                        /* ret_devid= */ NULL);
        if (r < 0)
                return r;

        const char *found_path = NULL;
        if (sd_id128_equal(esp_uuid, uuid))
                found_path = arg_esp_path;
        else if (arg_print_stub_path) { /* In case of the stub, also look for things in the xbootldr partition */
                sd_id128_t xbootldr_uuid;

                r = acquire_xbootldr(/* unprivileged_mode= */ false,
                                     /* ret_fd= */ NULL,
                                     &xbootldr_uuid,
                                     /* ret_devid= */ NULL);
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

        static const char *const verb_groups[] = {
                "Generic EFI Firmware/Boot Loader Commands",
                "Boot Loader Specification Commands",
                "Boot Loader Interface Commands",
                "systemd-boot Commands",
                "Kernel Image Commands",
        };

        static const char *const option_groups[] = {
                "Block Device Discovery Commands",
                "Options",
        };

        Table *verb_tables[ELEMENTSOF(verb_groups)] = {};
        CLEANUP_ELEMENTS(verb_tables, table_unref_array_clear);
        Table *option_tables[ELEMENTSOF(option_groups)] = {};
        CLEANUP_ELEMENTS(option_tables, table_unref_array_clear);

        for (size_t i = 0; i < ELEMENTSOF(verb_groups); i++) {
                r = verbs_get_help_table_group(verb_groups[i], &verb_tables[i]);
                if (r < 0)
                        return r;
        }

        for (size_t i = 0; i < ELEMENTSOF(option_groups); i++) {
                r = option_parser_get_help_table_group(option_groups[i], &option_tables[i]);
                if (r < 0)
                        return r;
        }

        (void) table_sync_column_widths(0,
                                        verb_tables[0], verb_tables[1], verb_tables[2],
                                        verb_tables[3], verb_tables[4],
                                        option_tables[0], option_tables[1]);

        printf("%s [OPTIONS...] COMMAND ...\n"
               "\n%sControl EFI firmware boot settings and manage boot loader.%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());

        for (size_t i = 0; i < ELEMENTSOF(verb_groups); i++) {
                printf("\n%s%s:%s\n", ansi_underline(), verb_groups[i], ansi_normal());

                r = table_print_or_warn(verb_tables[i]);
                if (r < 0)
                        return r;
        }

        for (size_t i = 0; i < ELEMENTSOF(option_groups); i++) {
                printf("\n%s%s:%s\n", ansi_underline(), option_groups[i], ansi_normal());

                r = table_print_or_warn(option_tables[i]);
                if (r < 0)
                        return r;
        }

        printf("\nSee the %s for details.\n", link);
        return 0;
}

VERB_COMMON_HELP(help);

VERB_GROUP("Generic EFI Firmware/Boot Loader Commands");

VERB_SCOPE(, verb_status, "status", NULL, VERB_ANY, 1, VERB_DEFAULT,
           "Show status of installed boot loader and EFI variables");

VERB_SCOPE(, verb_reboot_to_firmware, "reboot-to-firmware", "[BOOL]", VERB_ANY, 2, 0,
           "Query or set reboot-to-firmware EFI flag");

VERB_GROUP("Boot Loader Specification Commands");

VERB_SCOPE_NOARG(, verb_list, "list",
           "List boot loader entries");

VERB_SCOPE(, verb_unlink, "unlink", "ID", VERB_ANY, 2, 0,
           "Remove boot loader entry");

VERB_SCOPE(, verb_link, "link", "KERNEL", 2, 2, 0,
           "Create boot loader entry for specified kernel");

VERB_SCOPE_NOARG(, verb_cleanup, "cleanup",
           "Remove files in ESP not referenced in any boot entry");

VERB_GROUP("Boot Loader Interface Commands");

VERB_SCOPE(, verb_set_efivar, "set-default", "ID", 2, 2, 0,
           "Set default boot loader entry");

VERB_SCOPE(, verb_set_efivar, "set-oneshot", "ID", 2, 2, 0,
           "Set default boot loader entry, for next boot only");

VERB_SCOPE(, verb_set_efivar, "set-sysfail", "ID", 2, 2, 0,
           "Set boot loader entry used in case of a system failure");

VERB_SCOPE(, verb_set_efivar, "set-timeout", "SECONDS", 2, 2, 0,
           "Set the menu timeout");

VERB_SCOPE(, verb_set_efivar, "set-timeout-oneshot", "SECONDS", 2, 2, 0,
           "Set the menu timeout for the next boot only");

VERB_SCOPE(, verb_set_efivar, "set-preferred", "ID", 2, 2, 0,
           /* help= */ NULL);

VERB_GROUP("systemd-boot Commands");

VERB_SCOPE(, verb_install, "install", NULL, VERB_ANY, 1, 0,
           "Install systemd-boot to the ESP and EFI variables");

VERB_SCOPE(, verb_install, "update", NULL, VERB_ANY, 1, 0,
           "Update systemd-boot in the ESP and EFI variables");

VERB_SCOPE_NOARG(, verb_remove, "remove",
           "Remove systemd-boot from the ESP and EFI variables");

VERB_SCOPE_NOARG(, verb_is_installed, "is-installed",
           "Test whether systemd-boot is installed in the ESP");

VERB_SCOPE_NOARG(, verb_random_seed, "random-seed",
           "Initialize or refresh random seed in ESP and EFI variables");

VERB_GROUP("Kernel Image Commands");

VERB_SCOPE(, verb_kernel_identify, "kernel-identify", "KERNEL-IMAGE", 2, 2, 0,
           "Identify kernel image type");

VERB_SCOPE(, verb_kernel_inspect, "kernel-inspect", "KERNEL-IMAGE", 2, 2, 0,
           "Prints details about the kernel image");

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_GROUP("Block Device Discovery Commands"): {}

                OPTION('p', "print-esp-path", NULL, "Print path to the EFI System Partition mount point"): {}
                OPTION_LONG("print-path", NULL, /* help= */ NULL):  /* Compatibility alias */
                        arg_print_esp_path = true;
                        break;

                OPTION('x', "print-boot-path", NULL, "Print path to the $BOOT partition mount point"):
                        arg_print_dollar_boot_path = true;
                        break;

                OPTION_LONG("print-loader-path", NULL, "Print path to currently booted boot loader binary"):
                        arg_print_loader_path = true;
                        break;

                OPTION_LONG("print-stub-path", NULL, "Print path to currently booted unified kernel binary"):
                        arg_print_stub_path = true;
                        break;

                OPTION('R', "print-root-device", NULL,
                       "Print path to the block device node backing the root file system"
                       " (returns e.g. /dev/nvme0n1p5)"): {}
                OPTION_HELP_VERBATIM("-RR",
                                     "Print path to the whole disk block device node backing the root FS"
                                     " (returns e.g. /dev/nvme0n1)"):
                        arg_print_root_device++;
                        break;

                OPTION_LONG("print-efi-architecture", NULL, "Print the local EFI architecture string"):
                        arg_print_efi_architecture = true;
                        break;

                OPTION_GROUP("Options"): {}

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("esp-path", "PATH", "Path to the EFI System Partition (ESP)"): {}
                OPTION_LONG("path", "PATH", /* help= */ NULL):  /* Compatibility alias */
                        r = free_and_strdup(&arg_esp_path, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION_LONG("boot-path", "PATH", "Path to the $BOOT partition"):
                        r = free_and_strdup(&arg_xbootldr_path, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION_LONG("root", "PATH", "Operate on an alternate filesystem root"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image", "PATH", "Operate on disk image as filesystem root"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image-policy", "POLICY", "Specify disk image dissection policy"):
                        r = parse_image_policy_argument(opts.arg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("install-source", "SOURCE",
                            "Where to pick files when using --root=/--image= (auto, image, host)"): {
                        InstallSource is = install_source_from_string(opts.arg);
                        if (is < 0)
                                return log_error_errno(is, "Unexpected parameter for --install-source=: %s", opts.arg);

                        arg_install_source = is;
                        break;
                }

                OPTION_LONG("variables", "BOOL", "Whether to modify EFI variables"):
                        r = parse_tristate_argument_with_auto("--variables=", opts.arg, &arg_touch_variables);
                        if (r < 0)
                                return r;
#if !ENABLE_EFI
                        if (arg_touch_variables > 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                       "Compiled without support for EFI, --variables=%s cannot be specified.", opts.arg);
#endif
                        break;

                OPTION_LONG("no-variables", NULL, /* help= */ NULL):  /* Compatibility alias */
                        arg_touch_variables = false;
                        break;

                OPTION_LONG("random-seed", "BOOL", "Whether to create random-seed file during install"):
                        r = parse_boolean_argument("--random-seed=", opts.arg, &arg_install_random_seed);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_LONG("graceful", NULL,
                            "Don't fail when the ESP cannot be found or EFI variables cannot be written"):
                        _arg_graceful = ARG_GRACEFUL_YES;
                        break;

                OPTION('q', "quiet", NULL, "Suppress output"):
                        arg_quiet = true;
                        break;

                OPTION_COMMON_ENTRY_TOKEN:
                        r = parse_boot_entry_token_type(opts.arg, &arg_entry_token_type, &arg_entry_token);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_MAKE_ENTRY_DIRECTORY: {}
                OPTION_LONG("make-machine-id-directory", "BOOL", /* help= */ NULL):  /* Compatibility alias */
                        if (streq(opts.arg, "auto"))  /* retained for backwards compatibility */
                                arg_make_entry_directory = -1; /* yes if machine-id is permanent */
                        else {
                                r = parse_boolean_argument("--make-entry-directory=", opts.arg, NULL);
                                if (r < 0)
                                        return r;

                                arg_make_entry_directory = r;
                        }
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("all-architectures", NULL, "Install all supported EFI architectures"):
                        arg_arch_all = true;
                        break;

                OPTION_LONG("efi-boot-option-description", "DESCRIPTION",
                            "Description of the entry in the boot option list"):
                        if (!string_is_safe(opts.arg, STRING_ALLOW_BACKSLASHES|STRING_ALLOW_QUOTES|STRING_ALLOW_GLOBS)) {
                                _cleanup_free_ char *escaped = cescape(opts.arg);
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid --efi-boot-option-description=: %s", strna(escaped));
                        }
                        if (strlen(opts.arg) > EFI_BOOT_OPTION_DESCRIPTION_MAX)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--efi-boot-option-description= too long: %zu > %zu",
                                                       strlen(opts.arg), EFI_BOOT_OPTION_DESCRIPTION_MAX);
                        r = free_and_strdup_warn(&arg_efi_boot_option_description, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("efi-boot-option-description-with-device", "BOOL",
                            "Suffix description with disk vendor/model/serial"):
                        r = parse_boolean_argument("--efi-boot-option-description-with-device=", opts.arg,
                                                   &arg_efi_boot_option_description_with_device);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("dry-run", NULL, "Dry run (unlink and cleanup)"):
                        arg_dry_run = true;
                        break;

                OPTION_LONG("secure-boot-auto-enroll", "BOOL", "Set up secure boot auto-enrollment"):
                        r = parse_boolean_argument("--secure-boot-auto-enroll=", opts.arg,
                                                   &arg_secure_boot_auto_enroll);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_PRIVATE_KEY("Private key for Secure Boot auto-enrollment"):
                        r = free_and_strdup_warn(&arg_private_key, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_PRIVATE_KEY_SOURCE:
                        r = parse_openssl_key_source_argument(opts.arg,
                                                              &arg_private_key_source,
                                                              &arg_private_key_source_type);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_CERTIFICATE("PEM certificate to use when setting up Secure Boot auto-enrollment"):
                        r = free_and_strdup_warn(&arg_certificate, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_CERTIFICATE_SOURCE:
                        r = parse_openssl_certificate_source_argument(opts.arg,
                                                                      &arg_certificate_source,
                                                                      &arg_certificate_source_type);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("oldest", "BOOL",
                            "Delete oldest boot menu entry"):
                        r = parse_boolean_argument("--oldest=", opts.arg, &arg_oldest);
                        if (r < 0)
                                return r;

                        break;

                OPTION_LONG("keep-free", "BYTES",
                            "How much space to keep free on ESP/XBOOTLDR"):

                        if (isempty(opts.arg))
                                arg_keep_free = KEEP_FREE_BYTES_DEFAULT;
                        else {
                                r = parse_size(opts.arg, 1024, &arg_keep_free);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse --keep-free=: %s", opts.arg);
                        }

                        break;

                OPTION_LONG("entry-title", "TITLE",
                            "Selects the entry title for the new boot menu entry"):

                        if (isempty(opts.arg)) {
                                arg_entry_title = mfree(arg_entry_title);
                                break;
                        }

                        if (!efi_loader_entry_title_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not a valid boot menu entry title: %s", opts.arg);

                        r = free_and_strdup_warn(&arg_entry_title, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("entry-version", "VERSION",
                            "Selects the entry version for the new boot menu entry"):
                        if (isempty(opts.arg)) {
                                arg_entry_version = mfree(arg_entry_version);
                                break;
                        }

                        if (!version_is_valid_versionspec(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not a valid boot menu entry version: %s", opts.arg);

                        r = free_and_strdup_warn(&arg_entry_version, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("entry-commit", "NR",
                            "Selects the entry commit version for the new boot menu entry"): {
                        if (isempty(opts.arg)) {
                                arg_entry_commit = 0;
                                break;
                        }

                        uint64_t n;
                        r = safe_atou64(opts.arg, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --entry-commit= parameter: %s", opts.arg);
                        if (!entry_commit_valid(n))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not a valid entry commit number.");

                        arg_entry_commit = n;
                        break;
                }

                OPTION('X', "extra", "PATH",
                       "Pass extra resource (confext, sysext, credential) to the invoked UKI of the boot menu entry"): {

                        if (isempty(opts.arg)) {
                                arg_extras = strv_free(arg_extras);
                                break;
                        }

                        _cleanup_free_ char *x = NULL;
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &x);
                        if (r < 0)
                                return r;

                        _cleanup_free_ char *fn = NULL;
                        r = path_extract_filename(x, &fn);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract filename from '%s': %m", x);
                        if (!efi_loader_entry_resource_filename_valid(fn))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Extra filename '%s' is not suitable for reference in a boot menu entry.", fn);

                        r = strv_consume(&arg_extras, TAKE_PTR(x));
                        if (r < 0)
                                return log_oom();

                        strv_uniq(arg_extras);
                        break;
                }

                OPTION_LONG("tries-left", "NR",
                            "Set boot menu entries tries-left counter to the specified value"): {
                        if (isempty(opts.arg)) {
                                arg_tries_left = UINT_MAX;
                                break;
                        }

                        unsigned u;
                        r = safe_atou(opts.arg, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse tries left counter: %s", opts.arg);
                        if (u >= UINT_MAX)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Tries left counter too large, refusing: %u", u);

                        arg_tries_left = u;
                        break;
                }}

        char **args = option_parser_get_args(&opts);

        if (!!arg_print_esp_path + !!arg_print_dollar_boot_path + (arg_print_root_device > 0) + arg_print_loader_path + arg_print_stub_path + arg_print_efi_architecture > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--print-esp-path/-p, --print-boot-path/-x, --print-root-device=/-R, --print-loader-path, --print-stub-path, --print-efi-architecture cannot be combined.");

        if ((arg_root || arg_image) && args[0] && !STR_IN_SET(args[0], "status", "list",
                        "install", "update", "remove", "is-installed", "random-seed", "unlink", "cleanup"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Options --root= and --image= are not supported with verb %s.",
                                       args[0]);

        if (arg_root && arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        if (arg_install_source != INSTALL_SOURCE_AUTO && !arg_root && !arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--install-from-host is only supported with --root= or --image=.");

        if (arg_dry_run && args[0] && !STR_IN_SET(args[0], "unlink", "cleanup"))
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

        *ret_args = args;
        return 1;
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        int r;

        /* Invocation as Varlink service */

        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_ROOT_ONLY |
                        SD_VARLINK_SERVER_MYSELF_ONLY |
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT,
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
                        "io.systemd.BootControl.Install",             vl_method_install,
                        "io.systemd.BootControl.Link",                vl_method_link,
                        "io.systemd.BootControl.Unlink",              vl_method_unlink);
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

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
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

        if (arg_print_efi_architecture) {
                printf("%s\n", get_efi_arch());
                return 0;
        }

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

        return dispatch_verb_with_args(args, NULL);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
