/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>
#include <unistd.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "bootctl.h"
#include "bootctl-status.h"
#include "bootctl-util.h"
#include "bootspec.h"
#include "chase.h"
#include "devnum-util.h"
#include "dirent-util.h"
#include "efi-api.h"
#include "efi-loader.h"
#include "efivars.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "pager.h"
#include "path-util.h"
#include "pretty-print.h"
#include "recurse-dir.h"
#include "string-util.h"
#include "strv.h"
#include "tpm2-util.h"

static int boot_config_load_and_select(
                BootConfig *config,
                const char *esp_path,
                dev_t esp_devid,
                const char *xbootldr_path,
                dev_t xbootldr_devid) {

        int r;

        /* If XBOOTLDR and ESP actually refer to the same block device, suppress XBOOTLDR, since it would
         * find the same entries twice. */
        bool same = esp_path && xbootldr_path && devnum_set_and_equal(esp_devid, xbootldr_devid);

        r = boot_config_load(config, esp_path, same ? NULL : xbootldr_path);
        if (r < 0)
                return r;

        if (!arg_root) {
                _cleanup_strv_free_ char **efi_entries = NULL;

                r = efi_loader_get_entries(&efi_entries);
                if (r == -ENOENT || ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_debug_errno(r, "Boot loader reported no entries.");
                else if (r < 0)
                        log_warning_errno(r, "Failed to determine entries reported by boot loader, ignoring: %m");
                else
                        (void) boot_config_augment_from_loader(config, efi_entries, /* auto_only= */ false);
        }

        return boot_config_select_special_entries(config, /* skip_efivars= */ !!arg_root);
}

static int status_entries(
                const BootConfig *config,
                const char *esp_path,
                sd_id128_t esp_partition_uuid,
                const char *xbootldr_path,
                sd_id128_t xbootldr_partition_uuid) {

        int r;

        assert(config);
        assert(esp_path || xbootldr_path);

        printf("%sBoot Loader Entry Locations:%s\n", ansi_underline(), ansi_normal());

        printf("          ESP: %s (", esp_path);
        if (!sd_id128_is_null(esp_partition_uuid))
                printf("/dev/disk/by-partuuid/" SD_ID128_UUID_FORMAT_STR "",
                       SD_ID128_FORMAT_VAL(esp_partition_uuid));
        if (!xbootldr_path)
                /* ESP is $BOOT if XBOOTLDR not present. */
                printf(", %s$BOOT%s", ansi_green(), ansi_normal());
        printf(")");

        if (xbootldr_path) {
                printf("\n     XBOOTLDR: %s (", xbootldr_path);
                if (!sd_id128_is_null(xbootldr_partition_uuid))
                        printf("/dev/disk/by-partuuid/" SD_ID128_UUID_FORMAT_STR ", ",
                               SD_ID128_FORMAT_VAL(xbootldr_partition_uuid));
                /* XBOOTLDR is always $BOOT if present. */
                printf("%s$BOOT%s)", ansi_green(), ansi_normal());
        }

        if (settle_entry_token() >= 0)
                printf("\n        token: %s", arg_entry_token);
        printf("\n\n");

        if (config->default_entry < 0)
                printf("%zu entries, no entry could be determined as default.\n", config->n_entries);
        else {
                printf("%sDefault Boot Loader Entry:%s\n", ansi_underline(), ansi_normal());

                r = show_boot_entry(
                                boot_config_default_entry(config),
                                /* show_as_default= */ false,
                                /* show_as_selected= */ false,
                                /* show_reported= */ false);
                if (r > 0)
                        /* < 0 is already logged by the function itself, let's just emit an extra warning if
                           the default entry is broken */
                        printf("\nWARNING: default boot entry is broken\n");
        }

        return 0;
}

static int print_efi_option(uint16_t id, int *n_printed, bool in_order) {
        _cleanup_free_ char *title = NULL;
        _cleanup_free_ char *path = NULL;
        sd_id128_t partition;
        bool active;
        int r;

        assert(n_printed);

        r = efi_get_boot_option(id, &title, &partition, &path, &active);
        if (r == -ENOENT) {
                log_debug_errno(r, "Boot option 0x%04X referenced but missing, ignoring: %m", id);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read boot option 0x%04X: %m", id);

        /* print only configured entries with partition information */
        if (!path || sd_id128_is_null(partition)) {
                log_debug("Ignoring boot entry 0x%04X without partition information.", id);
                return 0;
        }

        efi_tilt_backslashes(path);

        if (*n_printed == 0) /* Print section title before first entry */
                printf("%sBoot Loaders Listed in EFI Variables:%s\n", ansi_underline(), ansi_normal());

        printf("        Title: %s%s%s\n", ansi_highlight(), strna(title), ansi_normal());
        printf("           ID: 0x%04X\n", id);
        printf("       Status: %sactive%s\n", active ? "" : "in", in_order ? ", boot-order" : "");
        printf("    Partition: /dev/disk/by-partuuid/" SD_ID128_UUID_FORMAT_STR "\n",
               SD_ID128_FORMAT_VAL(partition));
        printf("         File: %s%s%s/%s%s\n",
               glyph(GLYPH_TREE_RIGHT), ansi_grey(), arg_esp_path, ansi_normal(), path);
        printf("\n");

        (*n_printed)++;
        return 1;
}

static int status_variables(void) {
        _cleanup_free_ uint16_t *options = NULL, *order = NULL;
        int n_options, n_order, n_printed = 0;

        n_options = efi_get_boot_options(&options);
        if (n_options == -ENOENT)
                return log_error_errno(n_options,
                                       "Failed to access EFI variables, efivarfs"
                                       " needs to be available at /sys/firmware/efi/efivars/.");
        if (n_options < 0)
                return log_error_errno(n_options, "Failed to read EFI boot entries: %m");

        n_order = efi_get_boot_order(&order);
        if (n_order == -ENOENT)
                n_order = 0;
        else if (n_order < 0)
                return log_error_errno(n_order, "Failed to read EFI boot order: %m");

        /* print entries in BootOrder first */
        for (int i = 0; i < n_order; i++)
                (void) print_efi_option(order[i], &n_printed, /* in_order= */ true);

        /* print remaining entries */
        for (int i = 0; i < n_options; i++) {
                for (int j = 0; j < n_order; j++)
                        if (options[i] == order[j])
                                goto next_option;

                (void) print_efi_option(options[i], &n_printed, /* in_order= */ false);

        next_option:
                continue;
        }

        if (n_printed == 0)
                printf("No boot loaders listed in EFI Variables.\n\n");

        return 0;
}

static int enumerate_binaries(
                const char *esp_path,
                const char *path,
                char **previous,
                bool *is_first) {

        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_free_ char *p = NULL;
        int c = 0, r;

        assert(esp_path);
        assert(path);
        assert(previous);
        assert(is_first);

        r = chase_and_opendir(path, esp_path, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, &p, &d);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read \"%s/%s\": %m", esp_path, skip_leading_slash(path));

        FOREACH_DIRENT(de, d, break) {
                _cleanup_free_ char *v = NULL, *filename = NULL;
                _cleanup_close_ int fd = -EBADF;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                filename = path_join(p, de->d_name);
                if (!filename)
                        return log_oom();
                LOG_SET_PREFIX(filename);

                fd = openat(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open file for reading: %m");

                r = get_file_version(fd, &v);
                if (r < 0 && r != -ESRCH)
                        return r;

                if (*previous) { /* Let's output the previous entry now, since now we know that there will be
                                  * one more, and can draw the tree glyph properly. */
                        printf("         %s %s%s\n",
                               *is_first ? "File:" : "     ",
                               glyph(GLYPH_TREE_BRANCH), *previous);
                        *is_first = false;
                        *previous = mfree(*previous);
                }

                /* Do not output this entry immediately, but store what should be printed in a state
                 * variable, because we only will know the tree glyph to print (branch or final edge) once we
                 * read one more entry */
                if (r == -ESRCH) /* No systemd-owned file but still interesting to print */
                        r = asprintf(previous, "%s%s/%s/%s/%s",
                                     ansi_grey(), esp_path, ansi_normal(), path, de->d_name);
                else /* if (r >= 0) */
                        r = asprintf(previous, "%s%s/%s/%s/%s (%s%s%s)",
                                     ansi_grey(), esp_path, ansi_normal(), path, de->d_name,
                                     ansi_highlight(), v, ansi_normal());
                if (r < 0)
                        return log_oom();

                c++;
        }

        return c;
}

static int status_binaries(const char *esp_path, sd_id128_t partition) {
        _cleanup_free_ char *last = NULL;
        bool is_first = true;
        int r, k;

        printf("%sAvailable Boot Loaders on ESP:%s\n", ansi_underline(), ansi_normal());

        if (!esp_path) {
                printf("          ESP: Cannot find or access mount point of ESP.\n\n");
                return -ENOENT;
        }

        printf("          ESP: %s", esp_path);
        if (!sd_id128_is_null(partition))
                printf(" (/dev/disk/by-partuuid/" SD_ID128_UUID_FORMAT_STR ")", SD_ID128_FORMAT_VAL(partition));
        printf("\n");

        r = enumerate_binaries(esp_path, "EFI/systemd", &last, &is_first);
        if (r < 0)
                goto fail;

        k = enumerate_binaries(esp_path, "EFI/BOOT", &last, &is_first);
        if (k < 0) {
                r = k;
                goto fail;
        }

        if (last) /* let's output the last entry now, since now we know that there will be no more, and can draw the tree glyph properly */
                printf("         %s %s%s\n",
                       is_first ? "File:" : "     ",
                       glyph(GLYPH_TREE_RIGHT), last);

        if (r == 0 && !arg_quiet)
                log_info("systemd-boot not installed in ESP.");
        if (k == 0 && !arg_quiet)
                log_info("No default/fallback boot loader installed in ESP.");

        printf("\n");
        return 0;

fail:
        errno = -r;
        printf("         File: (can't access %s: %m)\n\n", esp_path);
        return r;
}

static int efi_get_variable_string_and_warn(const char *variable, char **ret) {
        int r;

        r = efi_get_variable_string(variable, ret);
        if (r < 0 && r != -ENOENT)
                return log_warning_errno(r, "Failed to read EFI variable '%s', ignoring: %m", variable);

        return r;
}

static int efi_get_variable_path_and_warn(const char *variable, char **ret) {
        int r;

        r = efi_get_variable_path(variable, ret);
        if (r < 0 && r != -ENOENT)
                return log_warning_errno(r, "Failed to read EFI variable '%s', ignoring: %m", variable);

        return r;
}

static void print_yes_no_line(bool first, bool good, const char *name) {
        printf("%s%s %s\n",
               first ? "     Features: " : "               ",
               COLOR_MARK_BOOL(good),
               name);
}

int verb_status(int argc, char *argv[], void *userdata) {
        sd_id128_t esp_uuid = SD_ID128_NULL, xbootldr_uuid = SD_ID128_NULL;
        dev_t esp_devid = 0, xbootldr_devid = 0;
        int r, k;

        r = acquire_esp(/* unprivileged_mode= */ -1,
                        /* graceful= */ false,
                        /* ret_part= */ NULL,
                        /* ret_pstart= */ NULL,
                        /* ret_psize= */ NULL,
                        &esp_uuid,
                        &esp_devid);
        if (arg_print_esp_path) {
                if (r == -EACCES) /* If we couldn't acquire the ESP path, log about access errors (which is the only
                                   * error the find_esp_and_warn() won't log on its own) */
                        return log_error_errno(r, "Failed to determine ESP location: %m");
                if (r < 0)
                        return r;

                puts(arg_esp_path);
                return 0;
        }

        r = acquire_xbootldr(
                        /* unprivileged_mode= */ -1,
                        &xbootldr_uuid,
                        &xbootldr_devid);
        if (arg_print_dollar_boot_path) {
                if (r == -EACCES)
                        return log_error_errno(r, "Failed to determine XBOOTLDR partition: %m");
                if (r < 0)
                        return r;

                const char *path = arg_dollar_boot_path();
                if (!path)
                        return log_error_errno(SYNTHETIC_ERRNO(EACCES), "Failed to determine XBOOTLDR location.");

                puts(path);
                return 0;
        }

        r = 0; /* If we couldn't determine the path, then don't consider that a problem from here on, just
                * show what we can show */

        pager_open(arg_pager_flags);

        if (arg_root)
                log_debug("Skipping 'System' section, operating offline.");
        else if (!is_efi_boot())
                printf("%sSystem:%s\n"
                       "Not booted with EFI\n\n",
                       ansi_underline(), ansi_normal());
        else {
                static const struct {
                        uint64_t flag;
                        const char *name;
                } loader_flags[] = {
                        { EFI_LOADER_FEATURE_BOOT_COUNTING,           "Boot counting"                         },
                        { EFI_LOADER_FEATURE_CONFIG_TIMEOUT,          "Menu timeout control"                  },
                        { EFI_LOADER_FEATURE_CONFIG_TIMEOUT_ONE_SHOT, "One-shot menu timeout control"         },
                        { EFI_LOADER_FEATURE_ENTRY_DEFAULT,           "Default entry control"                 },
                        { EFI_LOADER_FEATURE_ENTRY_ONESHOT,           "One-shot entry control"                },
                        { EFI_LOADER_FEATURE_XBOOTLDR,                "Support for XBOOTLDR partition"        },
                        { EFI_LOADER_FEATURE_RANDOM_SEED,             "Support for passing random seed to OS" },
                        { EFI_LOADER_FEATURE_LOAD_DRIVER,             "Load drop-in drivers"                  },
                        { EFI_LOADER_FEATURE_SORT_KEY,                "Support Type #1 sort-key field"        },
                        { EFI_LOADER_FEATURE_SAVED_ENTRY,             "Support @saved pseudo-entry"           },
                        { EFI_LOADER_FEATURE_DEVICETREE,              "Support Type #1 devicetree field"      },
                        { EFI_LOADER_FEATURE_SECUREBOOT_ENROLL,       "Enroll SecureBoot keys"                },
                        { EFI_LOADER_FEATURE_RETAIN_SHIM,             "Retain SHIM protocols"                 },
                        { EFI_LOADER_FEATURE_MENU_DISABLE,            "Menu can be disabled"                  },
                        { EFI_LOADER_FEATURE_MULTI_PROFILE_UKI,       "Multi-Profile UKIs are supported"      },
                        { EFI_LOADER_FEATURE_REPORT_URL,              "Loader reports network boot URL"       },
                        { EFI_LOADER_FEATURE_TYPE1_UKI,               "Support Type #1 uki field"             },
                        { EFI_LOADER_FEATURE_TYPE1_UKI_URL,           "Support Type #1 uki-url field"         },
                };
                static const struct {
                        uint64_t flag;
                        const char *name;
                } stub_flags[] = {
                        { EFI_STUB_FEATURE_REPORT_BOOT_PARTITION,     "Stub reports loader partition information"                   },
                        { EFI_STUB_FEATURE_REPORT_STUB_PARTITION,     "Stub reports stub partition information"                     },
                        { EFI_STUB_FEATURE_REPORT_URL,                "Stub reports network boot URL"                               },
                        { EFI_STUB_FEATURE_PICK_UP_CREDENTIALS,       "Picks up credentials from boot partition"                    },
                        { EFI_STUB_FEATURE_PICK_UP_SYSEXTS,           "Picks up system extension images from boot partition"        },
                        { EFI_STUB_FEATURE_PICK_UP_CONFEXTS,          "Picks up configuration extension images from boot partition" },
                        { EFI_STUB_FEATURE_THREE_PCRS,                "Measures kernel+command line+sysexts"                        },
                        { EFI_STUB_FEATURE_RANDOM_SEED,               "Support for passing random seed to OS"                       },
                        { EFI_STUB_FEATURE_CMDLINE_ADDONS,            "Pick up .cmdline from addons"                                },
                        { EFI_STUB_FEATURE_CMDLINE_SMBIOS,            "Pick up .cmdline from SMBIOS Type 11"                        },
                        { EFI_STUB_FEATURE_DEVICETREE_ADDONS,         "Pick up .dtb from addons"                                    },
                        { EFI_STUB_FEATURE_MULTI_PROFILE_UKI,         "Stub understands profile selector"                           },
                };
                _cleanup_free_ char *fw_type = NULL, *fw_info = NULL, *loader = NULL, *loader_path = NULL, *stub = NULL, *stub_path = NULL,
                        *current_entry = NULL, *oneshot_entry = NULL, *default_entry = NULL, *sysfail_entry = NULL, *sysfail_reason = NULL;
                uint64_t loader_features = 0, stub_features = 0;
                int have;

                (void) efi_get_variable_string_and_warn(EFI_LOADER_VARIABLE_STR("LoaderFirmwareType"), &fw_type);
                (void) efi_get_variable_string_and_warn(EFI_LOADER_VARIABLE_STR("LoaderFirmwareInfo"), &fw_info);
                (void) efi_get_variable_string_and_warn(EFI_LOADER_VARIABLE_STR("LoaderInfo"), &loader);
                (void) efi_get_variable_string_and_warn(EFI_LOADER_VARIABLE_STR("StubInfo"), &stub);
                (void) efi_get_variable_path_and_warn(EFI_LOADER_VARIABLE_STR("LoaderImageIdentifier"), &loader_path);
                (void) efi_get_variable_path_and_warn(EFI_LOADER_VARIABLE_STR("StubImageIdentifier"), &stub_path);
                (void) efi_loader_get_features(&loader_features);
                (void) efi_stub_get_features(&stub_features);
                (void) efi_get_variable_string_and_warn(EFI_LOADER_VARIABLE_STR("LoaderEntrySelected"), &current_entry);
                (void) efi_get_variable_string_and_warn(EFI_LOADER_VARIABLE_STR("LoaderEntryOneShot"), &oneshot_entry);
                (void) efi_get_variable_string_and_warn(EFI_LOADER_VARIABLE_STR("LoaderEntryDefault"), &default_entry);
                (void) efi_get_variable_string_and_warn(EFI_LOADER_VARIABLE_STR("LoaderEntrySysFail"), &sysfail_entry);
                (void) efi_get_variable_string_and_warn(EFI_LOADER_VARIABLE_STR("LoaderSysFailReason"), &sysfail_reason);

                SecureBootMode secure = efi_get_secure_boot_mode();
                printf("%sSystem:%s\n", ansi_underline(), ansi_normal());
                printf("      Firmware: %s%s (%s)%s\n", ansi_highlight(), strna(fw_type), strna(fw_info), ansi_normal());
                printf(" Firmware Arch: %s\n", get_efi_arch());
                printf("   Secure Boot: %s%s%s",
                       IN_SET(secure, SECURE_BOOT_USER, SECURE_BOOT_DEPLOYED) ? ansi_highlight_green() : ansi_normal(),
                       enabled_disabled(IN_SET(secure, SECURE_BOOT_USER, SECURE_BOOT_DEPLOYED)),
                       ansi_normal());

                if (secure != SECURE_BOOT_DISABLED)
                        printf(" (%s)\n", secure_boot_mode_to_string(secure));
                else
                        printf("\n");

                Tpm2Support s = tpm2_support_full(TPM2_SUPPORT_FIRMWARE|TPM2_SUPPORT_DRIVER);
                printf("  TPM2 Support: %s%s%s\n",
                       FLAGS_SET(s, TPM2_SUPPORT_FIRMWARE|TPM2_SUPPORT_DRIVER) ? ansi_highlight_green() :
                       (s & (TPM2_SUPPORT_FIRMWARE|TPM2_SUPPORT_DRIVER)) != 0 ? ansi_highlight_red() : ansi_highlight_yellow(),
                       FLAGS_SET(s, TPM2_SUPPORT_FIRMWARE|TPM2_SUPPORT_DRIVER) ? "yes" :
                       (s & TPM2_SUPPORT_FIRMWARE) ? "firmware only, driver unavailable" :
                       (s & TPM2_SUPPORT_DRIVER) ? "driver only, firmware unavailable" : "no",
                       ansi_normal());

                k = efi_measured_uki(LOG_DEBUG);
                if (k > 0)
                        printf("  Measured UKI: %syes%s\n", ansi_highlight_green(), ansi_normal());
                else if (k == 0)
                        printf("  Measured UKI: no\n");
                else {
                        errno = -k;
                        printf("  Measured UKI: %sfailed%s (%m)\n", ansi_highlight_red(), ansi_normal());
                }

                k = efi_get_reboot_to_firmware();
                if (k > 0)
                        printf("  Boot into FW: %sactive%s\n", ansi_highlight_yellow(), ansi_normal());
                else if (k == 0)
                        printf("  Boot into FW: supported\n");
                else if (k == -EOPNOTSUPP)
                        printf("  Boot into FW: not supported\n");
                else {
                        errno = -k;
                        printf("  Boot into FW: %sfailed%s (%m)\n", ansi_highlight_red(), ansi_normal());
                }
                printf("\n");

                if (loader) {
                        printf("%sCurrent Boot Loader:%s\n", ansi_underline(), ansi_normal());
                        printf("       Product: %s%s%s\n", ansi_highlight(), loader, ansi_normal());
                        for (size_t i = 0; i < ELEMENTSOF(loader_flags); i++)
                                print_yes_no_line(i == 0, FLAGS_SET(loader_features, loader_flags[i].flag), loader_flags[i].name);

                        sd_id128_t loader_partition_uuid = SD_ID128_NULL;
                        (void) efi_loader_get_device_part_uuid(&loader_partition_uuid);

                        _cleanup_free_ char *loader_url = NULL;
                        (void) efi_get_variable_string_and_warn(EFI_LOADER_VARIABLE_STR("LoaderDeviceURL"), &loader_url);

                        if (!sd_id128_is_null(loader_partition_uuid)) {
                                /* If we know esp_uuid and loader_partition_uuid is not equal to it, print a warning. */
                                if (!sd_id128_is_null(esp_uuid) && !sd_id128_equal(loader_partition_uuid, esp_uuid))
                                        printf("WARNING: The boot loader reports a different partition UUID than the detected ESP "
                                               "("SD_ID128_UUID_FORMAT_STR" vs. "SD_ID128_UUID_FORMAT_STR")!\n",
                                               SD_ID128_FORMAT_VAL(loader_partition_uuid),
                                               SD_ID128_FORMAT_VAL(esp_uuid));

                                printf("     Partition: /dev/disk/by-partuuid/" SD_ID128_UUID_FORMAT_STR "\n",
                                       SD_ID128_FORMAT_VAL(loader_partition_uuid));
                        } else if (loader_path)
                                printf("     Partition: n/a\n");

                        if (loader_path)
                                printf("        Loader: %s%s%s/%s%s\n",
                                       glyph(GLYPH_TREE_RIGHT), ansi_grey(), arg_esp_path, ansi_normal(), loader_path);

                        if (loader_url)
                                printf("  Net Boot URL: %s\n", loader_url);

                        if (sysfail_entry)
                                printf("SysFail Reason: %s\n", sysfail_reason);

                        if (current_entry)
                                printf(" Current Entry: %s\n", current_entry);
                        if (default_entry)
                                printf(" Default Entry: %s\n", default_entry);
                        if (oneshot_entry && !streq_ptr(oneshot_entry, default_entry))
                                printf(" OneShot Entry: %s\n", oneshot_entry);
                        if (sysfail_entry)
                                printf(" SysFail Entry: %s\n", sysfail_entry);

                        printf("\n");
                }

                if (stub) {
                        printf("%sCurrent Stub:%s\n", ansi_underline(), ansi_normal());
                        printf("      Product: %s%s%s\n", ansi_highlight(), stub, ansi_normal());
                        for (size_t i = 0; i < ELEMENTSOF(stub_flags); i++)
                                print_yes_no_line(i == 0, FLAGS_SET(stub_features, stub_flags[i].flag), stub_flags[i].name);

                        sd_id128_t stub_partition_uuid = SD_ID128_NULL;
                        (void) efi_stub_get_device_part_uuid(&stub_partition_uuid);

                        _cleanup_free_ char *stub_url = NULL;
                        (void) efi_get_variable_string_and_warn(EFI_LOADER_VARIABLE_STR("StubDeviceURL"), &stub_url);

                        if (!sd_id128_is_null(stub_partition_uuid)) {
                                /* _If_ we know both esp_uuid and xbootldr_uuid and stub_partition_uuid is not equal
                                 * to _either_ of them, print a warning. */
                                if (!sd_id128_is_null(esp_uuid) && !sd_id128_equal(stub_partition_uuid, esp_uuid) &&
                                    !sd_id128_is_null(xbootldr_uuid) && !sd_id128_equal(stub_partition_uuid, xbootldr_uuid))
                                        printf("WARNING: The stub loader reports a different UUID than the detected ESP and XBOOTDLR partitions "
                                               "("SD_ID128_UUID_FORMAT_STR" vs. "SD_ID128_UUID_FORMAT_STR"/"SD_ID128_UUID_FORMAT_STR")!\n",
                                               SD_ID128_FORMAT_VAL(stub_partition_uuid),
                                               SD_ID128_FORMAT_VAL(esp_uuid),
                                               SD_ID128_FORMAT_VAL(xbootldr_uuid));

                                printf("    Partition: /dev/disk/by-partuuid/" SD_ID128_UUID_FORMAT_STR "\n",
                                       SD_ID128_FORMAT_VAL(stub_partition_uuid));
                        } else if (stub_path)
                                printf("    Partition: n/a\n");

                        if (stub_path)
                                printf("         Stub: %s%s\n", glyph(GLYPH_TREE_RIGHT), strna(stub_path));

                        if (stub_url)
                                printf(" Net Boot URL: %s\n", stub_url);

                        printf("\n");
                }

                printf("%sRandom Seed:%s\n", ansi_underline(), ansi_normal());
                have = access(EFIVAR_PATH(EFI_LOADER_VARIABLE_STR("LoaderSystemToken")), F_OK) >= 0;
                printf(" System Token: %s\n", have ? "set" : "not set");

                if (arg_esp_path) {
                        _cleanup_free_ char *p = NULL;

                        p = path_join(arg_esp_path, "/loader/random-seed");
                        if (!p)
                                return log_oom();

                        r = access(p, F_OK);
                        if (r < 0 && errno != ENOENT)
                                printf("       Exists: Can't access %s (%m)\n", p);
                        else
                                printf("       Exists: %s\n", yes_no(r >= 0));
                }

                printf("\n");
        }

        if (arg_esp_path)
                RET_GATHER(r, status_binaries(arg_esp_path, esp_uuid));

        if (!arg_root && is_efi_boot())
                RET_GATHER(r, status_variables());

        if (arg_esp_path || arg_xbootldr_path) {
                _cleanup_(boot_config_free) BootConfig config = BOOT_CONFIG_NULL;

                k = boot_config_load_and_select(&config,
                                                arg_esp_path, esp_devid,
                                                arg_xbootldr_path, xbootldr_devid);
                RET_GATHER(r, k);

                if (k >= 0)
                        RET_GATHER(r,
                                   status_entries(&config,
                                                  arg_esp_path, esp_uuid,
                                                  arg_xbootldr_path, xbootldr_uuid));
        }

        return r;
}

static int ref_file(Hashmap **known_files, const char *fn, int increment) {
        char *k = NULL;
        int n, r;

        assert(known_files);

        /* just gracefully ignore this. This way the caller doesn't have to verify whether the bootloader
         * entry is relevant. */
        if (!fn)
                return 0;

        n = PTR_TO_INT(hashmap_get2(*known_files, fn, (void**)&k));
        n += increment;

        assert(n >= 0);

        if (n == 0) {
                (void) hashmap_remove(*known_files, fn);
                free(k);
        } else if (!k) {
                _cleanup_free_ char *t = NULL;

                t = strdup(fn);
                if (!t)
                        return -ENOMEM;
                r = hashmap_ensure_put(known_files, &path_hash_ops_free, t, INT_TO_PTR(n));
                if (r < 0)
                        return r;
                TAKE_PTR(t);
        } else {
                r = hashmap_update(*known_files, fn, INT_TO_PTR(n));
                if (r < 0)
                        return r;
        }

        return n;
}

static void deref_unlink_file(Hashmap **known_files, const char *fn, const char *root) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(known_files);

        /* just gracefully ignore this. This way the caller doesn't
           have to verify whether the bootloader entry is relevant */
        if (!fn || !root)
                return;

        r = ref_file(known_files, fn, -1);
        if (r < 0)
                return (void) log_warning_errno(r, "Failed to deref \"%s\", ignoring: %m", fn);
        if (r > 0)
                return;

        if (arg_dry_run) {
                r = chase_and_access(fn, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, F_OK, &path);
                if (r < 0)
                        log_info_errno(r, "Unable to determine whether \"%s\" exists, ignoring: %m", fn);
                else
                        log_info("Would remove \"%s\"", path);
                return;
        }

        r = chase_and_unlink(fn, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, 0, &path);
        if (r >= 0)
                log_info("Removed \"%s\"", path);
        else if (r != -ENOENT)
                return (void) log_warning_errno(r, "Failed to remove \"%s\", ignoring: %m", fn);

        _cleanup_free_ char *d = NULL;
        if (path_extract_directory(fn, &d) >= 0 && !path_equal(d, "/")) {
                r = chase_and_unlink(d, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, AT_REMOVEDIR, NULL);
                if (r < 0 && !IN_SET(r, -ENOTEMPTY, -ENOENT))
                        log_warning_errno(r, "Failed to remove directory \"%s\", ignoring: %m", d);
        }
}

static int count_known_files(const BootConfig *config, const char* root, Hashmap **ret_known_files) {
        _cleanup_hashmap_free_ Hashmap *known_files = NULL;
        int r;

        assert(config);
        assert(ret_known_files);

        for (size_t i = 0; i < config->n_entries; i++) {
                const BootEntry *e = config->entries + i;

                if (!path_equal(e->root, root))
                        continue;

                r = ref_file(&known_files, e->kernel, +1);
                if (r < 0)
                        return r;
                r = ref_file(&known_files, e->efi, +1);
                if (r < 0)
                        return r;
                STRV_FOREACH(s, e->initrd) {
                        r = ref_file(&known_files, *s, +1);
                        if (r < 0)
                                return r;
                }
                r = ref_file(&known_files, e->device_tree, +1);
                if (r < 0)
                        return r;
                STRV_FOREACH(s, e->device_tree_overlay) {
                        r = ref_file(&known_files, *s, +1);
                        if (r < 0)
                                return r;
                }
        }

        *ret_known_files = TAKE_PTR(known_files);

        return 0;
}

static int boot_config_find_in(const BootConfig *config, const char *root, const char *id) {
        assert(config);

        if (!root || !id)
                return -ENOENT;

        for (size_t i = 0; i < config->n_entries; i++)
                if (path_equal(config->entries[i].root, root) &&
                    fnmatch(id, config->entries[i].id, FNM_CASEFOLD) == 0)
                        return i;

        return -ENOENT;
}

static int unlink_entry(const BootConfig *config, const char *root, const char *id) {
        _cleanup_hashmap_free_ Hashmap *known_files = NULL;
        const BootEntry *e = NULL;
        int r;

        assert(config);

        r = count_known_files(config, root, &known_files);
        if (r < 0)
                return log_error_errno(r, "Failed to count files in %s: %m", root);

        r = boot_config_find_in(config, root, id);
        if (r < 0)
                return r;

        if (r == config->default_entry)
                log_warning("%s is the default boot entry", id);
        if (r == config->selected_entry)
                log_warning("%s is the selected boot entry", id);

        e = &config->entries[r];

        deref_unlink_file(&known_files, e->kernel, e->root);
        deref_unlink_file(&known_files, e->efi, e->root);
        STRV_FOREACH(s, e->initrd)
                deref_unlink_file(&known_files, *s, e->root);
        deref_unlink_file(&known_files, e->device_tree, e->root);
        STRV_FOREACH(s, e->device_tree_overlay)
                deref_unlink_file(&known_files, *s, e->root);

        if (arg_dry_run)
                log_info("Would remove \"%s\"", e->path);
        else {
                r = chase_and_unlink(e->path, root, CHASE_PROHIBIT_SYMLINKS, 0, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to remove \"%s\": %m", e->path);

                log_info("Removed %s", e->path);
        }

        return 0;
}

static int list_remove_orphaned_file(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        Hashmap *known_files = userdata;

        assert(path);

        if (event != RECURSE_DIR_ENTRY)
                return RECURSE_DIR_CONTINUE;

        if (hashmap_get(known_files, path))
                return RECURSE_DIR_CONTINUE; /* keep! */

        if (arg_dry_run)
                log_info("Would remove %s", path);
        else if (unlinkat(dir_fd, de->d_name, 0) < 0)
                log_warning_errno(errno, "Failed to remove \"%s\", ignoring: %m", path);
        else
                log_info("Removed %s", path);

        return RECURSE_DIR_CONTINUE;
}

static int cleanup_orphaned_files(
                const BootConfig *config,
                const char *root) {

        _cleanup_hashmap_free_ Hashmap *known_files = NULL;
        _cleanup_free_ char *full = NULL, *p = NULL;
        _cleanup_close_ int dir_fd = -EBADF;
        int r;

        assert(config);
        assert(root);

        log_info("Cleaning %s", root);

        r = settle_entry_token();
        if (r < 0)
                return r;

        r = count_known_files(config, root, &known_files);
        if (r < 0)
                return log_error_errno(r, "Failed to count files in %s: %m", root);

        dir_fd = chase_and_open(arg_entry_token, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS,
                        O_DIRECTORY|O_CLOEXEC, &full);
        if (dir_fd == -ENOENT)
                return 0;
        if (dir_fd < 0)
                return log_error_errno(dir_fd, "Failed to open '%s/%s': %m", root, skip_leading_slash(arg_entry_token));

        p = path_join("/", arg_entry_token);
        if (!p)
                return log_oom();

        r = recurse_dir(dir_fd, p, 0, UINT_MAX, RECURSE_DIR_SORT, list_remove_orphaned_file, known_files);
        if (r < 0)
                return log_error_errno(r, "Failed to cleanup %s: %m", full);

        return r;
}

int verb_list(int argc, char *argv[], void *userdata) {
        _cleanup_(boot_config_free) BootConfig config = BOOT_CONFIG_NULL;
        dev_t esp_devid = 0, xbootldr_devid = 0;
        int r;

        /* If we lack privileges we invoke find_esp_and_warn() in "unprivileged mode" here, which does two
         * things: turn off logging about access errors and turn off potentially privileged device probing.
         * Here we're interested in the latter but not the former, hence request the mode, and log about
         * EACCES. */

        r = acquire_esp(/* unprivileged_mode= */ -1, /* graceful= */ false, NULL, NULL, NULL, NULL, &esp_devid);
        if (r == -EACCES) /* We really need the ESP path for this call, hence also log about access errors */
                return log_error_errno(r, "Failed to determine ESP location: %m");
        if (r < 0)
                return r;

        r = acquire_xbootldr(/* unprivileged_mode= */ -1, NULL, &xbootldr_devid);
        if (r == -EACCES)
                return log_error_errno(r, "Failed to determine XBOOTLDR partition: %m");
        if (r < 0)
                return r;

        r = boot_config_load_and_select(&config, arg_esp_path, esp_devid, arg_xbootldr_path, xbootldr_devid);
        if (r < 0)
                return r;

        if (config.n_entries == 0 && !sd_json_format_enabled(arg_json_format_flags)) {
                log_info("No boot loader entries found.");
                return 0;
        }

        if (streq(argv[0], "list")) {
                pager_open(arg_pager_flags);
                return show_boot_entries(&config, arg_json_format_flags);
        } else if (streq(argv[0], "cleanup")) {
                if (arg_xbootldr_path && xbootldr_devid != esp_devid)
                        cleanup_orphaned_files(&config, arg_xbootldr_path);
                return cleanup_orphaned_files(&config, arg_esp_path);
        } else {
                assert(streq(argv[0], "unlink"));
                if (arg_xbootldr_path && xbootldr_devid != esp_devid) {
                        r = unlink_entry(&config, arg_xbootldr_path, argv[1]);
                        if (r == 0 || r != -ENOENT)
                                return r;
                }
                return unlink_entry(&config, arg_esp_path, argv[1]);
        }
}

int verb_unlink(int argc, char *argv[], void *userdata) {
        return verb_list(argc, argv, userdata);
}

int vl_method_list_boot_entries(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(boot_config_free) BootConfig config = BOOT_CONFIG_NULL;
        dev_t esp_devid = 0, xbootldr_devid = 0;
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table = */ NULL, /* userdata = */ NULL);
        if (r != 0)
                return r;

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        r = acquire_esp(/* unprivileged_mode= */ false,
                        /* graceful= */ false,
                        /* ret_part= */ NULL,
                        /* ret_pstart= */ NULL,
                        /* ret_psize= */ NULL,
                        /* ret_uuid=*/ NULL,
                        &esp_devid);
        if (r == -EACCES) /* We really need the ESP path for this call, hence also log about access errors */
                return log_error_errno(r, "Failed to determine ESP location: %m");
        if (r < 0)
                return r;

        r = acquire_xbootldr(
                        /* unprivileged_mode= */ false,
                        /* ret_uuid= */ NULL,
                        &xbootldr_devid);
        if (r == -EACCES)
                return log_error_errno(r, "Failed to determine XBOOTLDR partition: %m");
        if (r < 0)
                return r;

        r = boot_config_load_and_select(&config, arg_esp_path, esp_devid, arg_xbootldr_path, xbootldr_devid);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *previous = NULL;
        for (size_t i = 0; i < config.n_entries; i++) {
                if (previous) {
                        r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_VARIANT("entry", previous));
                        if (r < 0)
                                return r;

                        previous = sd_json_variant_unref(previous);
                }

                r = boot_entry_to_json(&config, i, &previous);
                if (r < 0)
                        return r;
        }

        if (!previous)
                return sd_varlink_error(link, "io.systemd.BootControl.NoSuchBootEntry", NULL);

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("entry", previous));
}
