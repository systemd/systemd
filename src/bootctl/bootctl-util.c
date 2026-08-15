/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "boot-entry.h"
#include "bootctl.h"
#include "bootctl-util.h"
#include "efivars.h"
#include "errno-util.h"
#include "fileio.h"
#include "log.h"
#include "pe-binary.h"
#include "string-util.h"
#include "sync-util.h"
#include "virt.h"

bool touch_variables(void) {
        /* If we run in a container or on a non-EFI system, automatically turn off EFI file system access,
         * unless explicitly overridden. */

        if (arg_touch_variables >= 0)
                return set_efi_boot(arg_touch_variables);

        if (arg_root) {
                log_once(LOG_NOTICE,
                         "Operating on %s, skipping EFI variable modifications.",
                         arg_image ? "image" : "root directory");
                return set_efi_boot(false);
        }

        if (!is_efi_boot()) { /* NB: this internally checks if we run in a container */
                log_once(LOG_NOTICE,
                         "Not booted with EFI or running in a container, skipping EFI variable modifications.");
                return false;
        }

        return true;
}

int verify_touch_variables_allowed(const char *command) {
        /* Note: changing EFI variables is the primary purpose of these verbs, hence unlike in the other
         * verbs that might touch EFI variables where we skip things gracefully, here we fail loudly if we
         * are not run on EFI or EFI variable modifications were turned off. */

        if (arg_touch_variables > 0) {
                /* If we explicitly allowed to touch EFI variables, then skip the is_efi_boot() checks used
                 * at various places. */
                set_efi_boot(true);
                return 0;
        }

        if (arg_touch_variables == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "'%s' operation cannot be combined with --variables=no.",
                                       command);

        if (arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Acting on %s, refusing EFI variable setup.",
                                       arg_image ? "image" : "root directory");

        if (detect_container() > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "'%s' operation not supported in a container.",
                                       command);

        if (!is_efi_boot())
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Not booted with UEFI.");

        if (access(EFIVAR_PATH(EFI_LOADER_VARIABLE_STR("LoaderInfo")), F_OK) < 0) {
                if (errno == ENOENT) {
                        log_error_errno(errno, "Not booted with a supported boot loader.");
                        return -EOPNOTSUPP;
                }

                return log_error_errno(errno, "Failed to detect whether boot loader supports '%s' operation: %m", command);
        }

        return 0;
}

int sync_everything(void) {
        int r = 0, k;

        if (arg_esp_path) {
                k = syncfs_path(AT_FDCWD, arg_esp_path);
                if (k < 0)
                        RET_GATHER(r, log_error_errno(k, "Failed to synchronize the ESP '%s': %m", arg_esp_path));
        }

        if (arg_xbootldr_path) {
                k = syncfs_path(AT_FDCWD, arg_xbootldr_path);
                if (k < 0)
                        RET_GATHER(r, log_error_errno(k, "Failed to synchronize $BOOT '%s': %m", arg_xbootldr_path));
        }

        return r;
}

const char* get_efi_arch(void) {
        /* Detect EFI firmware architecture of the running system. On mixed mode systems, it could be 32-bit
         * while the kernel is running in 64-bit. */

#ifdef __x86_64__
        _cleanup_free_ char *platform_size = NULL;
        int r;

        r = read_one_line_file("/sys/firmware/efi/fw_platform_size", &platform_size);
        if (r == -ENOENT)
                return EFI_MACHINE_TYPE_NAME;
        if (r < 0) {
                log_warning_errno(r,
                        "Error reading EFI firmware word size, assuming machine type '%s': %m",
                        EFI_MACHINE_TYPE_NAME);
                return EFI_MACHINE_TYPE_NAME;
        }

        if (streq(platform_size, "64"))
                return EFI_MACHINE_TYPE_NAME;
        if (streq(platform_size, "32"))
                return "ia32";

        log_warning(
                "Unknown EFI firmware word size '%s', using machine type '%s'.",
                platform_size,
                EFI_MACHINE_TYPE_NAME);
#endif

        return EFI_MACHINE_TYPE_NAME;
}

int get_file_version(int fd, char **ret) {
        int r;

        assert(fd >= 0);
        assert(ret);

        /* Reads the version marker that systemd-boot/systemd-stub and friends store in their ".sdmagic" PE
         * section, i.e. a string such as "#### LoaderInfo: systemd-boot 218 ####", and returns the inner
         * part, e.g. "systemd-boot 218". Does not reposition the file offset (as it uses pread()). */

        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        r = pe_load_headers(fd, &dos_header, &pe_header);
        if (r == -EBADMSG)
                return log_debug_errno(SYNTHETIC_ERRNO(ESRCH), "EFI binary is not a valid PE file, assuming no version information.");
        if (r < 0)
                return r;

        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        r = pe_load_sections(fd, dos_header, pe_header, &sections);
        if (r == -EBADMSG)
                return log_debug_errno(SYNTHETIC_ERRNO(ESRCH), "Failed to load PE section table, assuming no version information.");
        if (r < 0)
                return r;

        _cleanup_free_ char *sdmagic = NULL;
        r = pe_read_section_data_by_name(
                        fd,
                        pe_header,
                        sections,
                        ".sdmagic",
                        /* max_size= */ 4U*1024U,
                        (void**) &sdmagic,
                        /* ret_size= */ NULL);
        if (IN_SET(r, -ENXIO, -EBADMSG))
                return log_debug_errno(SYNTHETIC_ERRNO(ESRCH), "EFI binary has no .sdmagic section, assuming no version information.");
        if (r < 0)
                return log_debug_errno(r, "Failed to read .sdmagic section of EFI binary: %m");

        const char *p = startswith(sdmagic, "#### LoaderInfo: ");
        if (!p)
                return log_debug_errno(SYNTHETIC_ERRNO(ESRCH), "EFI binary .sdmagic section lacks LoaderInfo marker.");

        const char *e = endswith(p, " ####");
        if (!e || e <= p)
                return log_debug_errno(SYNTHETIC_ERRNO(ESRCH), "EFI binary has malformed LoaderInfo marker.");

        char *marker = strndup(p, e - p);
        if (!marker)
                return log_oom_debug();

        log_debug("EFI binary LoaderInfo marker: \"%s\"", marker);
        *ret = TAKE_PTR(marker);
        return 0;
}

int settle_entry_token(void) {
        int r;

        r = boot_entry_token_ensure(
                        arg_root,
                        secure_getenv("KERNEL_INSTALL_CONF_ROOT"),
                        arg_machine_id,
                        /* machine_id_is_random= */ false,
                        &arg_entry_token_type,
                        &arg_entry_token);
        if (r < 0)
                return r;

        log_debug("Using entry token: %s", arg_entry_token);
        return 0;
}
