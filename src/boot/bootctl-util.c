/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mman.h>

#include "bootctl.h"
#include "bootctl-util.h"
#include "fileio.h"
#include "stat-util.h"
#include "sync-util.h"

int sync_everything(void) {
        int ret = 0, k;

        if (arg_esp_path) {
                k = syncfs_path(AT_FDCWD, arg_esp_path);
                if (k < 0)
                        ret = log_error_errno(k, "Failed to synchronize the ESP '%s': %m", arg_esp_path);
        }

        if (arg_xbootldr_path) {
                k = syncfs_path(AT_FDCWD, arg_xbootldr_path);
                if (k < 0)
                        ret = log_error_errno(k, "Failed to synchronize $BOOT '%s': %m", arg_xbootldr_path);
        }

        return ret;
}

const char *get_efi_arch(void) {
        /* Detect EFI firmware architecture of the running system. On mixed mode systems, it could be 32bit
         * while the kernel is running in 64bit. */

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

/* search for "#### LoaderInfo: systemd-boot 218 ####" string inside the binary */
int get_file_version(int fd, char **ret) {
        struct stat st;
        char *buf;
        const char *s, *e;
        char *x = NULL;
        int r;

        assert(fd >= 0);
        assert(ret);

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat EFI binary: %m");

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_error_errno(r, "EFI binary is not a regular file: %m");

        if (st.st_size < 27 || file_offset_beyond_memory_size(st.st_size)) {
                *ret = NULL;
                return 0;
        }

        buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (buf == MAP_FAILED)
                return log_error_errno(errno, "Failed to memory map EFI binary: %m");

        s = mempmem_safe(buf, st.st_size - 8, "#### LoaderInfo: ", 17);
        if (!s) {
                r = -ESRCH;
                goto finish;
        }

        e = memmem_safe(s, st.st_size - (s - buf), " ####", 5);
        if (!e || e - s < 3) {
                r = log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Malformed version string.");
                goto finish;
        }

        x = strndup(s, e - s);
        if (!x) {
                r = log_oom();
                goto finish;
        }
        r = 1;

finish:
        (void) munmap(buf, st.st_size);
        if (r >= 0)
                *ret = x;

        return r;
}

int settle_entry_token(void) {
        int r;

<<<<<<< HEAD
        r = boot_entry_token_ensure(
                        arg_root,
                        etc_kernel(),
                        arg_machine_id,
                        &arg_entry_token_type,
                        &arg_entry_token);
        if (r < 0)
                return r;
=======
        switch (arg_entry_token_type) {

        case ARG_ENTRY_TOKEN_AUTO: {
                _cleanup_free_ char *buf = NULL, *p = NULL;
                p = path_join(arg_root, etc_kernel(), "entry-token");
                if (!p)
                        return log_oom();
                r = read_one_line_file(p, &buf);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read %s: %m", p);

                if (!isempty(buf)) {
                        free_and_replace(arg_entry_token, buf);
                        arg_entry_token_type = ARG_ENTRY_TOKEN_LITERAL;
                } else if (sd_id128_is_null(arg_machine_id)) {
                        _cleanup_free_ char *id = NULL, *image_id = NULL;

                        r = parse_os_release(arg_root,
                                             IMAGE_EXTENSION,
                                             "IMAGE_ID", &image_id,
                                             "ID", &id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to load /etc/os-release: %m");

                        if (!isempty(image_id)) {
                                free_and_replace(arg_entry_token, image_id);
                                arg_entry_token_type = ARG_ENTRY_TOKEN_OS_IMAGE_ID;
                        } else if (!isempty(id)) {
                                free_and_replace(arg_entry_token, id);
                                arg_entry_token_type = ARG_ENTRY_TOKEN_OS_ID;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No machine ID set, and /etc/os-release carries no ID=/IMAGE_ID= fields.");
                } else {
                        r = free_and_strdup_warn(&arg_entry_token, SD_ID128_TO_STRING(arg_machine_id));
                        if (r < 0)
                                return r;

                        arg_entry_token_type = ARG_ENTRY_TOKEN_MACHINE_ID;
                }

                break;
        }

        case ARG_ENTRY_TOKEN_MACHINE_ID:
                if (sd_id128_is_null(arg_machine_id))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No machine ID set.");

                r = free_and_strdup_warn(&arg_entry_token, SD_ID128_TO_STRING(arg_machine_id));
                if (r < 0)
                        return r;

                break;

        case ARG_ENTRY_TOKEN_OS_IMAGE_ID: {
                _cleanup_free_ char *buf = NULL;

                r = parse_os_release(arg_root, IMAGE_EXTENSION, "IMAGE_ID", &buf);
                if (r < 0)
                        return log_error_errno(r, "Failed to load /etc/os-release: %m");

                if (isempty(buf))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "IMAGE_ID= field not set in /etc/os-release.");

                free_and_replace(arg_entry_token, buf);
                break;
        }

        case ARG_ENTRY_TOKEN_OS_ID: {
                _cleanup_free_ char *buf = NULL;

                r = parse_os_release(arg_root, IMAGE_EXTENSION, "ID", &buf);
                if (r < 0)
                        return log_error_errno(r, "Failed to load /etc/os-release: %m");

                if (isempty(buf))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "ID= field not set in /etc/os-release.");

                free_and_replace(arg_entry_token, buf);
                break;
        }

        case ARG_ENTRY_TOKEN_LITERAL:
                assert(!isempty(arg_entry_token)); /* already filled in by command line parser */
                break;
        }

        if (isempty(arg_entry_token) || !(utf8_is_valid(arg_entry_token) && string_is_safe(arg_entry_token)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected entry token not valid: %s", arg_entry_token);
>>>>>>> os-util: add a new syscfg image type and the ability to parse their release files

        log_debug("Using entry token: %s", arg_entry_token);
        return 0;
}
