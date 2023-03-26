/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mman.h>

#include "bootctl.h"
#include "bootctl-util.h"
#include "fileio.h"
#include "os-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "sync-util.h"
#include "utf8.h"

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

        if (!arg_entry_token) {
                r = boot_entry_token_from_type(
                                arg_root,
                                etc_kernel(),
                                arg_machine_id,
                                &arg_entry_token_type,
                                &arg_entry_token);
                if (r < 0)
                        return r;
        }

        log_debug("Using entry token: %s", arg_entry_token);
        return 0;
}
