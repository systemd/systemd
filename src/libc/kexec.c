/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/kexec.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef __NR_kexec_file_load
#undef kexec_file_load
extern typeof(missing_kexec_file_load) kexec_file_load __attribute__((weak));
int missing_kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline, unsigned long flags) {
        if (kexec_file_load)
                return kexec_file_load(kernel_fd, initrd_fd, cmdline_len, cmdline, flags);
        return syscall(__NR_kexec_file_load, kernel_fd, initrd_fd, cmdline_len, cmdline, flags);
}
#endif
