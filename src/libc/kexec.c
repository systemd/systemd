/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/kexec.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !HAVE_KEXEC_FILE_LOAD && defined __NR_kexec_file_load
int missing_kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline, unsigned long flags) {
        return syscall(__NR_kexec_file_load, kernel_fd, initrd_fd, cmdline_len, cmdline, flags);
}
#endif
