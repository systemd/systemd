/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/kexec.h>

#include "libc-shim.h"

#ifdef __NR_kexec_file_load
DEFINE_SYSCALL_SHIM(kexec_file_load, int,
                    int, kernel_fd,
                    int, initrd_fd,
                    unsigned long, cmdline_len,
                    const char *, cmdline,
                    unsigned long, flags)
#endif
