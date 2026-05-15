/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/kexec.h>          /* IWYU pragma: export */
#include <sys/syscall.h>

/* Supported since kernel v3.17 (cb1052581e2bddd6096544f3f944f4e7fdad4c4f).
 * Not available on all architectures. */
#ifdef __NR_kexec_file_load
int kexec_file_load_shim(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline, unsigned long flags);
#  define kexec_file_load kexec_file_load_shim
#  define HAVE_KEXEC_FILE_LOAD_SYSCALL 1
#else
#  define HAVE_KEXEC_FILE_LOAD_SYSCALL 0
#endif
