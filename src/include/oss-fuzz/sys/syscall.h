/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/syscall.h>

#include <assert.h>

#ifndef __IGNORE_close_range
#  if defined(__aarch64__)
#    define systemd_NR_close_range 436
#  elif defined(__alpha__)
#    define systemd_NR_close_range 546
#  elif defined(__arc__) || defined(__tilegx__)
#    define systemd_NR_close_range 436
#  elif defined(__arm__)
#    define systemd_NR_close_range 436
#  elif defined(__i386__)
#    define systemd_NR_close_range 436
#  elif defined(__ia64__)
#    define systemd_NR_close_range 1460
#  elif defined(__loongarch_lp64)
#    define systemd_NR_close_range 436
#  elif defined(__m68k__)
#    define systemd_NR_close_range 436
#  elif defined(_MIPS_SIM)
#    if _MIPS_SIM == _MIPS_SIM_ABI32
#      define systemd_NR_close_range 4436
#    elif _MIPS_SIM == _MIPS_SIM_NABI32
#      define systemd_NR_close_range 6436
#    elif _MIPS_SIM == _MIPS_SIM_ABI64
#      define systemd_NR_close_range 5436
#    else
#      error "Unknown MIPS ABI"
#    endif
#  elif defined(__hppa__)
#    define systemd_NR_close_range 436
#  elif defined(__powerpc__)
#    define systemd_NR_close_range 436
#  elif defined(__riscv)
#    if __riscv_xlen == 32
#      define systemd_NR_close_range 436
#    elif __riscv_xlen == 64
#      define systemd_NR_close_range 436
#    else
#      error "Unknown RISC-V ABI"
#    endif
#  elif defined(__s390__)
#    define systemd_NR_close_range 436
#  elif defined(__sh__)
#    define systemd_NR_close_range 436
#  elif defined(__sparc__)
#    define systemd_NR_close_range 436
#  elif defined(__x86_64__)
#    if defined(__ILP32__)
#      define systemd_NR_close_range (436 | /* __X32_SYSCALL_BIT */ 0x40000000)
#    else
#      define systemd_NR_close_range 436
#    endif
#  elif !defined(missing_arch_template)
#    warning "close_range() syscall number is unknown for your architecture"
#  endif

/* may be an (invalid) negative number due to libseccomp, see PR 13319 */
#  if defined __NR_close_range && __NR_close_range >= 0
#    if defined systemd_NR_close_range
static_assert(__NR_close_range == systemd_NR_close_range, "");
#    endif
#  else
#    if defined __NR_close_range
#      undef __NR_close_range
#    endif
#    if defined systemd_NR_close_range && systemd_NR_close_range >= 0
#      define __NR_close_range systemd_NR_close_range
#    endif
#  endif
#endif

#ifndef __IGNORE_mount_setattr
#  if defined(__aarch64__)
#    define systemd_NR_mount_setattr 442
#  elif defined(__alpha__)
#    define systemd_NR_mount_setattr 552
#  elif defined(__arc__) || defined(__tilegx__)
#    define systemd_NR_mount_setattr 442
#  elif defined(__arm__)
#    define systemd_NR_mount_setattr 442
#  elif defined(__i386__)
#    define systemd_NR_mount_setattr 442
#  elif defined(__ia64__)
#    define systemd_NR_mount_setattr 1466
#  elif defined(__loongarch_lp64)
#    define systemd_NR_mount_setattr 442
#  elif defined(__m68k__)
#    define systemd_NR_mount_setattr 442
#  elif defined(_MIPS_SIM)
#    if _MIPS_SIM == _MIPS_SIM_ABI32
#      define systemd_NR_mount_setattr 4442
#    elif _MIPS_SIM == _MIPS_SIM_NABI32
#      define systemd_NR_mount_setattr 6442
#    elif _MIPS_SIM == _MIPS_SIM_ABI64
#      define systemd_NR_mount_setattr 5442
#    else
#      error "Unknown MIPS ABI"
#    endif
#  elif defined(__hppa__)
#    define systemd_NR_mount_setattr 442
#  elif defined(__powerpc__)
#    define systemd_NR_mount_setattr 442
#  elif defined(__riscv)
#    if __riscv_xlen == 32
#      define systemd_NR_mount_setattr 442
#    elif __riscv_xlen == 64
#      define systemd_NR_mount_setattr 442
#    else
#      error "Unknown RISC-V ABI"
#    endif
#  elif defined(__s390__)
#    define systemd_NR_mount_setattr 442
#  elif defined(__sh__)
#    define systemd_NR_mount_setattr 442
#  elif defined(__sparc__)
#    define systemd_NR_mount_setattr 442
#  elif defined(__x86_64__)
#    if defined(__ILP32__)
#      define systemd_NR_mount_setattr (442 | /* __X32_SYSCALL_BIT */ 0x40000000)
#    else
#      define systemd_NR_mount_setattr 442
#    endif
#  elif !defined(missing_arch_template)
#    warning "mount_setattr() syscall number is unknown for your architecture"
#  endif

/* may be an (invalid) negative number due to libseccomp, see PR 13319 */
#  if defined __NR_mount_setattr && __NR_mount_setattr >= 0
#    if defined systemd_NR_mount_setattr
static_assert(__NR_mount_setattr == systemd_NR_mount_setattr, "");
#    endif
#  else
#    if defined __NR_mount_setattr
#      undef __NR_mount_setattr
#    endif
#    if defined systemd_NR_mount_setattr && systemd_NR_mount_setattr >= 0
#      define __NR_mount_setattr systemd_NR_mount_setattr
#    endif
#  endif
#endif

#ifndef __IGNORE_openat2
#  if defined(__aarch64__)
#    define systemd_NR_openat2 437
#  elif defined(__alpha__)
#    define systemd_NR_openat2 547
#  elif defined(__arc__) || defined(__tilegx__)
#    define systemd_NR_openat2 437
#  elif defined(__arm__)
#    define systemd_NR_openat2 437
#  elif defined(__i386__)
#    define systemd_NR_openat2 437
#  elif defined(__ia64__)
#    define systemd_NR_openat2 1461
#  elif defined(__loongarch_lp64)
#    define systemd_NR_openat2 437
#  elif defined(__m68k__)
#    define systemd_NR_openat2 437
#  elif defined(_MIPS_SIM)
#    if _MIPS_SIM == _MIPS_SIM_ABI32
#      define systemd_NR_openat2 4437
#    elif _MIPS_SIM == _MIPS_SIM_NABI32
#      define systemd_NR_openat2 6437
#    elif _MIPS_SIM == _MIPS_SIM_ABI64
#      define systemd_NR_openat2 5437
#    else
#      error "Unknown MIPS ABI"
#    endif
#  elif defined(__hppa__)
#    define systemd_NR_openat2 437
#  elif defined(__powerpc__)
#    define systemd_NR_openat2 437
#  elif defined(__riscv)
#    if __riscv_xlen == 32
#      define systemd_NR_openat2 437
#    elif __riscv_xlen == 64
#      define systemd_NR_openat2 437
#    else
#      error "Unknown RISC-V ABI"
#    endif
#  elif defined(__s390__)
#    define systemd_NR_openat2 437
#  elif defined(__sh__)
#    define systemd_NR_openat2 437
#  elif defined(__sparc__)
#    define systemd_NR_openat2 437
#  elif defined(__x86_64__)
#    if defined(__ILP32__)
#      define systemd_NR_openat2 (437 | /* __X32_SYSCALL_BIT */ 0x40000000)
#    else
#      define systemd_NR_openat2 437
#    endif
#  elif !defined(missing_arch_template)
#    warning "openat2() syscall number is unknown for your architecture"
#  endif

/* may be an (invalid) negative number due to libseccomp, see PR 13319 */
#  if defined __NR_openat2 && __NR_openat2 >= 0
#    if defined systemd_NR_openat2
static_assert(__NR_openat2 == systemd_NR_openat2, "");
#    endif
#  else
#    if defined __NR_openat2
#      undef __NR_openat2
#    endif
#    if defined systemd_NR_openat2 && systemd_NR_openat2 >= 0
#      define __NR_openat2 systemd_NR_openat2
#    endif
#  endif
#endif
