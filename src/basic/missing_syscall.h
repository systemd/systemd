/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Missing glibc definitions to access certain kernel APIs */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef ARCH_MIPS
#include <asm/sgidefs.h>
#endif

#if defined(__x86_64__) && defined(__ILP32__)
#  define systemd_SC_arch_bias(x) ((x) | /* __X32_SYSCALL_BIT */ 0x40000000)
#elif defined(__ia64__)
#  define systemd_SC_arch_bias(x) (1024 + (x))
#elif defined __alpha__
#  define systemd_SC_arch_bias(x) (110 + (x))
#elif defined _MIPS_SIM
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#    define systemd_SC_arch_bias(x) (4000 + (x))
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#    define systemd_SC_arch_bias(x) (6000 + (x))
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#    define systemd_SC_arch_bias(x) (5000 + (x))
#  else
#    error "Unknown MIPS ABI"
#  endif
#else
#  define systemd_SC_arch_bias(x) (x)
#endif

#include "missing_keyctl.h"
#include "missing_stat.h"

/* linux/kcmp.h */
#ifndef KCMP_FILE /* 3f4994cfc15f38a3159c6e3a4b3ab2e1481a6b02 (3.19) */
#define KCMP_FILE 0
#endif

#if !HAVE_PIVOT_ROOT
static inline int missing_pivot_root(const char *new_root, const char *put_old) {
        return syscall(__NR_pivot_root, new_root, put_old);
}

#  define pivot_root missing_pivot_root
#endif

/* ======================================================================= */

#if defined __x86_64__
#  define systemd_NR_memfd_create systemd_SC_arch_bias(319)
#elif defined __arm__
#  define systemd_NR_memfd_create 385
#elif defined __aarch64__
#  define systemd_NR_memfd_create 279
#elif defined(__powerpc__)
#  define systemd_NR_memfd_create 360
#elif defined __s390__
#  define systemd_NR_memfd_create 350
#elif defined _MIPS_SIM
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#    define systemd_NR_memfd_create systemd_SC_arch_bias(354)
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#    define systemd_NR_memfd_create systemd_SC_arch_bias(318)
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#    define systemd_NR_memfd_create systemd_SC_arch_bias(314)
#  endif
#elif defined __i386__
#  define systemd_NR_memfd_create 356
#elif defined __arc__
#  define systemd_NR_memfd_create 279
#else
#  warning "memfd_create() syscall number unknown for your architecture"
#endif

/* may be (invalid) negative number due to libseccomp, see PR 13319 */
#if defined __NR_memfd_create && __NR_memfd_create >= 0
#  if defined systemd_NR_memfd_create
assert_cc(__NR_memfd_create == systemd_NR_memfd_create);
#  endif
#else
#  if defined __NR_memfd_create
#    undef __NR_memfd_create
#  endif
#  if defined systemd_NR_memfd_create
#    define __NR_memfd_create systemd_NR_memfd_create
#  endif
#endif

#if !HAVE_MEMFD_CREATE
static inline int missing_memfd_create(const char *name, unsigned int flags) {
#  ifdef __NR_memfd_create
        return syscall(__NR_memfd_create, name, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define memfd_create missing_memfd_create
#endif

/* ======================================================================= */

#if defined __x86_64__
#  define systemd_NR_getrandom systemd_SC_arch_bias(318)
#elif defined(__i386__)
#  define systemd_NR_getrandom 355
#elif defined(__arm__)
#  define systemd_NR_getrandom 384
#elif defined(__aarch64__)
#  define systemd_NR_getrandom 278
#elif defined(__ia64__)
#  define systemd_NR_getrandom systemd_SC_arch_bias(318)
#elif defined(__m68k__)
#  define systemd_NR_getrandom 352
#elif defined(__s390x__)
#  define systemd_NR_getrandom 349
#elif defined(__powerpc__)
#  define systemd_NR_getrandom 359
#elif defined _MIPS_SIM
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#    define systemd_NR_getrandom systemd_SC_arch_bias(353)
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#    define systemd_NR_getrandom systemd_SC_arch_bias(317)
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#    define systemd_NR_getrandom systemd_SC_arch_bias(313)
#  endif
#elif defined(__arc__)
#  define systemd_NR_getrandom 278
#else
#  warning "getrandom() syscall number unknown for your architecture"
#endif

/* may be (invalid) negative number due to libseccomp, see PR 13319 */
#if defined __NR_getrandom && __NR_getrandom >= 0
#  if defined systemd_NR_getrandom
assert_cc(__NR_getrandom == systemd_NR_getrandom);
#  endif
#else
#  if defined __NR_getrandom
#    undef __NR_getrandom
#  endif
#  if defined systemd_NR_getrandom
#    define __NR_getrandom systemd_NR_getrandom
#  endif
#endif

#if !HAVE_GETRANDOM
static inline int missing_getrandom(void *buffer, size_t count, unsigned flags) {
#  ifdef __NR_getrandom
        return syscall(__NR_getrandom, buffer, count, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define getrandom missing_getrandom
#endif

/* ======================================================================= */

/* The syscall has been defined since forever, but the glibc wrapper was missing. */
#if !HAVE_GETTID
static inline pid_t missing_gettid(void) {
#  if defined __NR_gettid && __NR_gettid >= 0
        return (pid_t) syscall(__NR_gettid);
#  else
#    error "__NR_gettid not defined"
#  endif
}

#  define gettid missing_gettid
#endif

/* ======================================================================= */

#if defined(__x86_64__)
#  define systemd_NR_name_to_handle_at systemd_SC_arch_bias(303)
#elif defined(__i386__)
#  define systemd_NR_name_to_handle_at 341
#elif defined(__arm__)
#  define systemd_NR_name_to_handle_at 370
#elif defined __aarch64__
#  define systemd_NR_name_to_handle_at 264
#elif defined(__powerpc__)
#  define systemd_NR_name_to_handle_at 345
#elif defined __s390__ || defined __s390x__
#  define systemd_NR_name_to_handle_at 335
#elif defined(__arc__)
#  define systemd_NR_name_to_handle_at 264
#elif defined _MIPS_SIM
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#    define systemd_NR_name_to_handle_at systemd_SC_arch_bias(339)
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#    define systemd_NR_name_to_handle_at systemd_SC_arch_bias(303)
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#    define systemd_NR_name_to_handle_at systemd_SC_arch_bias(298)
#  endif
#else
#  warning "name_to_handle_at number is not defined"
#endif

/* may be (invalid) negative number due to libseccomp, see PR 13319 */
#if defined __NR_name_to_handle_at && __NR_name_to_handle_at >= 0
#  if defined systemd_NR_name_to_handle_at
assert_cc(__NR_name_to_handle_at == systemd_NR_name_to_handle_at);
#  endif
#else
#  if defined __NR_name_to_handle_at
#    undef __NR_name_to_handle_at
#  endif
#  if defined systemd_NR_name_to_handle_at
#    define __NR_name_to_handle_at systemd_NR_name_to_handle_at
#  endif
#endif

#if !HAVE_NAME_TO_HANDLE_AT
struct file_handle {
        unsigned int handle_bytes;
        int handle_type;
        unsigned char f_handle[0];
};

static inline int missing_name_to_handle_at(int fd, const char *name, struct file_handle *handle, int *mnt_id, int flags) {
#  ifdef __NR_name_to_handle_at
        return syscall(__NR_name_to_handle_at, fd, name, handle, mnt_id, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define name_to_handle_at missing_name_to_handle_at
#endif

/* ======================================================================= */

#if defined __aarch64__
#  define systemd_NR_setns 268
#elif defined __arm__
#  define systemd_NR_setns 375
#elif defined(__x86_64__)
#  define systemd_NR_setns systemd_SC_arch_bias(308)
#elif defined(__i386__)
#  define systemd_NR_setns 346
#elif defined(__powerpc__)
#  define systemd_NR_setns 350
#elif defined __s390__ || defined __s390x__
#  define systemd_NR_setns 339
#elif defined(__arc__)
#  define systemd_NR_setns 268
#elif defined _MIPS_SIM
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#    define systemd_NR_setns systemd_SC_arch_bias(344)
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#    define systemd_NR_setns systemd_SC_arch_bias(308)
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#    define systemd_NR_setns systemd_SC_arch_bias(303)
#  endif
#else
#  warning "setns() syscall number unknown for your architecture"
#endif

/* may be (invalid) negative number due to libseccomp, see PR 13319 */
#if defined __NR_setns && __NR_setns >= 0
#  if defined systemd_NR_setns
assert_cc(__NR_setns == systemd_NR_setns);
#  endif
#else
#  if defined __NR_setns
#    undef __NR_setns
#  endif
#  if defined systemd_NR_setns
#    define __NR_setns systemd_NR_setns
#  endif
#endif

#if !HAVE_SETNS
static inline int missing_setns(int fd, int nstype) {
#  ifdef __NR_setns
        return syscall(__NR_setns, fd, nstype);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define setns missing_setns
#endif

/* ======================================================================= */

static inline pid_t raw_getpid(void) {
#if defined(__alpha__)
        return (pid_t) syscall(__NR_getxpid);
#else
        return (pid_t) syscall(__NR_getpid);
#endif
}

/* ======================================================================= */

#if defined __x86_64__
#  define systemd_NR_renameat2 systemd_SC_arch_bias(316)
#elif defined __arm__
#  define systemd_NR_renameat2 382
#elif defined __aarch64__
#  define systemd_NR_renameat2 276
#elif defined _MIPS_SIM
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#    define systemd_NR_renameat2 systemd_SC_arch_bias(351)
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#    define systemd_NR_renameat2 systemd_SC_arch_bias(315)
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#    define systemd_NR_renameat2 systemd_SC_arch_bias(311)
#  endif
#elif defined __i386__
#  define systemd_NR_renameat2 353
#elif defined __powerpc64__
#  define systemd_NR_renameat2 357
#elif defined __s390__ || defined __s390x__
#  define systemd_NR_renameat2 347
#elif defined __arc__
#  define systemd_NR_renameat2 276
#else
#  warning "renameat2() syscall number unknown for your architecture"
#endif

/* may be (invalid) negative number due to libseccomp, see PR 13319 */
#if defined __NR_renameat2 && __NR_renameat2 >= 0
#  if defined systemd_NR_renameat2
assert_cc(__NR_renameat2 == systemd_NR_renameat2);
#  endif
#else
#  if defined __NR_renameat2
#    undef __NR_renameat2
#  endif
#  if defined systemd_NR_renameat2
#    define __NR_renameat2 systemd_NR_renameat2
#  endif
#endif

#if !HAVE_RENAMEAT2
static inline int missing_renameat2(int oldfd, const char *oldname, int newfd, const char *newname, unsigned flags) {
#  ifdef __NR_renameat2
        return syscall(__NR_renameat2, oldfd, oldname, newfd, newname, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define renameat2 missing_renameat2
#endif

/* ======================================================================= */

#if !HAVE_KCMP
static inline int missing_kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2) {
#  if defined __NR_kcmp && __NR_kcmp >= 0
        return syscall(__NR_kcmp, pid1, pid2, type, idx1, idx2);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define kcmp missing_kcmp
#endif

/* ======================================================================= */

#if !HAVE_KEYCTL
static inline long missing_keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
#  if defined __NR_keyctl && __NR_keyctl >= 0
        return syscall(__NR_keyctl, cmd, arg2, arg3, arg4, arg5);
#  else
        errno = ENOSYS;
        return -1;
#  endif

#  define keyctl missing_keyctl
}

static inline key_serial_t missing_add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t ringid) {
#  if defined __NR_add_key && __NR_add_key >= 0
        return syscall(__NR_add_key, type, description, payload, plen, ringid);
#  else
        errno = ENOSYS;
        return -1;
#  endif

#  define add_key missing_add_key
}

static inline key_serial_t missing_request_key(const char *type, const char *description, const char * callout_info, key_serial_t destringid) {
#  if defined __NR_request_key && __NR_request_key >= 0
        return syscall(__NR_request_key, type, description, callout_info, destringid);
#  else
        errno = ENOSYS;
        return -1;
#  endif

#  define request_key missing_request_key
}
#endif

/* ======================================================================= */

#if defined(__x86_64__)
#  define systemd_NR_copy_file_range systemd_SC_arch_bias(326)
#elif defined(__i386__)
#  define systemd_NR_copy_file_range 377
#elif defined __s390__
#  define systemd_NR_copy_file_range 375
#elif defined __arm__
#  define systemd_NR_copy_file_range 391
#elif defined __aarch64__
#  define systemd_NR_copy_file_range 285
#elif defined __powerpc__
#  define systemd_NR_copy_file_range 379
#elif defined __arc__
#  define systemd_NR_copy_file_range 285
#elif defined _MIPS_SIM
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#    define systemd_NR_copy_file_range systemd_SC_arch_bias(360)
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#    define systemd_NR_copy_file_range systemd_SC_arch_bias(324)
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#    define systemd_NR_copy_file_range systemd_SC_arch_bias(320)
#  endif
#else
#  warning "copy_file_range() syscall number unknown for your architecture"
#endif

/* may be (invalid) negative number due to libseccomp, see PR 13319 */
#if defined __NR_copy_file_range && __NR_copy_file_range >= 0
#  if defined systemd_NR_copy_file_range
assert_cc(__NR_copy_file_range == systemd_NR_copy_file_range);
#  endif
#else
#  if defined __NR_copy_file_range
#    undef __NR_copy_file_range
#  endif
#  if defined systemd_NR_copy_file_range
#    define __NR_copy_file_range systemd_NR_copy_file_range
#  endif
#endif

#if !HAVE_COPY_FILE_RANGE
static inline ssize_t missing_copy_file_range(int fd_in, loff_t *off_in,
                                              int fd_out, loff_t *off_out,
                                              size_t len,
                                              unsigned int flags) {
#  ifdef __NR_copy_file_range
        return syscall(__NR_copy_file_range, fd_in, off_in, fd_out, off_out, len, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define copy_file_range missing_copy_file_range
#endif

/* ======================================================================= */

#if defined __i386__
#  define systemd_NR_bpf 357
#elif defined __x86_64__
#  define systemd_NR_bpf systemd_SC_arch_bias(321)
#elif defined __aarch64__
#  define systemd_NR_bpf 280
#elif defined __arm__
#  define systemd_NR_bpf 386
#elif defined(__powerpc__)
#  define systemd_NR_bpf 361
#elif defined __sparc__
#  define systemd_NR_bpf 349
#elif defined __s390__
#  define systemd_NR_bpf 351
#elif defined __tilegx__
#  define systemd_NR_bpf 280
#elif defined _MIPS_SIM
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#    define systemd_NR_bpf systemd_SC_arch_bias(355)
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#    define systemd_NR_bpf systemd_SC_arch_bias(319)
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#    define systemd_NR_bpf systemd_SC_arch_bias(315)
#  endif
#else
#  warning "bpf() syscall number unknown for your architecture"
#endif

/* may be (invalid) negative number due to libseccomp, see PR 13319 */
#if defined __NR_bpf && __NR_bpf >= 0
#  if defined systemd_NR_bpf
assert_cc(__NR_bpf == systemd_NR_bpf);
#  endif
#else
#  if defined __NR_bpf
#    undef __NR_bpf
#  endif
#  if defined systemd_NR_bpf
#    define __NR_bpf systemd_NR_bpf
#  endif
#endif

#if !HAVE_BPF
union bpf_attr;

static inline int missing_bpf(int cmd, union bpf_attr *attr, size_t size) {
#ifdef __NR_bpf
        return (int) syscall(__NR_bpf, cmd, attr, size);
#else
        errno = ENOSYS;
        return -1;
#endif
}

#  define bpf missing_bpf
#endif

/* ======================================================================= */

#ifndef __IGNORE_pkey_mprotect
#  if defined __i386__
#    define systemd_NR_pkey_mprotect 380
#  elif defined __x86_64__
#    define systemd_NR_pkey_mprotect systemd_SC_arch_bias(329)
#  elif defined __aarch64__
#    define systemd_NR_pkey_mprotect 288
#  elif defined __arm__
#    define systemd_NR_pkey_mprotect 394
#  elif defined __powerpc__
#    define systemd_NR_pkey_mprotect 386
#  elif defined __s390__
#    define systemd_NR_pkey_mprotect 384
#  elif defined _MIPS_SIM
#    if _MIPS_SIM == _MIPS_SIM_ABI32
#      define systemd_NR_pkey_mprotect systemd_SC_arch_bias(363)
#    elif _MIPS_SIM == _MIPS_SIM_NABI32
#      define systemd_NR_pkey_mprotect systemd_SC_arch_bias(327)
#    elif _MIPS_SIM == _MIPS_SIM_ABI64
#      define systemd_NR_pkey_mprotect systemd_SC_arch_bias(323)
#    endif
#  else
#    warning "pkey_mprotect() syscall number unknown for your architecture"
#  endif

/* may be (invalid) negative number due to libseccomp, see PR 13319 */
#  if defined __NR_pkey_mprotect && __NR_pkey_mprotect >= 0
#    if defined systemd_NR_pkey_mprotect
assert_cc(__NR_pkey_mprotect == systemd_NR_pkey_mprotect);
#    endif
#  else
#    if defined __NR_pkey_mprotect
#      undef __NR_pkey_mprotect
#    endif
#    if defined systemd_NR_pkey_mprotect
#      define __NR_pkey_mprotect systemd_NR_pkey_mprotect
#    endif
#  endif
#endif

/* ======================================================================= */

#if defined __aarch64__
#  define systemd_NR_statx 291
#elif defined __arm__
#  define systemd_NR_statx 397
#elif defined __alpha__
#  define systemd_NR_statx 522
#elif defined __i386__ || defined __powerpc64__
#  define systemd_NR_statx 383
#elif defined __s390__ || defined __s390x__
#  define systemd_NR_statx 379
#elif defined __sparc__
#  define systemd_NR_statx 360
#elif defined __x86_64__
#  define systemd_NR_statx systemd_SC_arch_bias(332)
#elif defined _MIPS_SIM
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#    define systemd_NR_statx systemd_SC_arch_bias(366)
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#    define systemd_NR_statx systemd_SC_arch_bias(330)
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#    define systemd_NR_statx systemd_SC_arch_bias(326)
#  endif
#else
#  warning "statx() syscall number unknown for your architecture"
#endif

/* may be (invalid) negative number due to libseccomp, see PR 13319 */
#if defined __NR_statx && __NR_statx >= 0
#  if defined systemd_NR_statx
assert_cc(__NR_statx == systemd_NR_statx);
#  endif
#else
#  if defined __NR_statx
#    undef __NR_statx
#  endif
#  if defined systemd_NR_statx
#    define __NR_statx systemd_NR_statx
#  endif
#endif

#if !HAVE_STATX
struct statx;

static inline ssize_t missing_statx(int dfd, const char *filename, unsigned flags, unsigned int mask, struct statx *buffer) {
#  ifdef __NR_statx
        return syscall(__NR_statx, dfd, filename, flags, mask, buffer);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}
#endif

/* This typedef is supposed to be always defined. */
typedef struct statx struct_statx;

#if !HAVE_STATX
#  define statx(dfd, filename, flags, mask, buffer) missing_statx(dfd, filename, flags, mask, buffer)
#endif

/* ======================================================================= */

#if !HAVE_SET_MEMPOLICY
enum {
        MPOL_DEFAULT,
        MPOL_PREFERRED,
        MPOL_BIND,
        MPOL_INTERLEAVE,
        MPOL_LOCAL,
};

static inline long missing_set_mempolicy(int mode, const unsigned long *nodemask,
                           unsigned long maxnode) {
        long i;
#  if defined __NR_set_mempolicy && __NR_set_mempolicy >= 0
        i = syscall(__NR_set_mempolicy, mode, nodemask, maxnode);
#  else
        errno = ENOSYS;
        i = -1;
#  endif
        return i;
}

#  define set_mempolicy missing_set_mempolicy
#endif

#if !HAVE_GET_MEMPOLICY
static inline long missing_get_mempolicy(int *mode, unsigned long *nodemask,
                           unsigned long maxnode, void *addr,
                           unsigned long flags) {
        long i;
#  if defined __NR_get_mempolicy && __NR_get_mempolicy >= 0
        i = syscall(__NR_get_mempolicy, mode, nodemask, maxnode, addr, flags);
#  else
        errno = ENOSYS;
        i = -1;
#  endif
        return i;
}

#  define get_mempolicy missing_get_mempolicy
#endif

/* ======================================================================= */

/* should be always defined, see kernel 39036cd2727395c3369b1051005da74059a85317 */
#define systemd_NR_pidfd_send_signal systemd_SC_arch_bias(424)

/* may be (invalid) negative number due to libseccomp, see PR 13319 */
#if defined __NR_pidfd_send_signal && __NR_pidfd_send_signal >= 0
#  if defined systemd_NR_pidfd_send_signal
assert_cc(__NR_pidfd_send_signal == systemd_NR_pidfd_send_signal);
#  endif
#else
#  if defined __NR_pidfd_send_signal
#    undef __NR_pidfd_send_signal
#  endif
#  define __NR_pidfd_send_signal systemd_NR_pidfd_send_signal
#endif

#if !HAVE_PIDFD_SEND_SIGNAL
static inline int missing_pidfd_send_signal(int fd, int sig, siginfo_t *info, unsigned flags) {
#  ifdef __NR_pidfd_send_signal
        return syscall(__NR_pidfd_send_signal, fd, sig, info, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define pidfd_send_signal missing_pidfd_send_signal
#endif

/* should be always defined, see kernel 7615d9e1780e26e0178c93c55b73309a5dc093d7 */
#define systemd_NR_pidfd_open systemd_SC_arch_bias(434)

/* may be (invalid) negative number due to libseccomp, see PR 13319 */
#if defined __NR_pidfd_open && __NR_pidfd_open >= 0
#  if defined systemd_NR_pidfd_open
assert_cc(__NR_pidfd_open == systemd_NR_pidfd_open);
#  endif
#else
#  if defined __NR_pidfd_open
#    undef __NR_pidfd_open
#  endif
#  define __NR_pidfd_open systemd_NR_pidfd_open
#endif

#if !HAVE_PIDFD_OPEN
static inline int missing_pidfd_open(pid_t pid, unsigned flags) {
#  ifdef __NR_pidfd_open
        return syscall(__NR_pidfd_open, pid, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define pidfd_open missing_pidfd_open
#endif

/* ======================================================================= */

#if !HAVE_RT_SIGQUEUEINFO
static inline int missing_rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *info) {
#  if defined __NR_rt_sigqueueinfo && __NR_rt_sigqueueinfo >= 0
        return syscall(__NR_rt_sigqueueinfo, tgid, sig, info);
#  else
#    error "__NR_rt_sigqueueinfo not defined"
#  endif
}

#  define rt_sigqueueinfo missing_rt_sigqueueinfo
#endif

/* ======================================================================= */

#define systemd_NR_close_range systemd_SC_arch_bias(436)

/* may be (invalid) negative number due to libseccomp, see PR 13319 */
#if defined __NR_close_range && __NR_close_range >= 0
#  if defined systemd_NR_close_range
assert_cc(__NR_close_range == systemd_NR_close_range);
#  endif
#else
#  if defined __NR_close_range
#    undef __NR_close_range
#  endif
#  if defined systemd_NR_close_range
#    define __NR_close_range systemd_NR_close_range
#  endif
#endif

#if !HAVE_CLOSE_RANGE
static inline int missing_close_range(int first_fd, int end_fd, unsigned flags) {
#  ifdef __NR_close_range
        /* Kernel-side the syscall expects fds as unsigned integers (just like close() actually), while
         * userspace exclusively uses signed integers for fds. We don't know just yet how glibc is going to
         * wrap this syscall, but let's assume it's going to be similar to what they do for close(),
         * i.e. make the same unsigned → signed type change from the raw kernel syscall compared to the
         * userspace wrapper. There's only one caveat for this: unlike for close() there's the special
         * UINT_MAX fd value for the 'end_fd' argument. Let's safely map that to -1 here. And let's refuse
         * any other negative values. */
        if ((first_fd < 0) || (end_fd < 0 && end_fd != -1)) {
                errno = -EBADF;
                return -1;
        }

        return syscall(__NR_close_range,
                       (unsigned) first_fd,
                       end_fd == -1 ? UINT_MAX : (unsigned) end_fd, /* Of course, the compiler should figure out that this is the identity mapping IRL */
                       flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define close_range missing_close_range
#endif
