/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

/* Trusted Execution BPF LSM program.
 *
 * Enforces that only binaries from signed dm-verity block devices (or the
 * initramfs during early boot) can be executed.
 *
 * Architecture:
 *   - bdev_setintegrity hook:  self-populates a map of trusted devices when
 *                              dm-verity signals signature validity
 *   - bdev_free_security hook: removes devices from the map on teardown
 *   - bprm_check_security:    blocks execve() from untrusted sources
 *   - mmap_file:              blocks PROT_EXEC mmap from untrusted sources
 *   - file_mprotect:          blocks W->X transitions from untrusted sources
 */

/* offsetof/container_of from <linux/stddef.h> (pulled in by vmlinux.h) clash
 * with libbpf's CO-RE-aware versions. Same dance as userns-restrict.bpf.c. */
#undef offsetof
#undef container_of

#include "vmlinux.h"

#include <errno.h>                  /* IWYU pragma: keep */
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Kernel macros, not BTF types — vmlinux.h doesn't carry CPP macros. */
#define PROT_EXEC 0x4
#define VM_EXEC   0x00000004

/* ---- Maps ---- */

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 0);  /* placeholder */
        __type(key, __u32);     /* dev_t from bdev->bd_dev */
        __type(value, __u8);    /* 1 = signature valid */
} verity_devices SEC(".maps");

/* ---- Globals (set by PID1 via skeleton) ---- */

/* Device number of the initramfs superblock. PID1 sets this at load time and
 * clears it (to 0) after switch_root. A value of 0 means "no initramfs trust
 * — the window is closed." */
volatile __u32 initramfs_s_dev;

/* ---- Integrity tracking hooks ---- */

SEC("lsm/bdev_setintegrity")
int BPF_PROG(restrict_fsaccess_bdev_setintegrity, struct block_device *bdev,
             enum lsm_integrity_type type, const void *value, __u64 size)
{
        if (type == LSM_INT_DMVERITY_SIG_VALID) {
                __u32 dev = bdev->bd_dev;
                __u8 valid = value && size > 0;
                bpf_map_update_elem(&verity_devices, &dev, &valid, BPF_ANY);
        }

        return 0;
}

SEC("lsm/bdev_free_security")
void BPF_PROG(restrict_fsaccess_bdev_free, struct block_device *bdev)
{
        __u32 dev = bdev->bd_dev;
        bpf_map_delete_elem(&verity_devices, &dev);
}

/* ---- Enforcement helpers ---- */

/* Check whether a file is from a trusted source.
 * Returns 0 (allow) or -EPERM (deny). */
static __always_inline int check_trusted_file(struct file *file)
{
        __u32 s_dev;
        __u8 *sig_valid;

        BPF_CORE_READ_INTO(&s_dev, file, f_inode, i_sb, s_dev);

        /* Check initramfs trust (active only during early boot) */
        if (initramfs_s_dev != 0 && s_dev == initramfs_s_dev)
                return 0;

        /* Check verity device map */
        sig_valid = bpf_map_lookup_elem(&verity_devices, &s_dev);
        if (sig_valid && *sig_valid)
                return 0;

        return -EPERM;
}

/* ---- Enforcement hooks ---- */

SEC("lsm/bprm_check_security")
int BPF_PROG(restrict_fsaccess_bprm_check, struct linux_binprm *bprm)
{
        struct file *file;

        BPF_CORE_READ_INTO(&file, bprm, file);
        return check_trusted_file(file);
}

SEC("lsm/mmap_file")
int BPF_PROG(restrict_fsaccess_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
{
        /* Only enforce on executable mappings */
        if (!(prot & PROT_EXEC))
                return 0;

        /* Anonymous executable mapping — no file backing, deny */
        if (!file)
                return -EPERM;

        return check_trusted_file(file);
}

SEC("lsm/file_mprotect")
int BPF_PROG(restrict_fsaccess_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot)
{
        struct file *file;
        unsigned long vm_flags;

        /* Only enforce when adding PROT_EXEC */
        if (!(prot & PROT_EXEC))
                return 0;

        /* If VM_EXEC is already set, the mapping is already executable — this
         * mprotect isn't granting new executable capability, allow */
        BPF_CORE_READ_INTO(&vm_flags, vma, vm_flags);
        if (vm_flags & VM_EXEC)
                return 0;

        /* Anonymous executable mapping — no file backing, deny */
        BPF_CORE_READ_INTO(&file, vma, vm_file);
        if (!file)
                return -EPERM;

        return check_trusted_file(file);
}

static const char _license[] SEC("license") = "GPL";
