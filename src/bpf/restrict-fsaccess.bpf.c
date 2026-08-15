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
 *
 * On kernels providing the bpf_real_data_inode() kfunc (v7.2+), files on
 * union filesystems (overlayfs) are resolved to the layer hosting their
 * data, so execution from overlays stacked on signed dm-verity devices
 * works. Without the kfunc such files are denied, as before.
 */

/* If offsetof() is implemented via __builtin_offset() then it doesn't work on current compilers, since the
 * built-ins do not understand CO-RE. Let's undefine any such macros here, to force bpf_helpers.h to define
 * its own definitions for this. (In new versions it will do so automatically, but at least in libbpf 1.1.0
 * it does not.) */
#undef offsetof
#undef container_of

#include "vmlinux.h"

#include <errno.h>                      /* IWYU pragma: keep */
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PROT_EXEC          0x4
#define VM_EXEC            0x00000004
#define PTRACE_MODE_ATTACH 0x02

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

/* ---- Self-protection guard globals (set by PID1 after attach) ----
 *
 * While all IDs are 0 (the .bss default), the guard is inactive — no real BPF
 * object has ID 0, so no comparisons match. PID1 populates these after
 * attaching all programs. */
volatile __u32 protected_map_id_verity;
volatile __u32 protected_map_id_bss;

/* Must equal _RESTRICT_FILESYSTEM_ACCESS_LINK_MAX in bpf-restrict-fsaccess.h — update when adding programs */
#define NUM_PROTECTED_OBJS 9 /* 5 enforcement + 4 guard (bpf, bpf_map, bpf_prog, ptrace) */
volatile __u32 protected_prog_ids[NUM_PROTECTED_OBJS];
volatile __u32 protected_link_ids[NUM_PROTECTED_OBJS];

/* ---- Integrity tracking hooks ---- */

/* Preferred version: reads both value and size for defense-in-depth.
 * Requires kernel v6.16+ or the backport of 1271a40eeafa ("bpf: Allow
 * access to const void pointer arguments in tracing programs").
 * On older kernels btf_ctx_access() rejects loads from const void *
 * arguments because it fails to skip the CONST modifier when checking
 * for void pointers. prepare_restrict_fsaccess_bpf() tries this version
 * first and falls back to the _compat variant below if loading fails. */
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

/* Compatibility version for kernels without 1271a40eeafa: does not
 * read the const void *value argument (ctx[2]) to avoid the verifier
 * rejection. Reads size (ctx[3]) directly from the raw context instead.
 * This is safe because dm-verity guarantees value!=NULL iff size>0. */
#define BDEV_SETINTEGRITY_SIZE_CTX_IDX 3 /* bdev_setintegrity(bdev, type, value, size) */
SEC("lsm/bdev_setintegrity")
int BPF_PROG(restrict_fsaccess_bdev_setintegrity_compat, struct block_device *bdev,
             enum lsm_integrity_type type)
{
        if (type == LSM_INT_DMVERITY_SIG_VALID) {
                __u32 dev = bdev->bd_dev;
                __u8 valid = ctx[BDEV_SETINTEGRITY_SIZE_CTX_IDX] > 0;
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

/* Set by PID1 between skeleton open and load (.rodata is read-only and
 * frozen after load): true when the kernel provides the
 * bpf_real_data_inode() kfunc (v7.2+). The verifier constant-folds the flag
 * and removes the (then unresolvable) kfunc call on kernels without it. */
const volatile bool have_real_data_inode = false;

/* Returns the inode hosting a regular file's data: on union filesystems
 * (overlayfs) the backing layer's inode rather than the union inode.
 * Sleepable, hence only callable from lsm.s/ programs. Weak so that the
 * object still loads on kernels that lack the kfunc. */
extern struct inode *bpf_real_data_inode(struct file *file) __weak __ksym;

/* Check whether a file's data lives on a trusted device.
 * Returns 0 (allow) or -EPERM (deny).
 *
 * mnt_dev is the device of the filesystem the file was opened on, data_dev
 * the device of the filesystem hosting its data; they differ only on union
 * filesystems. The initramfs window compares mnt_dev: whether a file is on
 * the initramfs is a question about the mounted filesystem — userspace
 * recorded the mount's s_dev, which for a union-mount initrd is the union's
 * anonymous device, not any backing device. The verity map is keyed by
 * block device, so it is compared against data_dev. */
static __always_inline int check_trusted_dev(__u32 mnt_dev, __u32 data_dev)
{
        __u8 *sig_valid;

        /* Check initramfs trust (active only during early boot) */
        if (initramfs_s_dev != 0 && mnt_dev == initramfs_s_dev)
                return 0;

        /* Check verity device map */
        sig_valid = bpf_map_lookup_elem(&verity_devices, &data_dev);
        if (sig_valid && *sig_valid)
                return 0;

        return -EPERM;
}

/* Check a file as the user sees it, resolving union filesystems to the
 * layer hosting the data. May sleep — lsm.s/ programs only.
 *
 * The kfunc follows the data: a metacopy upper on an untrusted layer can
 * still own the metadata (mode, ownership, setuid) of a binary whose data —
 * and hence verdict — comes from the trusted lower device. */
static __always_inline int check_trusted_file(struct file *file)
{
        struct inode *inode;
        __u32 mnt_dev, data_dev;

        BPF_CORE_READ_INTO(&mnt_dev, file, f_inode, i_sb, s_dev);

        /* No kfunc: the mount device stands in, denying union filesystems. */
        data_dev = mnt_dev;

        if (have_real_data_inode) {
                inode = bpf_real_data_inode(file);
                if (!inode)
                        return -EPERM;

                BPF_CORE_READ_INTO(&data_dev, inode, i_sb, s_dev);
        }

        return check_trusted_dev(mnt_dev, data_dev);
}

/* Check vma->vm_file. By the time a vma exists, stacking filesystems have
 * already installed the backing file into it (ovl_mmap() →
 * backing_file_mmap() → vma_set_file()), so no union resolution is needed —
 * and unlike re-resolving, vm_file names the file the pages actually come
 * from even after a later copy-up. */
static __always_inline int check_trusted_vm_file(struct file *file)
{
        __u32 s_dev;

        BPF_CORE_READ_INTO(&s_dev, file, f_inode, i_sb, s_dev);

        return check_trusted_dev(s_dev, s_dev);
}

/* ---- Enforcement hooks ---- */

SEC("lsm.s/bprm_check_security")
int BPF_PROG(restrict_fsaccess_bprm_check, struct linux_binprm *bprm)
{
        /* Direct dereference (CO-RE-relocated via vmlinux.h's
         * preserve_access_index) instead of bpf_probe_read(): only direct
         * loads keep the verifier's trusted-pointer tracking. */
        return check_trusted_file(bprm->file);
}

/* Covers more than plain mmap(): binfmt_elf maps the PT_INTERP interpreter
 * via vm_mmap(), so ld.so is only ever checked here, not by
 * bprm_check_security. */
SEC("lsm.s/mmap_file")
int BPF_PROG(restrict_fsaccess_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
{
        /* Only enforce on executable mappings */
        if (!(prot & PROT_EXEC))
                return 0;

        /* Anonymous executable mapping — no file backing, deny. The hook's
         * file argument is __nullable since kernel v7.0 (94e948b7e684), so the
         * verifier types it trusted-or-NULL and this check is mandatory:
         * without it, handing file to bpf_real_data_inode() fails to load.
         * Older kernels lack the annotation and drop the branch, but they lack
         * the kfunc too, so it never sees a NULL file. */
        if (!file)
                return -EPERM;

        return check_trusted_file(file);
}

/* Deliberately not sleepable: this hook runs under mmap_write_lock, where
 * sleeping in d_real()/verity I/O could invert the documented i_rwsem →
 * mmap_lock order (and bpf_lsm_file_mprotect is not in the kernel's
 * sleepable_lsm_hooks set anyway). No resolution is needed here, see
 * check_trusted_vm_file(). */
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

        /* Anonymous executable mapping — no file backing, deny. Direct
         * dereference, see restrict_fsaccess_bprm_check(). vm_file is in the
         * verifier's BTF_TYPE_SAFE_TRUSTED_OR_NULL list, so this check is live
         * and required. */
        file = vma->vm_file;
        if (!file)
                return -EPERM;

        return check_trusted_vm_file(file);
}

/* ---- PID1 ptrace protection ----
 *
 * Blocks PTRACE_MODE_ATTACH access to PID1 from any other process. This
 * prevents ptrace(PTRACE_ATTACH), /proc/1/mem, process_vm_readv(), and
 * pidfd_getfd() from extracting sensitive state from PID1's address space.
 *
 * PTRACE_MODE_READ is allowed — monitoring tools and systemctl need
 * /proc/1/status, /proc/1/fd/, /proc/1/ns/ *, etc.
 *
 * PID1 accessing itself is allowed. */

SEC("lsm/ptrace_access_check")
int BPF_PROG(restrict_fsaccess_ptrace_guard, struct task_struct *child,
             unsigned int mode)
{
        /* We only care about PID 1 and its threads (There are none but still.). */
        if (child->tgid != 1)
                return 0;

        /* We only care about dangerous operations. */
        if (!(mode & PTRACE_MODE_ATTACH))
                return 0;

        /* PID1 (any thread) accessing itself is allowed. */
        if ((bpf_get_current_pid_tgid() >> 32) == 1)
                return 0;

        return -EPERM;
}

/* ---- Self-protection guard ----
 *
 * Three hooks protect our BPF objects from non-PID1 processes:
 *
 *   lsm/bpf_map  — fires inside bpf_map_new_fd(), the chokepoint for ALL
 *                   code paths that produce a map FD (BPF_MAP_GET_FD_BY_ID,
 *                   BPF_OBJ_GET, BPF_MAP_CREATE). Blocks the primary attack:
 *                   obtaining an FD to verity_devices to inject fake trusted
 *                   devices via BPF_MAP_UPDATE_ELEM.
 *
 *   lsm/bpf_prog — fires inside bpf_prog_new_fd(), same chokepoint coverage
 *                   for programs. Defense-in-depth.
 *
 *   lsm/bpf      — handles BPF_LINK_GET_FD_BY_ID only. There is no
 *                   security_bpf_link() hook in the kernel, so link
 *                   protection uses the command-level bpf() hook. This is
 *                   sufficient: we don't pin links in production, so
 *                   BPF_OBJ_GET is not an attack vector for links. */

SEC("lsm/bpf_map")
int BPF_PROG(restrict_fsaccess_bpf_map_guard, struct bpf_map *map,
             unsigned int fmode)
{
        __u32 id;

        if ((bpf_get_current_pid_tgid() >> 32) == 1)
                return 0;

        id = map->id;
        if (id != 0 && (id == protected_map_id_verity ||
                        id == protected_map_id_bss))
                return -EPERM;

        return 0;
}

SEC("lsm/bpf_prog")
int BPF_PROG(restrict_fsaccess_bpf_prog_guard, struct bpf_prog *prog)
{
        __u32 id;

        if ((bpf_get_current_pid_tgid() >> 32) == 1)
                return 0;

        id = BPF_CORE_READ(prog, aux, id);
        if (id == 0)
                return 0;

        for (int i = 0; i < NUM_PROTECTED_OBJS; i++)
                if (id == protected_prog_ids[i])
                        return -EPERM;

        return 0;
}

SEC("lsm/bpf")
int BPF_PROG(restrict_fsaccess_bpf_guard, int cmd, union bpf_attr *attr,
             unsigned int size)
{
        __u32 id;

        if ((bpf_get_current_pid_tgid() >> 32) == 1)
                return 0;

        if (cmd != BPF_LINK_GET_FD_BY_ID)
                return 0;

        /* link_id/map_id/prog_id share the same offset in the bpf_attr union */
        id = attr->link_id;
        if (id == 0)
                return 0;

        for (int i = 0; i < NUM_PROTECTED_OBJS; i++)
                if (id == protected_link_ids[i])
                        return -EPERM;

        return 0;
}

static const char _license[] SEC("license") = "GPL";
