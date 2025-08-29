/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>
#include <linux/bpf.h>
#include <linux/bpf_insn.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "bpf-devices.h"
#include "bpf-program.h"
#include "cgroup.h"
#include "devnum-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"

#define PASS_JUMP_OFF 4096

/* Ensure the high level flags we use and the low-level BPF flags exposed on the kernel are defined the same way */
assert_cc((unsigned) BPF_DEVCG_ACC_MKNOD == (unsigned) CGROUP_DEVICE_MKNOD);
assert_cc((unsigned) BPF_DEVCG_ACC_READ  == (unsigned) CGROUP_DEVICE_READ);
assert_cc((unsigned) BPF_DEVCG_ACC_WRITE == (unsigned) CGROUP_DEVICE_WRITE);

static int bpf_prog_allow_list_device(
                BPFProgram *prog,
                char type,
                unsigned major,
                unsigned minor,
                CGroupDevicePermissions p) {

        int r;

        assert(prog);

        log_trace("%s: %c %u:%u %s", __func__, type, major, minor, cgroup_device_permissions_to_string(p));

        if (p <= 0 || p >= _CGROUP_DEVICE_PERMISSIONS_MAX)
                return -EINVAL;

        assert(IN_SET(type, 'b', 'c'));
        const int bpf_type = type == 'c' ? BPF_DEVCG_DEV_CHAR : BPF_DEVCG_DEV_BLOCK;

        const struct bpf_insn insn[] = {
                BPF_MOV32_REG(BPF_REG_1, BPF_REG_3),
                BPF_ALU32_IMM(BPF_AND, BPF_REG_1, p),
                BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 4), /* compare access type */

                BPF_JMP_IMM(BPF_JNE, BPF_REG_2, bpf_type, 3),  /* compare device type */
                BPF_JMP_IMM(BPF_JNE, BPF_REG_4, major, 2),     /* compare major */
                BPF_JMP_IMM(BPF_JNE, BPF_REG_5, minor, 1),     /* compare minor */
                BPF_JMP_A(PASS_JUMP_OFF),                      /* jump to PASS */
        };

        if (p == _CGROUP_DEVICE_PERMISSIONS_ALL)
                r = bpf_program_add_instructions(prog, insn + 3, ELEMENTSOF(insn) - 3);
        else
                r = bpf_program_add_instructions(prog, insn, ELEMENTSOF(insn));
        if (r < 0)
                return log_error_errno(r, "Extending device control BPF program failed: %m");

        return 1; /* return 1 → we did something */
}

static int bpf_prog_allow_list_major(
                BPFProgram *prog,
                char type,
                unsigned major,
                CGroupDevicePermissions p) {

        int r;

        assert(prog);

        log_trace("%s: %c %u:* %s", __func__, type, major, cgroup_device_permissions_to_string(p));

        if (p <= 0 || p >= _CGROUP_DEVICE_PERMISSIONS_MAX)
                return -EINVAL;

        assert(IN_SET(type, 'b', 'c'));
        const int bpf_type = type == 'c' ? BPF_DEVCG_DEV_CHAR : BPF_DEVCG_DEV_BLOCK;

        const struct bpf_insn insn[] = {
                BPF_MOV32_REG(BPF_REG_1, BPF_REG_3),
                BPF_ALU32_IMM(BPF_AND, BPF_REG_1, p),
                BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 3), /* compare access type */

                BPF_JMP_IMM(BPF_JNE, BPF_REG_2, bpf_type, 2),  /* compare device type */
                BPF_JMP_IMM(BPF_JNE, BPF_REG_4, major, 1),     /* compare major */
                BPF_JMP_A(PASS_JUMP_OFF),                      /* jump to PASS */
        };

        if (p == _CGROUP_DEVICE_PERMISSIONS_ALL)
                r = bpf_program_add_instructions(prog, insn + 3, ELEMENTSOF(insn) - 3);
        else
                r = bpf_program_add_instructions(prog, insn, ELEMENTSOF(insn));
        if (r < 0)
                return log_error_errno(r, "Extending device control BPF program failed: %m");

        return 1; /* return 1 → we did something */
}

static int bpf_prog_allow_list_class(
                BPFProgram *prog,
                char type,
                CGroupDevicePermissions p) {

        int r;

        assert(prog);

        log_trace("%s: %c *:* %s", __func__, type, cgroup_device_permissions_to_string(p));

        if (p <= 0 || p >= _CGROUP_DEVICE_PERMISSIONS_MAX)
                return -EINVAL;

        assert(IN_SET(type, 'b', 'c'));
        const int bpf_type = type == 'c' ? BPF_DEVCG_DEV_CHAR : BPF_DEVCG_DEV_BLOCK;

        const struct bpf_insn insn[] = {
                BPF_MOV32_REG(BPF_REG_1, BPF_REG_3),
                BPF_ALU32_IMM(BPF_AND, BPF_REG_1, p),
                BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 2), /* compare access type */

                BPF_JMP_IMM(BPF_JNE, BPF_REG_2, bpf_type, 1), /* compare device type */
                BPF_JMP_A(PASS_JUMP_OFF),                     /* jump to PASS */
        };

        if (p == _CGROUP_DEVICE_PERMISSIONS_ALL)
                r = bpf_program_add_instructions(prog, insn + 3, ELEMENTSOF(insn) - 3);
        else
                r = bpf_program_add_instructions(prog, insn, ELEMENTSOF(insn));
        if (r < 0)
                return log_error_errno(r, "Extending device control BPF program failed: %m");

        return 1; /* return 1 → we did something */
}

int bpf_devices_cgroup_init(
                BPFProgram **ret,
                CGroupDevicePolicy policy,
                bool allow_list) {

        const struct bpf_insn pre_insn[] = {
                /* load device type to r2 */
                BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                            offsetof(struct bpf_cgroup_dev_ctx, access_type)),
                BPF_ALU32_IMM(BPF_AND, BPF_REG_2, 0xFFFF),

                /* load access type to r3 */
                BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
                            offsetof(struct bpf_cgroup_dev_ctx, access_type)),
                BPF_ALU32_IMM(BPF_RSH, BPF_REG_3, 16),

                /* load major number to r4 */
                BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_1,
                            offsetof(struct bpf_cgroup_dev_ctx, major)),

                /* load minor number to r5 */
                BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_1,
                            offsetof(struct bpf_cgroup_dev_ctx, minor)),
        };

        _cleanup_(bpf_program_freep) BPFProgram *prog = NULL;
        int r;

        assert(ret);

        if (policy == CGROUP_DEVICE_POLICY_AUTO && !allow_list) {
                *ret = NULL;
                return 0;
        }

        r = bpf_program_new(BPF_PROG_TYPE_CGROUP_DEVICE, "sd_devices", &prog);
        if (r < 0)
                return log_error_errno(r, "Loading device control BPF program failed: %m");

        if (policy == CGROUP_DEVICE_POLICY_CLOSED || allow_list) {
                r = bpf_program_add_instructions(prog, pre_insn, ELEMENTSOF(pre_insn));
                if (r < 0)
                        return log_error_errno(r, "Extending device control BPF program failed: %m");
        }

        *ret = TAKE_PTR(prog);
        return 1;
}

int bpf_devices_apply_policy(
                BPFProgram **prog,
                CGroupDevicePolicy policy,
                bool allow_list,
                const char *cgroup_path,
                BPFProgram **prog_installed) {

        _cleanup_free_ char *controller_path = NULL;
        int r;

        /* This will assign *prog_installed if everything goes well. */

        assert(prog);
        if (!*prog)
                goto finish;

        const bool deny_everything = policy == CGROUP_DEVICE_POLICY_STRICT && !allow_list;

        const struct bpf_insn post_insn[] = {
                /* return DENY */
                BPF_MOV64_IMM(BPF_REG_0, 0),
                BPF_JMP_A(1),
        };

        const struct bpf_insn exit_insn[] = {
                /* finally return DENY if deny_everything else ALLOW */
                BPF_MOV64_IMM(BPF_REG_0, deny_everything ? 0 : 1),
                BPF_EXIT_INSN()
        };

        if (!deny_everything) {
                r = bpf_program_add_instructions(*prog, post_insn, ELEMENTSOF(post_insn));
                if (r < 0)
                        return log_error_errno(r, "Extending device control BPF program failed: %m");

                /* Fixup PASS_JUMP_OFF jump offsets. */
                for (size_t off = 0; off < (*prog)->n_instructions; off++) {
                        struct bpf_insn *ins = &((*prog)->instructions[off]);

                        if (ins->code == (BPF_JMP | BPF_JA) && ins->off == PASS_JUMP_OFF)
                                ins->off = (*prog)->n_instructions - off - 1;
                }
        }

        r = bpf_program_add_instructions(*prog, exit_insn, ELEMENTSOF(exit_insn));
        if (r < 0)
                return log_error_errno(r, "Extending device control BPF program failed: %m");

        r = cg_get_path(cgroup_path, /* suffix = */ NULL, &controller_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine cgroup path: %m");

        r = bpf_program_cgroup_attach(*prog, BPF_CGROUP_DEVICE, controller_path, BPF_F_ALLOW_MULTI);
        if (r < 0)
                return log_error_errno(r, "Attaching device control BPF program to cgroup %s failed: %m",
                                       empty_to_root(cgroup_path));

 finish:
        /* Unref the old BPF program (which will implicitly detach it) right before attaching the new program. */
        if (prog_installed) {
                bpf_program_free(*prog_installed);
                *prog_installed = TAKE_PTR(*prog);
        }
        return 0;
}

static int allow_list_device_pattern(
                BPFProgram *prog,
                const char *path,
                char type,
                unsigned major,
                unsigned minor,
                CGroupDevicePermissions p) {

        assert(IN_SET(type, 'b', 'c'));

        if (!prog)
                return 0;

        if (major != UINT_MAX && minor != UINT_MAX)
                return bpf_prog_allow_list_device(prog, type, major, minor, p);
        if (major != UINT_MAX)
                return bpf_prog_allow_list_major(prog, type, major, p);

        return bpf_prog_allow_list_class(prog, type, p);
}

int bpf_devices_allow_list_device(
                BPFProgram *prog,
                const char *path,
                const char *node,
                CGroupDevicePermissions p) {

        mode_t mode;
        dev_t rdev;
        int r;

        assert(path);
        assert(p >= 0 && p < _CGROUP_DEVICE_PERMISSIONS_MAX);

        log_trace("%s: %s %s", __func__, node, cgroup_device_permissions_to_string(p));

        /* Some special handling for /dev/block/%u:%u, /dev/char/%u:%u, /run/systemd/inaccessible/chr and
         * /run/systemd/inaccessible/blk paths. Instead of stat()ing these we parse out the major/minor directly. This
         * means clients can use these path without the device node actually around */
        r = device_path_parse_major_minor(node, &mode, &rdev);
        if (r < 0) {
                if (r != -ENODEV)
                        return log_warning_errno(r, "Couldn't parse major/minor from device path '%s': %m", node);

                struct stat st;
                if (stat(node, &st) < 0) {
                        if (errno == ENOENT) {
                                log_debug_errno(errno, "Device '%s' does not exist, skipping.", node);
                                return 0; /* returning 0 means → skipped */
                        }

                        return log_warning_errno(errno, "Couldn't stat device %s: %m", node);
                }

                if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode))
                        return log_warning_errno(SYNTHETIC_ERRNO(ENODEV), "%s is not a device.", node);

                mode = st.st_mode;
                rdev = (dev_t) st.st_rdev;
        }

        return allow_list_device_pattern(prog, path, S_ISCHR(mode) ? 'c' : 'b', major(rdev), minor(rdev), p);
}

int bpf_devices_allow_list_major(
                BPFProgram *prog,
                const char *path,
                const char *name,
                char type,
                CGroupDevicePermissions permissions) {

        unsigned major;
        int r;

        assert(path);
        assert(IN_SET(type, 'b', 'c'));
        assert(permissions >= 0 && permissions < _CGROUP_DEVICE_PERMISSIONS_MAX);

        if (streq(name, "*"))
                /* If the name is a wildcard, then apply this list to all devices of this type */
                return allow_list_device_pattern(prog, path, type, /* major= */ UINT_MAX, /* minor= */ UINT_MAX, permissions);

        if (safe_atou(name, &major) >= 0 && DEVICE_MAJOR_VALID(major))
                /* The name is numeric and suitable as major. In that case, let's take its major, and create
                 * the entry directly. */
                return allow_list_device_pattern(prog, path, type, major, /* minor= */ UINT_MAX, permissions);

        _cleanup_fclose_ FILE *f = NULL;
        bool good = false, any = false;

        f = fopen("/proc/devices", "re");
        if (!f)
                return log_warning_errno(errno, "Cannot open /proc/devices to resolve %s: %m", name);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *w, *p;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_warning_errno(r, "Failed to read /proc/devices: %m");
                if (r == 0)
                        break;

                if (type == 'c' && streq(line, "Character devices:")) {
                        good = true;
                        continue;
                }

                if (type == 'b' && streq(line, "Block devices:")) {
                        good = true;
                        continue;
                }

                if (isempty(line)) {
                        good = false;
                        continue;
                }

                if (!good)
                        continue;

                p = strstrip(line);

                w = strpbrk(p, WHITESPACE);
                if (!w)
                        continue;
                *w = 0;

                r = safe_atou(p, &major);
                if (r < 0)
                        continue;
                if (major <= 0)
                        continue;

                w++;
                w += strspn(w, WHITESPACE);

                if (fnmatch(name, w, 0) != 0)
                        continue;

                if (allow_list_device_pattern(prog, path, type, major, /* minor= */ UINT_MAX, permissions) > 0)
                        any = true;
        }

        if (!any)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Device allow list pattern \"%s\" did not match anything.", name);

        return any;
}

int bpf_devices_allow_list_static(
                BPFProgram *prog,
                const char *path) {

        static const char auto_devices[] =
                "/dev/null\0" "rwm\0"
                "/dev/zero\0" "rwm\0"
                "/dev/full\0" "rwm\0"
                "/dev/random\0" "rwm\0"
                "/dev/urandom\0" "rwm\0"
                "/dev/tty\0" "rwm\0"
                "/dev/ptmx\0" "rwm\0"
                /* Allow /run/systemd/inaccessible/{chr,blk} devices for mapping InaccessiblePaths */
                "/run/systemd/inaccessible/chr\0" "rwm\0"
                "/run/systemd/inaccessible/blk\0" "rwm\0";
        int r = 0, k;

        NULSTR_FOREACH_PAIR(node, acc, auto_devices) {
                k = bpf_devices_allow_list_device(prog, path, node, cgroup_device_permissions_from_string(acc));
                if ((r >= 0 && k < 0) || (r >= 0 && k > 0))
                        r = k;
        }

        /* PTS (/dev/pts) devices may not be duplicated, but accessed */
        k = bpf_devices_allow_list_major(prog, path, "pts", 'c', CGROUP_DEVICE_READ|CGROUP_DEVICE_WRITE);
        if ((r >= 0 && k < 0) || (r >= 0 && k > 0))
                r = k;

        return r;
}
