/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>
#include <linux/bpf_insn.h>

#include "bpf-devices.h"
#include "bpf-program.h"
#include "fd-util.h"
#include "fileio.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"

#define PASS_JUMP_OFF 4096

static int bpf_access_type(const char *acc) {
        int r = 0;

        assert(acc);

        for (; *acc; acc++)
                switch(*acc) {
                case 'r':
                        r |= BPF_DEVCG_ACC_READ;
                        break;
                case 'w':
                        r |= BPF_DEVCG_ACC_WRITE;
                        break;
                case 'm':
                        r |= BPF_DEVCG_ACC_MKNOD;
                        break;
                default:
                        return -EINVAL;
                }

        return r;
}

static int bpf_prog_allow_list_device(
                BPFProgram *prog,
                char type,
                int major,
                int minor,
                const char *acc) {

        int r, access;

        assert(prog);
        assert(acc);

        log_trace("%s: %c %d:%d %s", __func__, type, major, minor, acc);

        access = bpf_access_type(acc);
        if (access <= 0)
                return -EINVAL;

        assert(IN_SET(type, 'b', 'c'));
        const int bpf_type = type == 'c' ? BPF_DEVCG_DEV_CHAR : BPF_DEVCG_DEV_BLOCK;

        const struct bpf_insn insn[] = {
                BPF_MOV32_REG(BPF_REG_1, BPF_REG_3),
                BPF_ALU32_IMM(BPF_AND, BPF_REG_1, access),
                BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 4), /* compare access type */

                BPF_JMP_IMM(BPF_JNE, BPF_REG_2, bpf_type, 3),  /* compare device type */
                BPF_JMP_IMM(BPF_JNE, BPF_REG_4, major, 2),     /* compare major */
                BPF_JMP_IMM(BPF_JNE, BPF_REG_5, minor, 1),     /* compare minor */
                BPF_JMP_A(PASS_JUMP_OFF),                      /* jump to PASS */
        };

        if (FLAGS_SET(access, BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD))
                r = bpf_program_add_instructions(prog, insn + 3, ELEMENTSOF(insn) - 3);
        else
                r = bpf_program_add_instructions(prog, insn, ELEMENTSOF(insn));
        if (r < 0)
                log_error_errno(r, "Extending device control BPF program failed: %m");

        return r;
}

static int bpf_prog_allow_list_major(
                BPFProgram *prog,
                char type,
                int major,
                const char *acc) {

        int r, access;

        assert(prog);
        assert(acc);

        log_trace("%s: %c %d:* %s", __func__, type, major, acc);

        access = bpf_access_type(acc);
        if (access <= 0)
                return -EINVAL;

        assert(IN_SET(type, 'b', 'c'));
        const int bpf_type = type == 'c' ? BPF_DEVCG_DEV_CHAR : BPF_DEVCG_DEV_BLOCK;

        const struct bpf_insn insn[] = {
                BPF_MOV32_REG(BPF_REG_1, BPF_REG_3),
                BPF_ALU32_IMM(BPF_AND, BPF_REG_1, access),
                BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 3), /* compare access type */

                BPF_JMP_IMM(BPF_JNE, BPF_REG_2, bpf_type, 2),  /* compare device type */
                BPF_JMP_IMM(BPF_JNE, BPF_REG_4, major, 1),     /* compare major */
                BPF_JMP_A(PASS_JUMP_OFF),                      /* jump to PASS */
        };

        if (FLAGS_SET(access, BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD))
                r = bpf_program_add_instructions(prog, insn + 3, ELEMENTSOF(insn) - 3);
        else
                r = bpf_program_add_instructions(prog, insn, ELEMENTSOF(insn));
        if (r < 0)
                log_error_errno(r, "Extending device control BPF program failed: %m");

        return r;
}

static int bpf_prog_allow_list_class(
                BPFProgram *prog,
                char type,
                const char *acc) {

        int r, access;

        assert(prog);
        assert(acc);

        log_trace("%s: %c *:* %s", __func__, type, acc);

        access = bpf_access_type(acc);
        if (access <= 0)
                return -EINVAL;

        assert(IN_SET(type, 'b', 'c'));
        const int bpf_type = type == 'c' ? BPF_DEVCG_DEV_CHAR : BPF_DEVCG_DEV_BLOCK;

        const struct bpf_insn insn[] = {
                BPF_MOV32_REG(BPF_REG_1, BPF_REG_3),
                BPF_ALU32_IMM(BPF_AND, BPF_REG_1, access),
                BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 2), /* compare access type */

                BPF_JMP_IMM(BPF_JNE, BPF_REG_2, bpf_type, 1), /* compare device type */
                BPF_JMP_A(PASS_JUMP_OFF),                     /* jump to PASS */
        };

        if (FLAGS_SET(access, BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD))
                r = bpf_program_add_instructions(prog, insn + 3, ELEMENTSOF(insn) - 3);
        else
                r = bpf_program_add_instructions(prog, insn, ELEMENTSOF(insn));
        if (r < 0)
                log_error_errno(r, "Extending device control BPF program failed: %m");

        return r;
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

        _cleanup_(bpf_program_unrefp) BPFProgram *prog = NULL;
        int r;

        assert(ret);

        if (policy == CGROUP_DEVICE_POLICY_AUTO && !allow_list)
                return 0;

        r = bpf_program_new(BPF_PROG_TYPE_CGROUP_DEVICE, &prog);
        if (r < 0)
                return log_error_errno(r, "Loading device control BPF program failed: %m");

        if (policy == CGROUP_DEVICE_POLICY_CLOSED || allow_list) {
                r = bpf_program_add_instructions(prog, pre_insn, ELEMENTSOF(pre_insn));
                if (r < 0)
                        return log_error_errno(r, "Extending device control BPF program failed: %m");
        }

        *ret = TAKE_PTR(prog);

        return 0;
}

int bpf_devices_apply_policy(
                BPFProgram *prog,
                CGroupDevicePolicy policy,
                bool allow_list,
                const char *cgroup_path,
                BPFProgram **prog_installed) {

        _cleanup_free_ char *controller_path = NULL;
        int r;

        /* This will assign *prog_installed if everything goes well. */

        if (!prog)
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
                r = bpf_program_add_instructions(prog, post_insn, ELEMENTSOF(post_insn));
                if (r < 0)
                        return log_error_errno(r, "Extending device control BPF program failed: %m");

                /* Fixup PASS_JUMP_OFF jump offsets. */
                for (size_t off = 0; off < prog->n_instructions; off++) {
                        struct bpf_insn *ins = &prog->instructions[off];

                        if (ins->code == (BPF_JMP | BPF_JA) && ins->off == PASS_JUMP_OFF)
                                ins->off = prog->n_instructions - off - 1;
                }
        }

        r = bpf_program_add_instructions(prog, exit_insn, ELEMENTSOF(exit_insn));
        if (r < 0)
                return log_error_errno(r, "Extending device control BPF program failed: %m");

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, cgroup_path, NULL, &controller_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine cgroup path: %m");

        r = bpf_program_cgroup_attach(prog, BPF_CGROUP_DEVICE, controller_path, BPF_F_ALLOW_MULTI);
        if (r < 0)
                return log_error_errno(r, "Attaching device control BPF program to cgroup %s failed: %m",
                                       empty_to_root(cgroup_path));

 finish:
        /* Unref the old BPF program (which will implicitly detach it) right before attaching the new program. */
        if (prog_installed) {
                bpf_program_unref(*prog_installed);
                *prog_installed = bpf_program_ref(prog);
        }
        return 0;
}

int bpf_devices_supported(void) {
        const struct bpf_insn trivial[] = {
                BPF_MOV64_IMM(BPF_REG_0, 1),
                BPF_EXIT_INSN()
        };

        _cleanup_(bpf_program_unrefp) BPFProgram *program = NULL;
        static int supported = -1;
        int r;

        /* Checks whether BPF device controller is supported. For this, we check five things:
         *
         * a) whether we are privileged
         * b) whether the unified hierarchy is being used
         * c) the BPF implementation in the kernel supports BPF_PROG_TYPE_CGROUP_DEVICE programs, which we require
         */

        if (supported >= 0)
                return supported;

        if (geteuid() != 0) {
                log_debug("Not enough privileges, BPF device control is not supported.");
                return supported = 0;
        }

        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0)
                return log_error_errno(r, "Can't determine whether the unified hierarchy is used: %m");
        if (r == 0) {
                log_debug("Not running with unified cgroups, BPF device control is not supported.");
                return supported = 0;
        }

        r = bpf_program_new(BPF_PROG_TYPE_CGROUP_DEVICE, &program);
        if (r < 0) {
                log_debug_errno(r, "Can't allocate CGROUP DEVICE BPF program, BPF device control is not supported: %m");
                return supported = 0;
        }

        r = bpf_program_add_instructions(program, trivial, ELEMENTSOF(trivial));
        if (r < 0) {
                log_debug_errno(r, "Can't add trivial instructions to CGROUP DEVICE BPF program, BPF device control is not supported: %m");
                return supported = 0;
        }

        r = bpf_program_load_kernel(program, NULL, 0);
        if (r < 0) {
                log_debug_errno(r, "Can't load kernel CGROUP DEVICE BPF program, BPF device control is not supported: %m");
                return supported = 0;
        }

        return supported = 1;
}

static int allow_list_device_pattern(
                BPFProgram *prog,
                const char *path,
                char type,
                const unsigned *maj,
                const unsigned *min,
                const char *acc) {

        assert(IN_SET(type, 'b', 'c'));

        if (cg_all_unified() > 0) {
                if (!prog)
                        return 0;

                if (maj && min)
                        return bpf_prog_allow_list_device(prog, type, *maj, *min, acc);
                else if (maj)
                        return bpf_prog_allow_list_major(prog, type, *maj, acc);
                else
                        return bpf_prog_allow_list_class(prog, type, acc);

        } else {
                char buf[2+DECIMAL_STR_MAX(unsigned)*2+2+4];
                int r;

                if (maj && min)
                        xsprintf(buf, "%c %u:%u %s", type, *maj, *min, acc);
                else if (maj)
                        xsprintf(buf, "%c %u:* %s", type, *maj, acc);
                else
                        xsprintf(buf, "%c *:* %s", type, acc);

                /* Changing the devices list of a populated cgroup might result in EINVAL, hence ignore
                 * EINVAL here. */

                r = cg_set_attribute("devices", path, "devices.allow", buf);
                if (r < 0)
                        log_full_errno(IN_SET(r, -ENOENT, -EROFS, -EINVAL, -EACCES, -EPERM) ? LOG_DEBUG : LOG_WARNING,
                                       r, "Failed to set devices.allow on %s: %m", path);

                return r;
        }
}

int bpf_devices_allow_list_device(
                BPFProgram *prog,
                const char *path,
                const char *node,
                const char *acc) {

        mode_t mode;
        dev_t rdev;
        int r;

        assert(path);
        assert(acc);
        assert(strlen(acc) <= 3);

        log_trace("%s: %s %s", __func__, node, acc);

        /* Some special handling for /dev/block/%u:%u, /dev/char/%u:%u, /run/systemd/inaccessible/chr and
         * /run/systemd/inaccessible/blk paths. Instead of stat()ing these we parse out the major/minor directly. This
         * means clients can use these path without the device node actually around */
        r = device_path_parse_major_minor(node, &mode, &rdev);
        if (r < 0) {
                if (r != -ENODEV)
                        return log_warning_errno(r, "Couldn't parse major/minor from device path '%s': %m", node);

                struct stat st;
                if (stat(node, &st) < 0)
                        return log_warning_errno(errno, "Couldn't stat device %s: %m", node);

                if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode))
                        return log_warning_errno(SYNTHETIC_ERRNO(ENODEV), "%s is not a device.", node);

                mode = st.st_mode;
                rdev = (dev_t) st.st_rdev;
        }

        unsigned maj = major(rdev), min = minor(rdev);
        return allow_list_device_pattern(prog, path, S_ISCHR(mode) ? 'c' : 'b', &maj, &min, acc);
}

int bpf_devices_allow_list_major(
                BPFProgram *prog,
                const char *path,
                const char *name,
                char type,
                const char *acc) {

        unsigned maj;
        int r;

        assert(path);
        assert(acc);
        assert(IN_SET(type, 'b', 'c'));

        if (streq(name, "*"))
                /* If the name is a wildcard, then apply this list to all devices of this type */
                return allow_list_device_pattern(prog, path, type, NULL, NULL, acc);

        if (safe_atou(name, &maj) >= 0 && DEVICE_MAJOR_VALID(maj))
                /* The name is numeric and suitable as major. In that case, let's take its major, and create
                 * the entry directly. */
                return allow_list_device_pattern(prog, path, type, &maj, NULL, acc);

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

                r = safe_atou(p, &maj);
                if (r < 0)
                        continue;
                if (maj <= 0)
                        continue;

                w++;
                w += strspn(w, WHITESPACE);

                if (fnmatch(name, w, 0) != 0)
                        continue;

                any = true;
                (void) allow_list_device_pattern(prog, path, type, &maj, NULL, acc);
        }

        if (!any)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Device allow list pattern \"%s\" did not match anything.", name);

        return 0;
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

        const char *node, *acc;
        NULSTR_FOREACH_PAIR(node, acc, auto_devices) {
                k = bpf_devices_allow_list_device(prog, path, node, acc);
                if (r >= 0 && k < 0)
                        r = k;
        }

        /* PTS (/dev/pts) devices may not be duplicated, but accessed */
        k = bpf_devices_allow_list_major(prog, path, "pts", 'c', "rw");
        if (r >= 0 && k < 0)
                r = k;

        return r;
}
