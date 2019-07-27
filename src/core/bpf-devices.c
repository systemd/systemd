/* SPDX-License-Identifier: LGPL-2.1+ */
#include <linux/bpf_insn.h>

#include "bpf-devices.h"
#include "bpf-program.h"

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

int cgroup_bpf_whitelist_device(BPFProgram *prog, int type, int major, int minor, const char *acc) {
        struct bpf_insn insn[] = {
                BPF_JMP_IMM(BPF_JNE, BPF_REG_2, type, 6), /* compare device type */
                BPF_MOV32_REG(BPF_REG_1, BPF_REG_3), /* calculate access type */
                BPF_ALU32_IMM(BPF_AND, BPF_REG_1, 0),
                BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 3), /* compare access type */
                BPF_JMP_IMM(BPF_JNE, BPF_REG_4, major, 2), /* compare major */
                BPF_JMP_IMM(BPF_JNE, BPF_REG_5, minor, 1), /* compare minor */
                BPF_JMP_A(PASS_JUMP_OFF), /* jump to PASS */
        };
        int r, access;

        assert(prog);
        assert(acc);

        access = bpf_access_type(acc);
        if (access <= 0)
                return -EINVAL;

        insn[2].imm = access;

        r = bpf_program_add_instructions(prog, insn, ELEMENTSOF(insn));
        if (r < 0)
                log_error_errno(r, "Extending device control BPF program failed: %m");

        return r;
}

int cgroup_bpf_whitelist_major(BPFProgram *prog, int type, int major, const char *acc) {
        struct bpf_insn insn[] = {
                BPF_JMP_IMM(BPF_JNE, BPF_REG_2, type, 5), /* compare device type */
                BPF_MOV32_REG(BPF_REG_1, BPF_REG_3), /* calculate access type */
                BPF_ALU32_IMM(BPF_AND, BPF_REG_1, 0),
                BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 2), /* compare access type */
                BPF_JMP_IMM(BPF_JNE, BPF_REG_4, major, 1), /* compare major */
                BPF_JMP_A(PASS_JUMP_OFF), /* jump to PASS */
        };
        int r, access;

        assert(prog);
        assert(acc);

        access = bpf_access_type(acc);
        if (access <= 0)
                return -EINVAL;

        insn[2].imm = access;

        r = bpf_program_add_instructions(prog, insn, ELEMENTSOF(insn));
        if (r < 0)
                log_error_errno(r, "Extending device control BPF program failed: %m");

        return r;
}

int cgroup_bpf_whitelist_class(BPFProgram *prog, int type, const char *acc) {
        struct bpf_insn insn[] = {
                BPF_JMP_IMM(BPF_JNE, BPF_REG_2, type, 5), /* compare device type */
                BPF_MOV32_REG(BPF_REG_1, BPF_REG_3), /* calculate access type */
                BPF_ALU32_IMM(BPF_AND, BPF_REG_1, 0),
                BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 1), /* compare access type */
                BPF_JMP_A(PASS_JUMP_OFF), /* jump to PASS */
        };
        int r, access;

        assert(prog);
        assert(acc);

        access = bpf_access_type(acc);
        if (access <= 0)
                return -EINVAL;

        insn[2].imm = access;

        r = bpf_program_add_instructions(prog, insn, ELEMENTSOF(insn));
        if (r < 0)
                log_error_errno(r, "Extending device control BPF program failed: %m");

        return r;
}

int cgroup_init_device_bpf(BPFProgram **ret, CGroupDevicePolicy policy, bool whitelist) {
        struct bpf_insn pre_insn[] = {
                /* load device type to r2 */
                BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_1,
                            offsetof(struct bpf_cgroup_dev_ctx, access_type)),

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

        if (policy == CGROUP_AUTO && !whitelist)
                return 0;

        r = bpf_program_new(BPF_PROG_TYPE_CGROUP_DEVICE, &prog);
        if (r < 0)
                return log_error_errno(r, "Loading device control BPF program failed: %m");

        if (policy == CGROUP_CLOSED || whitelist) {
                r = bpf_program_add_instructions(prog, pre_insn, ELEMENTSOF(pre_insn));
                if (r < 0)
                        return log_error_errno(r, "Extending device control BPF program failed: %m");
        }

        *ret = TAKE_PTR(prog);

        return 0;
}

int cgroup_apply_device_bpf(Unit *u, BPFProgram *prog, CGroupDevicePolicy policy, bool whitelist) {
        struct bpf_insn post_insn[] = {
                /* return DENY */
                BPF_MOV64_IMM(BPF_REG_0, 0),
                BPF_JMP_A(1),

        };

        struct bpf_insn exit_insn[] = {
                /* else return ALLOW */
                BPF_MOV64_IMM(BPF_REG_0, 1),
                BPF_EXIT_INSN()
        };

        _cleanup_free_ char *path = NULL;
        int r;

        if (!prog) {
                /* Remove existing program. */
                u->bpf_device_control_installed = bpf_program_unref(u->bpf_device_control_installed);
                return 0;
        }

        if (policy != CGROUP_STRICT || whitelist) {
                size_t off;

                r = bpf_program_add_instructions(prog, post_insn, ELEMENTSOF(post_insn));
                if (r < 0)
                        return log_error_errno(r, "Extending device control BPF program failed: %m");

                /* Fixup PASS_JUMP_OFF jump offsets. */
                for (off = 0; off < prog->n_instructions; off++) {
                        struct bpf_insn *ins = &prog->instructions[off];

                        if (ins->code == (BPF_JMP | BPF_JA) && ins->off == PASS_JUMP_OFF)
                                ins->off = prog->n_instructions - off - 1;
                }
        } else
                /* Explicitly forbid everything. */
                exit_insn[0].imm = 0;

        r = bpf_program_add_instructions(prog, exit_insn, ELEMENTSOF(exit_insn));
        if (r < 0)
                return log_error_errno(r, "Extending device control BPF program failed: %m");

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, NULL, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine cgroup path: %m");

        r = bpf_program_cgroup_attach(prog, BPF_CGROUP_DEVICE, path, BPF_F_ALLOW_MULTI);
        if (r < 0)
                return log_error_errno(r, "Attaching device control BPF program to cgroup %s failed: %m", path);

        /* Unref the old BPF program (which will implicitly detach it) right before attaching the new program. */
        u->bpf_device_control_installed = bpf_program_unref(u->bpf_device_control_installed);

        /* Remember that this BPF program is installed now. */
        u->bpf_device_control_installed = bpf_program_ref(prog);

        return 0;
}

int bpf_devices_supported(void) {
        struct bpf_insn trivial[] = {
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
