#include "architecture.h"
#include "fd-util.h"
#include "log.h"
#include "macro-fundamental.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "vmspawn-util.h"
#include <stdio.h>

bool qemu_check_kvm_support(void) {
        int r;
        r = access("/dev/kvm", F_OK);
        if (r == 0)
                return true;

        switch (errno) {
        case ENOENT:
                log_debug_errno(errno, "/dev/kvm not found. Not using KVM acceleration.");
                break;

        case EACCES:
                log_debug_errno(errno, "Permission denied to access /dev/kvm. Not using KVM acceleration.");
                break;
        }

        return false;
}

int find_ovmf_firmware(const char **ret_firmware_path) {
#ifdef __x86_64__
        #define FIRMWARE_LOCATIONS "/usr/share/ovmf/x64/OVMF_CODE.secboot.fd"
#elif __i386__
        #define FIRMWARE_LOCATIONS "/usr/share/edk2/ovmf-ia32/OVMF_CODE.secboot.fd", "/usr/share/OVMF/OVMF32_CODE_4M.secboot.fd"
#else
        #define FIRMWARE_LOCATIONS
#endif

        FOREACH_STRING(firmware, FIRMWARE_LOCATIONS) {
                if (access(firmware, F_OK) == 0) {
                        if (ret_firmware_path)
                                *ret_firmware_path = firmware;
                        return 0;
                }
        }

#undef FIRMWARE_LOCATIONS
#ifdef __x86_64__
        #define FIRMWARE_LOCATIONS "/usr/share/ovmf/ovmf_code_x64.bin", "/usr/share/ovmf/x64/OVMF_CODE.fd", "/usr/share/qemu/ovmf-x86_64.bin"
#elif __i386__
        #define FIRMWARE_LOCATIONS "/usr/share/ovmf/ovmf_code_ia32.bin", "/usr/share/edk2/ovmf-ia32/OVMF_CODE.fd"
#elif __aarch64__
        #define FIRMWARE_LOCATIONS "/usr/share/AAVMF/AAVMF_CODE.fd"
#elif __arm__
        #define FIRMWARE_LOCATIONS "/usr/share/AAVMF/AAVMF32_CODE.fd"
#else
        #define FIRMWARE_LOCATIONS
#endif

        FOREACH_STRING(firmware, FIRMWARE_LOCATIONS) {
                if (access(firmware, F_OK) == 0) {
                        if (ret_firmware_path)
                                *ret_firmware_path = firmware;
                        return 1;
                }
        }

#undef FIRMWARE_LOCATIONS
        #define FIRMWARE_LOCATIONS \
                "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd", \
                "/usr/share/edk2-ovmf/OVMF_CODE.secboot.fd", \
                "/usr/share/qemu/OVMF_CODE.secboot.fd", \
                "/usr/share/ovmf/OVMF.secboot.fd", \
                "/usr/share/OVMF/OVMF_CODE.secboot.fd"

        FOREACH_STRING(firmware, FIRMWARE_LOCATIONS) {
                if (access(firmware, F_OK) == 0) {
                        if (ret_firmware_path)
                                *ret_firmware_path = firmware;
                        return 0;
                }
        }

#undef FIRMWARE_LOCATIONS
        #define FIRMWARE_LOCATIONS \
                "/usr/share/edk2/ovmf/OVMF_CODE.fd", \
                "/usr/share/edk2-ovmf/OVMF_CODE.fd", \
                "/usr/share/qemu/OVMF_CODE.fd", \
                "/usr/share/ovmf/OVMF.fd", \
                "/usr/share/OVMF/OVMF_CODE.fd"

        FOREACH_STRING(firmware, FIRMWARE_LOCATIONS) {
                if (access(firmware, F_OK) == 0) {
                        if (ret_firmware_path)
                                *ret_firmware_path = firmware;
                        return 1;
                }
        }

#undef FIRMWARE_LOCATIONS
        return -ENOENT;
}

int find_qemu_binary(char **ret_qemu_binary) {
        int r;

        /*
         * On success the path to the qemu binary will be stored in `req_qemu_binary`
         *
         * If the qemu binary cannot be found -ENOENT will be returned.
         * If the native architecture is not supported by qemu -ESRCH will be returned;
         */

        static const char *architecture_to_qemu_table[_ARCHITECTURE_MAX] = {
                [ARCHITECTURE_ARM64]       = "aarch64",     /* differs from our name */
                [ARCHITECTURE_ARM]         = "arm",
                [ARCHITECTURE_ALPHA]       = "alpha",
                [ARCHITECTURE_X86_64]      = "x86_64",      /* differs from our name */
                [ARCHITECTURE_X86]         = "i386",        /* differs from our name */
                [ARCHITECTURE_LOONGARCH64] = "loongarch64",
                [ARCHITECTURE_MIPS64_LE]   = "mips",        /* differs from our name */
                [ARCHITECTURE_MIPS_LE]     = "mips",        /* differs from our name */
                [ARCHITECTURE_PARISC]      = "hppa",        /* differs from our name */
                [ARCHITECTURE_PPC64_LE]    = "ppc",         /* differs from our name */
                [ARCHITECTURE_PPC64]       = "ppc",         /* differs from our name */
                [ARCHITECTURE_PPC]         = "ppc",
                [ARCHITECTURE_RISCV32]     = "riscv32",
                [ARCHITECTURE_RISCV64]     = "riscv64",
                [ARCHITECTURE_S390X]       = "s390x",
        };

        FOREACH_STRING(s, "qemu", "qemu-kvm") {
                r = find_executable(s, ret_qemu_binary);
                if (r == 0)
                        return 0;

                if (r != -ENOENT)
                        return r;
        }

        const char *arch_qemu = architecture_to_qemu_table[native_architecture()];
        if (!arch_qemu)
                return log_debug_errno(SYNTHETIC_ERRNO(ESRCH), "Architecture %s not supported by qemu", architecture_to_string(native_architecture()));

        _cleanup_free_ char *qemu_arch_specific = NULL;
        qemu_arch_specific = strjoin("qemu-system-", arch_qemu);
        if (!qemu_arch_specific)
                return -ENOMEM;

        r = find_executable(qemu_arch_specific, ret_qemu_binary);
        if (r == 0)
                return 0;

        return -ENOENT;
}

int find_ovmf_vars(const char **ret_ovmf_vars) {
#ifdef __x86_64__
        #define OVMF_VARS_LOCATIONS "/usr/share/ovmf/x64/OVMF_VARS.fd"
#elif defined(__i386__)
        #define OVMF_VARS_LOCATIONS "/usr/share/edk2/ovmf-ia32/OVMF_VARS.fd", "/usr/share/OVMF/OVMF32_VARS_4M.fd"
#elif defined(__arm__)
        #define OVMF_VARS_LOCATIONS "/usr/share/AAVMF/AAVMF32_VARS.fd"
#elif defined(__aarch64__)
        #define OVMF_VARS_LOCATIONS "/usr/share/AAVMF/AAVMF_VARS.fd"
#endif

#define GENERIC_OVMF_VARS_LOCATIONS \
        "/usr/share/edk2/ovmf/OVMF_VARS.fd", \
        "/usr/share/edk2-ovmf/OVMF_VARS.fd", \
        "/usr/share/qemu/OVMF_VARS.fd", \
        "/usr/share/ovmf/OVMF_VARS.fd", \
        "/usr/share/OVMF/OVMF_VARS.fd"

        FOREACH_STRING(location, OVMF_VARS_LOCATIONS , GENERIC_OVMF_VARS_LOCATIONS) {
                if (access(location, F_OK) == 0) {
                        if (ret_ovmf_vars)
                                *ret_ovmf_vars = location;
                        return 0;
                }
        }

        log_error("Couldn't find OVMF UEFI variables file.");
        return -ENOENT;
}
