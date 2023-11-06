/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioctl.h>
#include <linux/vhost.h>

#include "architecture.h"
#include "conf-files.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "json.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"
#include "vmspawn-util.h"

OvmfConfig* ovmf_config_free(OvmfConfig *config) {
        if (!config)
                return NULL;

        free(config->path);
        free(config->vars);
        return mfree(config);
}

int qemu_check_kvm_support(void) {
        if (access("/dev/kvm", F_OK) >= 0)
                return true;
        if (errno == ENOENT) {
                log_debug_errno(errno, "/dev/kvm not found. Not using KVM acceleration.");
                return false;
        }
        if (errno == EPERM) {
                log_debug_errno(errno, "Permission denied to access /dev/kvm. Not using KVM acceleration.");
                return false;
        }

        return -errno;
}

int qemu_check_vsock_support(void) {
        int r;
        r = access("/dev/vhost-vsock", R_OK | W_OK);
        if (r == 0)
                return true;
        if (errno == ENOENT) {
                log_debug_errno(errno, "/dev/vhost-vsock not found. Not adding a vsock device to the virtual machine.");
                return false;
        }
        if (errno == EPERM) {
                log_debug_errno(errno, "Permission denied to access /dev/vhost-vsock. Not adding a vsock device to the virtual machine.");
                return false;
        }

        return -errno;
}

/* holds the data retrieved from the QEMU firmware interop JSON data */
typedef struct FirmwareData {
        char **features;
        char *firmware;
        char *vars;
} FirmwareData;

static FirmwareData* firmware_data_free(FirmwareData *fwd) {
        if (!fwd)
                return NULL;

        fwd->features = strv_free(fwd->features);
        fwd->firmware = mfree(fwd->firmware);
        fwd->vars = mfree(fwd->vars);

        return mfree(fwd);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(FirmwareData*, firmware_data_free);

static int firmware_executable(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        static const JsonDispatch table[] = {
                { "filename", JSON_VARIANT_STRING, json_dispatch_string, offsetof(FirmwareData, firmware), JSON_MANDATORY },
                { "format",   JSON_VARIANT_STRING, NULL,                 0,                                JSON_MANDATORY },
                {}
        };

        return json_dispatch(v, table, 0, userdata);
}

static int firmware_nvram_template(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        static const JsonDispatch table[] = {
                { "filename", JSON_VARIANT_STRING, json_dispatch_string, offsetof(FirmwareData, vars), JSON_MANDATORY },
                { "format",   JSON_VARIANT_STRING, NULL,                 0,                            JSON_MANDATORY },
                {}
        };

        return json_dispatch(v, table, 0, userdata);
}

static int firmware_mapping(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        static const JsonDispatch table[] = {
                { "device",         JSON_VARIANT_STRING, NULL,                    0, JSON_MANDATORY },
                { "executable",     JSON_VARIANT_OBJECT, firmware_executable,     0, JSON_MANDATORY },
                { "nvram-template", JSON_VARIANT_OBJECT, firmware_nvram_template, 0, JSON_MANDATORY },
                {}
        };

        return json_dispatch(v, table, 0, userdata);
}

int find_ovmf_config(int search_sb, OvmfConfig **ret) {
        _cleanup_(ovmf_config_freep) OvmfConfig *config = NULL;
        _cleanup_free_ char *user_firmware_dir = NULL;
        _cleanup_strv_free_ char **conf_files = NULL;
        int r;

        /* Search in:
         * - $XDG_CONFIG_HOME/qemu/firmware
         * - /etc/qemu/firmware
         * - /usr/share/qemu/firmware
         *
         * Prioritising entries in "more specific" directories
         */

        r = xdg_user_config_dir(&user_firmware_dir, "/qemu/firmware");
        if (r < 0)
                return r;

        r = conf_files_list_strv(&conf_files, ".json", NULL, CONF_FILES_FILTER_MASKED|CONF_FILES_REGULAR,
                        STRV_MAKE_CONST(user_firmware_dir, "/etc/qemu/firmware", "/usr/share/qemu/firmware"));
        if (r < 0)
                return log_debug_errno(r, "Failed to list config files: %m");

        STRV_FOREACH(file, conf_files) {
                _cleanup_(firmware_data_freep) FirmwareData *fwd = NULL;
                _cleanup_(json_variant_unrefp) JsonVariant *config_json = NULL;
                _cleanup_free_ char *contents = NULL;
                size_t contents_sz = 0;

                r = read_full_file(*file, &contents, &contents_sz);
                if (r == -ENOMEM)
                        return r;
                if (r < 0) {
                        log_debug_errno(r, "Failed to read contents of %s - ignoring: %m", *file);
                        continue;
                }

                r = json_parse(contents, 0, &config_json, NULL, NULL);
                if (r == -ENOMEM)
                        return r;
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse the JSON in %s - ignoring: %m", *file);
                        continue;
                }

                static const JsonDispatch table[] = {
                        { "description",     JSON_VARIANT_STRING, NULL,               0,                                JSON_MANDATORY },
                        { "interface-types", JSON_VARIANT_ARRAY,  NULL,               0,                                JSON_MANDATORY },
                        { "mapping",         JSON_VARIANT_OBJECT, firmware_mapping,   0,                                JSON_MANDATORY },
                        { "targets",         JSON_VARIANT_ARRAY,  NULL,               0,                                JSON_MANDATORY },
                        { "features",        JSON_VARIANT_ARRAY,  json_dispatch_strv, offsetof(FirmwareData, features), JSON_MANDATORY },
                        { "tags",            JSON_VARIANT_ARRAY,  NULL,               0,                                JSON_MANDATORY },
                        {}
                };

                fwd = new0(FirmwareData, 1);
                if (!fwd)
                        return -ENOMEM;

                r = json_dispatch(config_json, table, 0, fwd);
                if (r == -ENOMEM)
                        return r;
                if (r < 0) {
                        log_debug_errno(r, "Failed to extract the required fields from the JSON in %s - ignoring: %m", *file);
                        continue;
                }

                int sb_present = !!strv_find(fwd->features, "secure-boot");

                /* exclude firmware which doesn't match our Secure Boot requirements */
                if (search_sb >= 0 && search_sb != sb_present) {
                        log_debug("Skipping %s, firmware doesn't fit required Secure Boot configuration", *file);
                        continue;
                }

                config = new0(OvmfConfig, 1);
                if (!config)
                        return -ENOMEM;

                config->path = TAKE_PTR(fwd->firmware);
                config->vars = TAKE_PTR(fwd->vars);
                config->supports_sb = sb_present;
                break;
        }

        if (!config)
                return -ENOENT;

        if (ret)
                *ret = TAKE_PTR(config);

        return 0;
}

int find_qemu_binary(char **ret_qemu_binary) {
        int r;

        /*
         * On success the path to the qemu binary will be stored in `req_qemu_binary`
         *
         * If the qemu binary cannot be found -ENOENT will be returned.
         * If the native architecture is not supported by qemu -EOPNOTSUPP will be returned;
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
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Architecture %s not supported by qemu", architecture_to_string(native_architecture()));

        _cleanup_free_ char *qemu_arch_specific = NULL;
        qemu_arch_specific = strjoin("qemu-system-", arch_qemu);
        if (!qemu_arch_specific)
                return -ENOMEM;

        return find_executable(qemu_arch_specific, ret_qemu_binary);
}

int machine_cid(unsigned int *ret_machine_cid) {
        int r;
        uint64_t cid;
        _cleanup_close_ int vfd = -EBADF;

        /* Enumerate all machine CIDs in [3..UINT_MAX) until we find a free CID.
         * if there are no free addresses return SYNTHETIC_ERRNO(EADDRNOTAVAIL)
         * if ioctl returns an unexpected error forward that
         */

        r = open("/dev/vhost-vsock", O_RDWR);
        if (r < 0)
                return log_debug_errno(r, "Failed to open /dev/vhost-vsock as read/write: %m");
        vfd = r;

        for (cid = 3; cid < UINT_MAX; cid++) {
                r = ioctl(vfd, VHOST_VSOCK_SET_GUEST_CID, &cid);
                if (r >= 0)
                        goto success;
                if (errno != EADDRINUSE)
                        return -errno;
        }

        return log_debug_errno(SYNTHETIC_ERRNO(EADDRNOTAVAIL), "Enumerated entire CID space and found no free CIDs: %m");

success:
        if (ret_machine_cid)
                *ret_machine_cid = (unsigned int)cid;

        return 0;
}
