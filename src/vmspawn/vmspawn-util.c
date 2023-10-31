/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioctl.h>
#include <linux/vhost.h>

#include "alloc-util.h"
#include "architecture.h"
#include "fd-util.h"
#include "fileio.h"
#include "json.h"
#include "log.h"
#include "macro-fundamental.h"
#include "memory-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "sort-util.h"
#include "string-util-fundamental.h"
#include "string-util.h"
#include "recurse-dir.h"
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
        if (access("/dev/kvm", F_OK) == 0)
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

/* holds the information needed to sort the config files into the right order */
typedef struct OvmfConfigFile {
        char *name;
        char *path;
        int priority;
} OvmfConfigFile;

static inline void ovmf_config_file_free_many(OvmfConfigFile *confs, size_t n_confs) {
        assert(confs || n_confs == 0);

        FOREACH_ARRAY(conf, confs, n_confs) {
                free(conf->name);
                free(conf->path);
        }

        free(confs);
}

static int ovmf_config_file_compare(const OvmfConfigFile *a, const OvmfConfigFile *b) {
        assert(a);
        assert(b);

        int name_cmp = strcmp(a->name, b->name);
        return name_cmp != 0 ? name_cmp : CMP(a->priority, b->priority);
}

/* holds the data retrieved from the QEMU firmware interop JSON data */
typedef struct FirmwareData {
        char **features;
        char *firmware;
        char *vars;
} FirmwareData;

static FirmwareData* firmware_data_new(void) {
        return new0(FirmwareData, 1);
}

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

        return json_dispatch(v, table, NULL, 0, userdata);
}

static int firmware_nvram_template(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        static const JsonDispatch table[] = {
                { "filename", JSON_VARIANT_STRING, json_dispatch_string, offsetof(FirmwareData, vars), JSON_MANDATORY },
                { "format",   JSON_VARIANT_STRING, NULL,                 0,                            JSON_MANDATORY },
                {}
        };

        return json_dispatch(v, table, NULL, 0, userdata);
}

static int firmware_mapping(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        static const JsonDispatch table[] = {
                { "device",         JSON_VARIANT_STRING, NULL,                    0, JSON_MANDATORY },
                { "executable",     JSON_VARIANT_OBJECT, firmware_executable,     0, JSON_MANDATORY },
                { "nvram-template", JSON_VARIANT_OBJECT, firmware_nvram_template, 0, JSON_MANDATORY },
                {}
        };

        return json_dispatch(v, table, NULL, 0, userdata);
}

int find_ovmf_config(int search_sb, OvmfConfig **ret) {
        _cleanup_(ovmf_config_freep) OvmfConfig *config = NULL;
        int r;

        config = new0(OvmfConfig, 1);
        if (!config)
                return -ENOMEM;

        _cleanup_free_ char *user_firmware_dir = NULL;
        r = xdg_user_config_dir(&user_firmware_dir, "/qemu/firmware");
        if (r < 0)
                return r;

        /* sdf_ptr is required to make CLEANUP_ARRAY work, without sdf_ptr the cleanup function is passed a
         * ptr which has the bit representation of the first two elements of the array */
        int source_dir_fds[] = { -EBADF, -EBADF, -EBADF };
        const int *sdf_ptr = source_dir_fds;
        OvmfConfigFile *files = NULL;
        size_t n_sdfs = ELEMENTSOF(source_dir_fds), n_cfs = 0, i = 0;
        CLEANUP_ARRAY(sdf_ptr, n_sdfs, close_many);
        CLEANUP_ARRAY(files, n_cfs, ovmf_config_file_free_many);

        /* Search in:
         * - $XDG_CONFIG_HOME/qemu/firmware
         * - /etc/qemu/firmware
         * - /usr/share/qemu/firmware
         *
         * Prioritising entries in "more specific" directories
         */
        char **search_dirs = STRV_MAKE(user_firmware_dir, "/etc/qemu/firmware", "/usr/share/qemu/firmware");
        STRV_FOREACH(s, search_dirs) {
                r = open(*s, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                if (r < 0) {
                        log_debug_errno(errno, "Failed to open directory '%s', ignoring: %m", *s);
                        i++;
                        continue;
                }
                source_dir_fds[i++] = r;
        }

        for (i = 0; i < n_sdfs; i++) {
                int sdf = source_dir_fds[i];
                if (sdf < 0)
                        continue;

                _cleanup_free_ DirectoryEntries *de = NULL;
                r = readdir_all(sdf, RECURSE_DIR_SORT, &de);
                if (r < 0) {
                        log_debug_errno(r, "Failed to read the contents of '%s', ignoring: %m", search_dirs[i]);
                        continue;
                }

                FOREACH_ARRAY(ent, de->entries, de->n_entries) {
                        const struct dirent *d = *ent;
                        if (!endswith(d->d_name, ".json"))
                                continue;

                        OvmfConfigFile *f = GREEDY_REALLOC(files, n_cfs + 1);
                        if (!f)
                                return -ENOMEM;

                        _cleanup_free_ char *name = NULL, *path = NULL;
                        name = strdup(d->d_name);
                        if (!name)
                                return -ENOMEM;

                        path = strjoin(search_dirs[i], "/", name);
                        if (!path)
                                return -ENOMEM;

                        f[n_cfs++] = (OvmfConfigFile) {
                                .name = TAKE_PTR(name),
                                .path = TAKE_PTR(path),
                                .priority = i,
                        };
                        files = f;
                }
        }

        typesafe_qsort(files, n_cfs, ovmf_config_file_compare);

        bool valid_config_found = false;

        for (i = 0; i < n_cfs; i++) {
                _cleanup_(json_variant_unrefp) JsonVariant *config_json = NULL;
                _cleanup_free_ char *contents = NULL;
                size_t contents_sz = 0;
                const OvmfConfigFile *file = &files[i];

                int sdf = source_dir_fds[file->priority];
                r = read_full_file_at(sdf, file->name, &contents, &contents_sz);
                if (r == -ENOMEM)
                        return r;
                if (r < 0) {
                        log_debug_errno(r, "Failed to read contents of %s - ignoring: %m", file->path);
                        continue;
                }

                /* if the file is empty we need to mask any later occurances of this file */
                if (contents_sz == 0) {
                        size_t j;
                        for (j = 1; j < 3; j++) {
                                if (i + j >= n_cfs)
                                        break;

                                if (!streq(files[i].name, files[i + j].name))
                                        break;

                                log_debug("Less specific file %s masked by empty %s", files[i + j].path, file->path);
                        }
                        i += j - 1;
                        continue;
                }

                r = json_parse(contents, 0, &config_json, NULL, NULL);
                if (r == -ENOMEM)
                        return r;
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse the JSON in %s - ignoring: %m", file->path);
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

                _cleanup_(firmware_data_freep) FirmwareData *fwd = firmware_data_new();
                if (!fwd)
                        return -ENOMEM;

                r = json_dispatch(config_json, table, NULL, 0, fwd);
                if (r == -ENOMEM)
                        return r;
                if (r < 0) {
                        log_debug_errno(r, "Failed to extract the required fields from the JSON in %s - ignoring: %m", file->path);
                        continue;
                }

                int sb_present = !!strv_find(fwd->features, "secure-boot");

                /* exclude firmware which doesn't match our secboot requirements */
                if (search_sb >= 0 && search_sb != sb_present) {
                        log_debug("Skipping %s, firmware doesn't fit required secboot configuration", file->path);
                        continue;
                }

                config->path = TAKE_PTR(fwd->firmware);
                config->vars = TAKE_PTR(fwd->vars);
                config->supports_sb = sb_present;
                valid_config_found = true;
                break;
        }

        if (!valid_config_found)
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
