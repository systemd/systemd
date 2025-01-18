/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cpio.h"
#include "device-path-util.h"
#include "devicetree.h"
#include "efivars.h"
#include "export-vars.h"
#include "graphics.h"
#include "iovec-util-fundamental.h"
#include "linux.h"
#include "measure.h"
#include "memory-util-fundamental.h"
#include "part-discovery.h"
#include "pe.h"
#include "proto/shell-parameters.h"
#include "random-seed.h"
#include "sbat.h"
#include "secure-boot.h"
#include "shim.h"
#include "smbios.h"
#include "splash.h"
#include "tpm2-pcr.h"
#include "uki.h"
#include "util.h"
#include "version.h"
#include "vmm.h"

/* The list of initrds we combine into one, in the order we want to merge them */
enum {
        /* The first two are part of the PE binary */
        INITRD_UCODE,
        INITRD_BASE,

        /* The rest are dynamically generated, and hence in dynamic memory */
        _INITRD_DYNAMIC_FIRST,
        INITRD_CREDENTIAL = _INITRD_DYNAMIC_FIRST,
        INITRD_GLOBAL_CREDENTIAL,
        INITRD_SYSEXT,
        INITRD_CONFEXT,
        INITRD_PCRSIG,
        INITRD_PCRPKEY,
        INITRD_OSREL,
        INITRD_PROFILE,
        _INITRD_MAX,
};

/* magic string to find in the binary image */
DECLARE_NOALLOC_SECTION(".sdmagic", "#### LoaderInfo: systemd-stub " GIT_VERSION " ####");

DECLARE_SBAT(SBAT_STUB_SECTION_TEXT);

static char16_t* pe_section_to_str16(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector *section) {

        assert(loaded_image);
        assert(section);

        if (!PE_SECTION_VECTOR_IS_SET(section))
                return NULL;

        return xstrn8_to_16((const char *) loaded_image->ImageBase + section->memory_offset, section->memory_size);
}

static char *pe_section_to_str8(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector *section) {

        assert(loaded_image);
        assert(section);

        if (!PE_SECTION_VECTOR_IS_SET(section))
                return NULL;

        return xstrndup8((const char *)loaded_image->ImageBase + section->memory_offset, section->memory_size);
}

static void combine_measured_flag(int *value, int measured) {
        assert(value);

        /* Combine the "measured" flag in a sensible way: if we haven't measured anything yet, the first
         * write is taken as is. Later writes can only turn off the flag, never on again. Or in other words,
         * we eventually want to return true iff we really measured *everything* there was to measure.
         *
         * Reminder how the "measured" flag actually works:
         *    > 0 → something was measured
         *   == 0 → there was something to measure but we didn't (because no TPM or so)
         *    < 0 → nothing has been submitted for measurement so far
         */

        if (measured < 0)
                return;

        *value = *value < 0 ? measured : *value && measured;
}

/* Combine initrds by concatenation in memory */
static EFI_STATUS combine_initrds(
                const struct iovec initrds[], size_t n_initrds,
                Pages *ret_initrd_pages, size_t *ret_initrd_size) {

        size_t n = 0;

        assert(initrds || n_initrds == 0);
        assert(ret_initrd_pages);
        assert(ret_initrd_size);

        FOREACH_ARRAY(i, initrds, n_initrds) {
                /* some initrds (the ones from UKI sections) need padding, pad all to be safe */
                size_t initrd_size = ALIGN4(i->iov_len);
                if (n > SIZE_MAX - initrd_size)
                        return EFI_OUT_OF_RESOURCES;

                n += initrd_size;
        }

        _cleanup_pages_ Pages pages = xmalloc_initrd_pages(n);
        uint8_t *p = PHYSICAL_ADDRESS_TO_POINTER(pages.addr);

        FOREACH_ARRAY(i, initrds, n_initrds) {
                size_t pad;

                p = mempcpy(p, i->iov_base, i->iov_len);

                pad = ALIGN4(i->iov_len) - i->iov_len;
                if (pad == 0)
                        continue;

                memzero(p, pad);
                p += pad;
        }

        assert(PHYSICAL_ADDRESS_TO_POINTER(pages.addr + n) == p);

        *ret_initrd_pages = TAKE_STRUCT(pages);
        *ret_initrd_size = n;

        return EFI_SUCCESS;
}

static void export_stub_variables(EFI_LOADED_IMAGE_PROTOCOL *loaded_image, unsigned profile) {
        static const uint64_t stub_features =
                EFI_STUB_FEATURE_REPORT_BOOT_PARTITION |    /* We set LoaderDevicePartUUID */
                EFI_STUB_FEATURE_PICK_UP_CREDENTIALS |      /* We pick up credentials from the boot partition */
                EFI_STUB_FEATURE_PICK_UP_SYSEXTS |          /* We pick up system extensions from the boot partition */
                EFI_STUB_FEATURE_PICK_UP_CONFEXTS |         /* We pick up configuration extensions from the boot partition */
                EFI_STUB_FEATURE_THREE_PCRS |               /* We can measure kernel image, parameters and sysext */
                EFI_STUB_FEATURE_RANDOM_SEED |              /* We pass a random seed to the kernel */
                EFI_STUB_FEATURE_CMDLINE_ADDONS |           /* We pick up .cmdline addons */
                EFI_STUB_FEATURE_CMDLINE_SMBIOS |           /* We support extending kernel cmdline from SMBIOS Type #11 */
                EFI_STUB_FEATURE_DEVICETREE_ADDONS |        /* We pick up .dtb addons */
                EFI_STUB_FEATURE_MULTI_PROFILE_UKI |        /* We grok the "@1" profile command line argument */
                EFI_STUB_FEATURE_REPORT_STUB_PARTITION |    /* We set StubDevicePartUUID + StubImageIdentifier */
                0;

        assert(loaded_image);

        /* add StubInfo (this is one is owned by the stub, hence we unconditionally override this with our
         * own data) */
        (void) efivar_set_str16(MAKE_GUID_PTR(LOADER), u"StubInfo", u"systemd-stub " GIT_VERSION, 0);

        (void) efivar_set_uint64_le(MAKE_GUID_PTR(LOADER), u"StubFeatures", stub_features, 0);

        (void) efivar_set_uint64_str16(MAKE_GUID_PTR(LOADER), u"StubProfile", profile, 0);

        if (loaded_image->DeviceHandle) {
                _cleanup_free_ char16_t *uuid = disk_get_part_uuid(loaded_image->DeviceHandle);
                if (uuid)
                        efivar_set_str16(MAKE_GUID_PTR(LOADER), u"StubDevicePartUUID", uuid, 0);
        }

        if (loaded_image->FilePath) {
                _cleanup_free_ char16_t *s = NULL;
                if (device_path_to_str(loaded_image->FilePath, &s) == EFI_SUCCESS)
                        efivar_set_str16(MAKE_GUID_PTR(LOADER), u"StubImageIdentifier", s, 0);
        }
}

static bool parse_profile_from_cmdline(char16_t **cmdline, unsigned *ret_profile) {
        assert(cmdline);
        assert(*cmdline);
        assert(ret_profile);

        const char16_t *p = *cmdline;
        if (p[0] != '@')
                goto nothing;

        uint64_t u;
        const char16_t *tail;
        if (!parse_number16(p + 1, &u, &tail))
                goto nothing;
        if (u > UINT_MAX)
                goto nothing;
        /* Remove exactly one separating space. No further mangling, in order to not disturb measurements –
         * and thus making prediction harder –, after all we want that people can safely prefix their command
         * lines with a profile without having to be bothered with additional whitespace the command line
         * might already contain. */
        if (tail[0] == u' ')
                tail++;
        else if (tail[0] != 0) /* If this is neither a space nor the end of the string, it must be something else */
                goto nothing;

        /* Drop prefix */
        free_and_xstrdup16(cmdline, tail);
        *ret_profile = u;
        return true;

nothing:
        *ret_profile = 0;
        return false;
}

static bool parse_profile_from_argument(const char16_t *arg, unsigned *ret_profile) {
        assert(arg);
        assert(ret_profile);

        if (arg[0] != '@')
                goto nothing;

        uint64_t u;
        if (!parse_number16(arg + 1, &u, /* ret_tail= */ NULL))
                goto nothing;

        if (u > UINT_MAX)
                goto nothing;

        *ret_profile = u;
        return true;

nothing:
        *ret_profile = 0;
        return false;
}

static void process_arguments(
                EFI_HANDLE stub_image,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                unsigned *ret_profile,
                char16_t **ret_cmdline) {

        assert(stub_image);
        assert(loaded_image);
        assert(ret_profile);
        assert(ret_cmdline);

        /* The UEFI shell registers EFI_SHELL_PARAMETERS_PROTOCOL onto images it runs. This lets us know that
         * LoadOptions starts with the stub binary path which we want to strip off. */
        EFI_SHELL_PARAMETERS_PROTOCOL *shell;
        if (BS->HandleProtocol(stub_image, MAKE_GUID_PTR(EFI_SHELL_PARAMETERS_PROTOCOL), (void **) &shell) != EFI_SUCCESS) {

                /* We also do a superficial check whether first character of passed command line
                 * is printable character (for compat with some Dell systems which fill in garbage?). */
                if (loaded_image->LoadOptionsSize < sizeof(char16_t) || ((const char16_t *) loaded_image->LoadOptions)[0] <= 0x1F)
                        goto nothing;

                /* Not running from EFI shell, use entire LoadOptions. Note that LoadOptions is a void*, so
                 * it could actually be anything! */
                char16_t *c = xstrndup16(loaded_image->LoadOptions, loaded_image->LoadOptionsSize / sizeof(char16_t));
                parse_profile_from_cmdline(&c, ret_profile);
                *ret_cmdline = mangle_stub_cmdline(c);
                return;
        }

        if (shell->Argc <= 1) /* No arguments were provided? Then we fall back to built-in cmdline. */
                goto nothing;

        size_t i = 1;

        /* The first argument is possibly an "@5" style profile specifier */
        i += parse_profile_from_argument(shell->Argv[i], ret_profile);

        if (i < shell->Argc) {
                /* Assemble the command line ourselves without our stub path. */
                *ret_cmdline = xstrdup16(shell->Argv[i++]);
                for (; i < shell->Argc; i++) {
                        _cleanup_free_ char16_t *old = *ret_cmdline;
                        *ret_cmdline = xasprintf("%ls %ls", old, shell->Argv[i]);
                }
        } else
                *ret_cmdline = NULL;

        return;

nothing:
        *ret_profile = 0;
        *ret_cmdline = NULL;
        return;
}

static EFI_STATUS load_addons_from_dir(
                EFI_FILE *root,
                const char16_t *prefix,
                char16_t ***items,
                size_t *n_items,
                size_t *n_allocated) {

        _cleanup_file_close_ EFI_FILE *extra_dir = NULL;
        _cleanup_free_ EFI_FILE_INFO *dirent = NULL;
        size_t dirent_size = 0;
        EFI_STATUS err;

        assert(root);
        assert(prefix);
        assert(items);
        assert(n_items);
        assert(n_allocated);

        err = open_directory(root, prefix, &extra_dir);
        if (err == EFI_NOT_FOUND)
                /* No extra subdir, that's totally OK */
                return EFI_SUCCESS;
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to open addons directory '%ls': %m", prefix);

        for (;;) {
                _cleanup_free_ char16_t *d = NULL;

                err = readdir(extra_dir, &dirent, &dirent_size);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to read addons directory of loaded image: %m");
                if (!dirent) /* End of directory */
                        break;

                if (dirent->FileName[0] == '.')
                        continue;
                if (FLAGS_SET(dirent->Attribute, EFI_FILE_DIRECTORY))
                        continue;
                if (!is_ascii(dirent->FileName))
                        continue;
                if (strlen16(dirent->FileName) > 255) /* Max filename size on Linux */
                        continue;
                if (!endswith_no_case(dirent->FileName, u".addon.efi"))
                        continue;

                d = xstrdup16(dirent->FileName);

                if (*n_items + 2 > *n_allocated) {
                        /* We allocate 16 entries at a time, as a matter of optimization */
                        if (*n_items > (SIZE_MAX / sizeof(uint16_t)) - 16) /* Overflow check, just in case */
                                return log_oom();

                        size_t m = *n_items + 16;
                        *items = xrealloc(*items, *n_allocated * sizeof(uint16_t *), m * sizeof(uint16_t *));
                        *n_allocated = m;
                }

                (*items)[(*n_items)++] = TAKE_PTR(d);
                (*items)[*n_items] = NULL; /* Let's always NUL terminate, to make freeing via strv_free() easy */
        }

        return EFI_SUCCESS;
}

static void cmdline_append_and_measure_addons(
                char16_t *cmdline_addon,
                char16_t **cmdline_append,
                int *parameters_measured) {

        assert(cmdline_append);
        assert(parameters_measured);

        if (isempty(cmdline_addon))
                return;

        _cleanup_free_ char16_t *copy = mangle_stub_cmdline(xstrdup16(cmdline_addon));
        if (isempty(copy))
                return;

        bool m = false;
        (void) tpm_log_load_options(copy, &m);
        combine_measured_flag(parameters_measured, m);

        _cleanup_free_ char16_t *tmp = TAKE_PTR(*cmdline_append);
        if (isempty(tmp))
                *cmdline_append = TAKE_PTR(copy);
        else
                *cmdline_append = xasprintf("%ls %ls", tmp, copy);
}

typedef struct NamedAddon {
        char16_t *filename;
        struct iovec blob;
} NamedAddon;

static void named_addon_done(NamedAddon *a) {
        assert(a);

        a->filename = mfree(a->filename);
        iovec_done(&a->blob);
}

static void named_addon_free_many(NamedAddon *a, size_t n) {
        assert(a || n == 0);

        FOREACH_ARRAY(i, a, n)
                named_addon_done(i);

        free(a);
}

static void install_addon_devicetrees(
                struct devicetree_state *dt_state,
                const NamedAddon *addons,
                size_t n_addons,
                int *parameters_measured) {

        EFI_STATUS err;

        assert(dt_state);
        assert(addons || n_addons == 0);
        assert(parameters_measured);

        FOREACH_ARRAY(a, addons, n_addons) {
                err = devicetree_install_from_memory(dt_state, a->blob.iov_base, a->blob.iov_len);
                if (err != EFI_SUCCESS) {
                        log_error_status(err, "Error loading addon devicetree, ignoring: %m");
                        continue;
                }

                bool m = false;
                err = tpm_log_tagged_event(
                                TPM2_PCR_KERNEL_CONFIG,
                                POINTER_TO_PHYSICAL_ADDRESS(a->blob.iov_base),
                                a->blob.iov_len,
                                DEVICETREE_ADDON_EVENT_TAG_ID,
                                a->filename,
                                &m);
                if (err != EFI_SUCCESS)
                        return (void) log_error_status(
                                        err,
                                        "Unable to extend PCR %i with DTB addon '%ls': %m",
                                        TPM2_PCR_KERNEL_CONFIG,
                                        a->filename);

                combine_measured_flag(parameters_measured, m);
        }
}

static inline void iovec_array_extend(struct iovec **arr, size_t *n_arr, struct iovec elem) {
        assert(arr);
        assert(n_arr);

        if (!iovec_is_set(&elem))
                return;

        *arr = xrealloc(*arr, *n_arr * sizeof(struct iovec), (*n_arr + 1)  * sizeof(struct iovec));
        (*arr)[(*n_arr)++] = elem;
}

static void measure_and_append_initrd_addons(
                struct iovec **all_initrds,
                size_t *n_all_initrds,
                const NamedAddon *initrd_addons,
                size_t n_initrd_addons,
                int *sections_measured) {

        EFI_STATUS err;

        assert(all_initrds);
        assert(n_all_initrds);
        assert(initrd_addons || n_initrd_addons == 0);
        assert(sections_measured);

        FOREACH_ARRAY(i, initrd_addons, n_initrd_addons) {
                bool m = false;
                err = tpm_log_tagged_event(
                                TPM2_PCR_KERNEL_CONFIG,
                                POINTER_TO_PHYSICAL_ADDRESS(i->blob.iov_base),
                                i->blob.iov_len,
                                INITRD_ADDON_EVENT_TAG_ID,
                                i->filename,
                                &m);
                if (err != EFI_SUCCESS)
                        return (void) log_error_status(
                                        err,
                                        "Unable to extend PCR %i with INITRD addon '%ls': %m",
                                        TPM2_PCR_KERNEL_CONFIG,
                                        i->filename);

                combine_measured_flag(sections_measured, m);

                iovec_array_extend(all_initrds, n_all_initrds, i->blob);
        }
}

static void measure_and_append_ucode_addons(
                struct iovec **all_initrds,
                size_t *n_all_initrds,
                const NamedAddon *ucode_addons,
                size_t n_ucode_addons,
                int *sections_measured) {

        EFI_STATUS err;

        assert(all_initrds);
        assert(n_all_initrds);
        assert(ucode_addons || n_ucode_addons == 0);
        assert(sections_measured);

        /* Ucode addons need to be measured and copied into all_initrds in reverse order,
         * the kernel takes the first one it finds. */
        for (ssize_t i = n_ucode_addons - 1; i >= 0; i--) {
                bool m = false;
                err = tpm_log_tagged_event(
                                TPM2_PCR_KERNEL_CONFIG,
                                POINTER_TO_PHYSICAL_ADDRESS(ucode_addons[i].blob.iov_base),
                                ucode_addons[i].blob.iov_len,
                                UCODE_ADDON_EVENT_TAG_ID,
                                ucode_addons[i].filename,
                                &m);
                if (err != EFI_SUCCESS)
                        return (void) log_error_status(
                                        err,
                                        "Unable to extend PCR %i with UCODE addon '%ls': %m",
                                        TPM2_PCR_KERNEL_CONFIG,
                                        ucode_addons[i].filename);

                combine_measured_flag(sections_measured, m);

                iovec_array_extend(all_initrds, n_all_initrds, ucode_addons[i].blob);
        }
}

static void extend_initrds(
                const struct iovec initrds[static _INITRD_MAX],
                struct iovec **all_initrds,
                size_t *n_all_initrds) {

        assert(initrds);
        assert(all_initrds);
        assert(n_all_initrds);

        FOREACH_ARRAY(i, initrds, _INITRD_MAX)
                iovec_array_extend(all_initrds, n_all_initrds, *i);
}

static EFI_STATUS load_addons(
                EFI_HANDLE stub_image,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const char16_t *prefix,
                const char *uname,
                char16_t **cmdline,                         /* Both input+output, extended with new addons we find */
                NamedAddon **devicetree_addons,             /* Ditto */
                size_t *n_devicetree_addons,
                NamedAddon **initrd_addons,                 /* Ditto */
                size_t *n_initrd_addons,
                NamedAddon **ucode_addons,                  /* Ditto */
                size_t *n_ucode_addons) {

        _cleanup_strv_free_ char16_t **items = NULL;
        _cleanup_file_close_ EFI_FILE *root = NULL;
        size_t n_items = 0, n_allocated = 0;
        EFI_STATUS err;

        assert(stub_image);
        assert(loaded_image);
        assert(prefix);

        if (!loaded_image->DeviceHandle)
                return EFI_SUCCESS;

        err = open_volume(loaded_image->DeviceHandle, &root);
        if (err == EFI_UNSUPPORTED)
                /* Error will be unsupported if the bootloader doesn't implement the file system protocol on
                 * its file handles. */
                return EFI_SUCCESS;
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Unable to open root directory: %m");

        err = load_addons_from_dir(root, prefix, &items, &n_items, &n_allocated);
        if (err != EFI_SUCCESS)
                return err;

        if (n_items == 0)
                return EFI_SUCCESS; /* Empty directory */

        /* Now, sort the files we found, to make this uniform and stable (and to ensure the TPM measurements
         * are not dependent on read order) */
        sort_pointer_array((void**) items, n_items, (compare_pointer_func_t) strcmp16);

        for (size_t i = 0; i < n_items; i++) {
                PeSectionVector sections[ELEMENTSOF(unified_sections)] = {};
                _cleanup_free_ EFI_DEVICE_PATH *addon_path = NULL;
                _cleanup_(unload_imagep) EFI_HANDLE addon = NULL;
                EFI_LOADED_IMAGE_PROTOCOL *loaded_addon = NULL;
                _cleanup_free_ char16_t *addon_spath = NULL;

                addon_spath = xasprintf("%ls\\%ls", prefix, items[i]);
                err = make_file_device_path(loaded_image->DeviceHandle, addon_spath, &addon_path);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Error making device path for %ls: %m", addon_spath);

                /* By using shim_load_image, we cover both the case where the PE files are signed with MoK
                 * and with DB, and running with or without shim. */
                err = shim_load_image(stub_image, addon_path, &addon);
                if (err != EFI_SUCCESS) {
                        log_error_status(err,
                                         "Failed to read '%ls' from '%ls', ignoring: %m",
                                         items[i],
                                         addon_spath);
                        continue;
                }

                err = BS->HandleProtocol(addon,
                                         MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL),
                                         (void **) &loaded_addon);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to find protocol in %ls: %m", items[i]);

                err = pe_memory_locate_sections(loaded_addon->ImageBase, unified_sections, sections);
                if (err != EFI_SUCCESS ||
                    (!PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_CMDLINE) &&
                     !PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTB) &&
                     !PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTBAUTO) &&
                     !PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_INITRD) &&
                     !PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_UCODE))) {
                        if (err == EFI_SUCCESS)
                                err = EFI_NOT_FOUND;
                        log_error_status(err,
                                         "Unable to locate embedded .cmdline/.dtb/.dtbauto/.initrd/.ucode sections in %ls, ignoring: %m",
                                         items[i]);
                        continue;
                }

                /* We want to enforce that addons are not UKIs, i.e.: they must not embed a kernel. */
                if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_LINUX)) {
                        log_error("%ls is a UKI, not an addon, ignoring.", items[i]);
                        continue;
                }

                /* Also enforce that, in case it is specified, .uname matches as a quick way to allow
                 * enforcing compatibility with a specific UKI only */
                if (uname && PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_UNAME) &&
                                !strneq8(uname,
                                         (const char *)loaded_addon->ImageBase + sections[UNIFIED_SECTION_UNAME].memory_offset,
                                         sections[UNIFIED_SECTION_UNAME].memory_size)) {
                        log_error(".uname mismatch between %ls and UKI, ignoring", items[i]);
                        continue;
                }

                if (cmdline && PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_CMDLINE)) {
                        _cleanup_free_ char16_t *tmp = TAKE_PTR(*cmdline),
                                *extra16 = mangle_stub_cmdline(pe_section_to_str16(loaded_addon, sections + UNIFIED_SECTION_CMDLINE));

                        *cmdline = xasprintf("%ls%ls%ls", strempty(tmp), isempty(tmp) ? u"" : u" ", extra16);
                }

                // FIXME: do we want to do something else here?
                // This should behave exactly as .dtb/.dtbauto in the main UKI
                if (devicetree_addons && PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTBAUTO)) {
                        *devicetree_addons = xrealloc(*devicetree_addons,
                                                      *n_devicetree_addons * sizeof(NamedAddon),
                                                      (*n_devicetree_addons + 1) * sizeof(NamedAddon));

                        (*devicetree_addons)[(*n_devicetree_addons)++] = (NamedAddon) {
                                .blob = {
                                        .iov_base = xmemdup((const uint8_t*) loaded_addon->ImageBase + sections[UNIFIED_SECTION_DTBAUTO].memory_offset, sections[UNIFIED_SECTION_DTBAUTO].memory_size),
                                        .iov_len = sections[UNIFIED_SECTION_DTBAUTO].memory_size,
                                },
                                .filename = xstrdup16(items[i]),
                        };
                } else if (devicetree_addons && PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTB)) {
                        *devicetree_addons = xrealloc(*devicetree_addons,
                                                      *n_devicetree_addons * sizeof(NamedAddon),
                                                      (*n_devicetree_addons + 1) * sizeof(NamedAddon));

                        (*devicetree_addons)[(*n_devicetree_addons)++] = (NamedAddon) {
                                .blob = {
                                        .iov_base = xmemdup((const uint8_t*) loaded_addon->ImageBase + sections[UNIFIED_SECTION_DTB].memory_offset, sections[UNIFIED_SECTION_DTB].memory_size),
                                        .iov_len = sections[UNIFIED_SECTION_DTB].memory_size,
                                },
                                .filename = xstrdup16(items[i]),
                        };
                }

                if (initrd_addons && PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_INITRD)) {
                        *initrd_addons = xrealloc(*initrd_addons,
                                                  *n_initrd_addons * sizeof(NamedAddon),
                                                  (*n_initrd_addons + 1)  * sizeof(NamedAddon));
                        (*initrd_addons)[(*n_initrd_addons)++] = (NamedAddon) {
                                .blob = {
                                        .iov_base = xmemdup((const uint8_t*) loaded_addon->ImageBase + sections[UNIFIED_SECTION_INITRD].memory_offset, sections[UNIFIED_SECTION_INITRD].memory_size),
                                        .iov_len = sections[UNIFIED_SECTION_INITRD].memory_size,
                                },
                                .filename = xstrdup16(items[i]),
                        };
                }

                if (ucode_addons && PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_UCODE)) {
                        *ucode_addons = xrealloc(*ucode_addons,
                                                 *n_ucode_addons * sizeof(NamedAddon),
                                                 (*n_ucode_addons + 1)  * sizeof(NamedAddon));
                        (*ucode_addons)[(*n_ucode_addons)++] = (NamedAddon) {
                                .blob = {
                                        .iov_base = xmemdup((const uint8_t*) loaded_addon->ImageBase + sections[UNIFIED_SECTION_UCODE].memory_offset, sections[UNIFIED_SECTION_UCODE].memory_size),
                                        .iov_len = sections[UNIFIED_SECTION_UCODE].memory_size,
                                },
                                .filename = xstrdup16(items[i]),
                        };
                }
        }

        return EFI_SUCCESS;
}

static void refresh_random_seed(EFI_LOADED_IMAGE_PROTOCOL *loaded_image) {
        EFI_STATUS err;

        assert(loaded_image);

        /* Handle case, where bootloader doesn't support DeviceHandle. */
        if (!loaded_image->DeviceHandle)
                return;

        /* Don't measure again, if sd-boot already initialized the random seed */
        uint64_t loader_features = 0;
        (void) efivar_get_uint64_le(MAKE_GUID_PTR(LOADER), u"LoaderFeatures", &loader_features);
        if (FLAGS_SET(loader_features, EFI_LOADER_FEATURE_RANDOM_SEED))
                return;

        _cleanup_file_close_ EFI_FILE *esp_dir = NULL;
        err = partition_open(MAKE_GUID_PTR(ESP), loaded_image->DeviceHandle, NULL, &esp_dir);
        if (err != EFI_SUCCESS) /* Non-fatal on failure, so that we still boot without it. */
                return;

        (void) process_random_seed(esp_dir);
}

static void measure_sections(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector sections[static _UNIFIED_SECTION_MAX],
                int *sections_measured) {

        assert(loaded_image);
        assert(sections);
        assert(sections_measured);

        /* Measure all "payload" of this PE image into a separate PCR (i.e. where nothing else is written
         * into so far), so that we have one PCR that we can nicely write policies against because it
         * contains all static data of this image, and thus can be easily be pre-calculated. */
        for (UnifiedSection section = 0; section < _UNIFIED_SECTION_MAX; section++) {

                if (!unified_section_measure(section)) /* shall not measure? */
                        continue;

                if (!PE_SECTION_VECTOR_IS_SET(sections + section)) /* not found */
                        continue;

                /* First measure the name of the section */
                bool m = false;
                (void) tpm_log_ipl_event_ascii(
                                TPM2_PCR_KERNEL_BOOT,
                                POINTER_TO_PHYSICAL_ADDRESS(unified_sections[section]),
                                strsize8(unified_sections[section]), /* including NUL byte */
                                unified_sections[section],
                                &m);
                combine_measured_flag(sections_measured, m);

                /* Then measure the data of the section */
                m = false;
                (void) tpm_log_ipl_event_ascii(
                                TPM2_PCR_KERNEL_BOOT,
                                POINTER_TO_PHYSICAL_ADDRESS(loaded_image->ImageBase) + sections[section].memory_offset,
                                sections[section].memory_size,
                                unified_sections[section],
                                &m);
                combine_measured_flag(sections_measured, m);
        }
}

static void cmdline_append_and_measure_smbios(char16_t **cmdline, int *parameters_measured) {
        assert(cmdline);
        assert(parameters_measured);

        /* SMBIOS OEM Strings data is controlled by the host admin and not covered by the VM attestation, so
         * MUST NOT be trusted when in a confidential VM */
        if (is_confidential_vm())
                return;

        const char *extra = smbios_find_oem_string("io.systemd.stub.kernel-cmdline-extra");
        if (!extra)
                return;

        _cleanup_free_ char16_t *extra16 = mangle_stub_cmdline(xstr8_to_16(extra));
        if (isempty(extra16))
                return;

        /* SMBIOS strings are measured in PCR1, but we also want to measure them in our specific PCR12, as
         * firmware-owned PCRs are very difficult to use as they'll contain unpredictable measurements that
         * are not under control of the machine owner. */
        bool m = false;
        (void) tpm_log_load_options(extra16, &m);
        combine_measured_flag(parameters_measured, m);

        _cleanup_free_ char16_t *tmp = TAKE_PTR(*cmdline);
        if (isempty(tmp))
                *cmdline = TAKE_PTR(extra16);
        else
                *cmdline = xasprintf("%ls %ls", tmp, extra16);
}

static void initrds_free(struct iovec (*initrds)[_INITRD_MAX]) {
        assert(initrds);

        /* Free the dynamic initrds, but leave the non-dynamic ones around */

        for (size_t i = _INITRD_DYNAMIC_FIRST; i < _INITRD_MAX; i++)
                iovec_done((*initrds) + i);
}

static void generate_sidecar_initrds(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                struct iovec initrds[static _INITRD_MAX],
                int *parameters_measured,
                int *sysext_measured,
                int *confext_measured) {

        bool m;

        assert(loaded_image);
        assert(initrds);
        assert(parameters_measured);
        assert(sysext_measured);
        assert(confext_measured);

        if (pack_cpio(loaded_image,
                      /* dropin_dir= */ NULL,
                      u".cred",
                      /* exclude_suffix= */ NULL,
                      ".extra/credentials",
                      /* dir_mode= */ 0500,
                      /* access_mode= */ 0400,
                      /* tpm_pcr= */ TPM2_PCR_KERNEL_CONFIG,
                      u"Credentials initrd",
                      initrds + INITRD_CREDENTIAL,
                      &m) == EFI_SUCCESS)
                combine_measured_flag(parameters_measured, m);

        if (pack_cpio(loaded_image,
                      u"\\loader\\credentials",
                      u".cred",
                      /* exclude_suffix= */ NULL,
                      ".extra/global_credentials",
                      /* dir_mode= */ 0500,
                      /* access_mode= */ 0400,
                      /* tpm_pcr= */ TPM2_PCR_KERNEL_CONFIG,
                      u"Global credentials initrd",
                      initrds + INITRD_GLOBAL_CREDENTIAL,
                      &m) == EFI_SUCCESS)
                combine_measured_flag(parameters_measured, m);

        if (pack_cpio(loaded_image,
                      /* dropin_dir= */ NULL,
                      u".raw",         /* ideally we'd pick up only *.sysext.raw here, but for compat we pick up *.raw instead … */
                      u".confext.raw", /* … but then exclude *.confext.raw again */
                      ".extra/sysext",
                      /* dir_mode= */ 0555,
                      /* access_mode= */ 0444,
                      /* tpm_pcr= */ TPM2_PCR_SYSEXTS,
                      u"System extension initrd",
                      initrds + INITRD_SYSEXT,
                      &m) == EFI_SUCCESS)
                combine_measured_flag(sysext_measured, m);

        if (pack_cpio(loaded_image,
                      /* dropin_dir= */ NULL,
                      u".confext.raw",
                      /* exclude_suffix= */ NULL,
                      ".extra/confext",
                      /* dir_mode= */ 0555,
                      /* access_mode= */ 0444,
                      /* tpm_pcr= */ TPM2_PCR_KERNEL_CONFIG,
                      u"Configuration extension initrd",
                      initrds + INITRD_CONFEXT,
                      &m) == EFI_SUCCESS)
                combine_measured_flag(confext_measured, m);
}

static void generate_embedded_initrds(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector sections[static _UNIFIED_SECTION_MAX],
                struct iovec initrds[static _INITRD_MAX]) {

        static const struct {
                UnifiedSection section;
                size_t initrd_index;
                const char16_t *filename;
        } table[] = {
                /* If the PCR signature was embedded in the PE image, then let's wrap it in a cpio and also pass it
                 * to the kernel, so that it can be read from /.extra/tpm2-pcr-signature.json. Note that this section
                 * is not measured, neither as raw section (see above), nor as cpio (here), because it is the
                 * signature of expected PCR values, i.e. its input are PCR measurements, and hence it shouldn't
                 * itself be input for PCR measurements. */
                { UNIFIED_SECTION_PCRSIG,  INITRD_PCRSIG, u"tpm2-pcr-signature.json"  },

                /* If the public key used for the PCR signatures was embedded in the PE image, then let's
                 * wrap it in a cpio and also pass it to the kernel, so that it can be read from
                 * /.extra/tpm2-pcr-public-key.pem. This section is already measured above, hence we won't
                 * measure the cpio. */
                { UNIFIED_SECTION_PCRPKEY, INITRD_PCRPKEY, u"tpm2-pcr-public-key.pem" },

                /* If we boot a specific profile, let's place the chosen profile in a file that userspace can
                 * make use of this information reasonably. */
                { UNIFIED_SECTION_PROFILE, INITRD_PROFILE, u"profile"                 },

                /* Similar, pass the .osrel section too. Userspace should have this information anyway, but
                 * it's so nicely symmetric to the .profile section which we pass around, and who knows,
                 * maybe this is useful to some. */
                { UNIFIED_SECTION_OSREL,   INITRD_OSREL,   u"os-release"              },
        };

        assert(loaded_image);
        assert(initrds);

        FOREACH_ELEMENT(t, table) {
                if (!PE_SECTION_VECTOR_IS_SET(sections + t->section))
                        continue;

                (void) pack_cpio_literal(
                                (const uint8_t*) loaded_image->ImageBase + sections[t->section].memory_offset,
                                sections[t->section].memory_size,
                                ".extra",
                                t->filename,
                                /* dir_mode= */ 0555,
                                /* access_mode= */ 0444,
                                /* tpm_pcr= */ UINT32_MAX,
                                /* tpm_description= */ NULL,
                                initrds + t->initrd_index,
                                /* ret_measured= */ NULL);
        }
}

static void lookup_embedded_initrds(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector sections[static _UNIFIED_SECTION_MAX],
                struct iovec initrds[static _INITRD_MAX]) {

        assert(loaded_image);
        assert(sections);
        assert(initrds);

        if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_INITRD))
                initrds[INITRD_BASE] = IOVEC_MAKE(
                                (const uint8_t*) loaded_image->ImageBase + sections[UNIFIED_SECTION_INITRD].memory_offset,
                                sections[UNIFIED_SECTION_INITRD].memory_size);

        if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_UCODE))
                initrds[INITRD_UCODE] = IOVEC_MAKE(
                                (const uint8_t*) loaded_image->ImageBase + sections[UNIFIED_SECTION_UCODE].memory_offset,
                                sections[UNIFIED_SECTION_UCODE].memory_size);
}

static void export_pcr_variables(
                int sections_measured,
                int parameters_measured,
                int sysext_measured,
                int confext_measured) {

        /* After we are done with measuring, set an EFI variable that tells userspace this was done
         * successfully, and encode in it which PCR was used. */

        if (sections_measured > 0)
                (void) efivar_set_uint64_str16(MAKE_GUID_PTR(LOADER), u"StubPcrKernelImage", TPM2_PCR_KERNEL_BOOT, 0);
        if (parameters_measured > 0)
                (void) efivar_set_uint64_str16(MAKE_GUID_PTR(LOADER), u"StubPcrKernelParameters", TPM2_PCR_KERNEL_CONFIG, 0);
        if (sysext_measured > 0)
                (void) efivar_set_uint64_str16(MAKE_GUID_PTR(LOADER), u"StubPcrInitRDSysExts", TPM2_PCR_SYSEXTS, 0);
        if (confext_measured > 0)
                (void) efivar_set_uint64_str16(MAKE_GUID_PTR(LOADER), u"StubPcrInitRDConfExts", TPM2_PCR_KERNEL_CONFIG, 0);
}

static void install_embedded_devicetree(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector sections[static _UNIFIED_SECTION_MAX],
                struct devicetree_state *dt_state) {

        EFI_STATUS err;

        assert(loaded_image);
        assert(sections);
        assert(dt_state);

        UnifiedSection section = _UNIFIED_SECTION_MAX;

        /* Use automatically selected DT if available, otherwise go for "normal" one */
        if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTBAUTO))
                section = UNIFIED_SECTION_DTBAUTO;
        else if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTB))
                section = UNIFIED_SECTION_DTB;
        else
                return;

        err = devicetree_install_from_memory(
                        dt_state,
                        (const uint8_t*) loaded_image->ImageBase + sections[section].memory_offset,
                        sections[section].memory_size);
        if (err != EFI_SUCCESS)
                log_error_status(err, "Error loading embedded devicetree, ignoring: %m");
}

static void load_all_addons(
                EFI_HANDLE image,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const char *uname,
                char16_t **cmdline_addons,
                NamedAddon **dt_addons,
                size_t *n_dt_addons,
                NamedAddon **initrd_addons,
                size_t *n_initrd_addons,
                NamedAddon **ucode_addons,
                size_t *n_ucode_addons) {

        EFI_STATUS err;

        assert(loaded_image);
        assert(cmdline_addons);
        assert(dt_addons);
        assert(n_dt_addons);
        assert(initrd_addons);
        assert(n_initrd_addons);
        assert(ucode_addons);
        assert(n_ucode_addons);

        err = load_addons(
                        image,
                        loaded_image,
                        u"\\loader\\addons",
                        uname,
                        cmdline_addons,
                        dt_addons,
                        n_dt_addons,
                        initrd_addons,
                        n_initrd_addons,
                        ucode_addons,
                        n_ucode_addons);
        if (err != EFI_SUCCESS)
                log_error_status(err, "Error loading global addons, ignoring: %m");

        /* Some bootloaders always pass NULL in FilePath, so we need to check for it here. */
        _cleanup_free_ char16_t *dropin_dir = get_extra_dir(loaded_image->FilePath);
        if (!dropin_dir)
                return;

        err = load_addons(
                        image,
                        loaded_image,
                        dropin_dir,
                        uname,
                        cmdline_addons,
                        dt_addons,
                        n_dt_addons,
                        initrd_addons,
                        n_initrd_addons,
                        ucode_addons,
                        n_ucode_addons);
        if (err != EFI_SUCCESS)
                log_error_status(err, "Error loading UKI-specific addons, ignoring: %m");
}

static void display_splash(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector sections[static _UNIFIED_SECTION_MAX]) {

        assert(loaded_image);
        assert(sections);

        if (!PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_SPLASH))
                return;

        graphics_splash((const uint8_t*) loaded_image->ImageBase + sections[UNIFIED_SECTION_SPLASH].memory_offset, sections[UNIFIED_SECTION_SPLASH].memory_size);
}

static EFI_STATUS find_sections(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                unsigned profile,
                PeSectionVector sections[static _UNIFIED_SECTION_MAX]) {

        EFI_STATUS err;

        assert(loaded_image);
        assert(sections);

        const PeSectionHeader *section_table;
        size_t n_section_table;
        err = pe_section_table_from_base(loaded_image->ImageBase, &section_table, &n_section_table);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Unable to locate PE section table: %m");

        /* Get the base sections */
        err = pe_locate_profile_sections(
                        section_table,
                        n_section_table,
                        unified_sections,
                        /* profile= */ UINT_MAX,
                        /* validate_base= */ PTR_TO_SIZE(loaded_image->ImageBase),
                        sections);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Unable to locate embedded base PE sections: %m");

        if (profile != UINT_MAX) {
                /* And then override them with the per-profile sections of the selected profile */
                err = pe_locate_profile_sections(
                                section_table,
                                n_section_table,
                                unified_sections,
                                profile,
                                /* validate_base= */ PTR_TO_SIZE(loaded_image->ImageBase),
                                sections);
                if (err != EFI_SUCCESS && !(err == EFI_NOT_FOUND && profile == 0)) /* the first profile is implied if it doesn't exist */
                        return log_error_status(err, "Unable to locate embedded per-profile PE sections: %m");
        }

        if (!PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_LINUX))
                return log_error_status(EFI_NOT_FOUND, "Image lacks .linux section.");

        return EFI_SUCCESS;
}

static void settle_command_line(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector sections[static _UNIFIED_SECTION_MAX],
                char16_t **cmdline,
                int *parameters_measured) {

        assert(loaded_image);
        assert(sections);
        assert(cmdline);

        /* This determines which command line to use. On input *cmdline contains the custom passed in cmdline
         * if there is any.
         *
         * We'll suppress the custom cmdline if we are in Secure Boot mode, and if either there is already
         * a cmdline baked into the UKI or we are in confidential VM mode. */

        if (!isempty(*cmdline)) {
                if (secure_boot_enabled() && (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_CMDLINE) || is_confidential_vm()))
                        /* Drop the custom cmdline */
                        *cmdline = mfree(*cmdline);
                else {
                        /* Let's measure the passed kernel command line into the TPM. Note that this possibly
                         * duplicates what we already did in the boot menu, if that was already
                         * used. However, since we want the boot menu to support an EFI binary, and want to
                         * this stub to be usable from any boot menu, let's measure things anyway. */
                        bool m = false;
                        (void) tpm_log_load_options(*cmdline, &m);
                        combine_measured_flag(parameters_measured, m);
                }
        }

        /* No cmdline specified? Or suppressed? Then let's take the one from the UKI, if there is any. */
        if (isempty(*cmdline))
                *cmdline = mangle_stub_cmdline(pe_section_to_str16(loaded_image, sections + UNIFIED_SECTION_CMDLINE));
}

static void measure_profile(unsigned profile, int *parameters_measured) {
        if (profile == 0) /* don't measure anything about the default profile */
                return;

        _cleanup_free_ char16_t *s = xasprintf("%u", profile);

        bool m = false;
        (void) tpm_log_tagged_event(
                        TPM2_PCR_KERNEL_CONFIG,
                        POINTER_TO_PHYSICAL_ADDRESS(s),
                        strsize16(s),
                        UKI_PROFILE_EVENT_TAG_ID,
                        s,
                        &m);
        combine_measured_flag(parameters_measured, m);
}

static EFI_STATUS run(EFI_HANDLE image) {
        int sections_measured = -1, parameters_measured = -1, sysext_measured = -1, confext_measured = -1;
        _cleanup_(devicetree_cleanup) struct devicetree_state dt_state = {};
        _cleanup_free_ char16_t *cmdline = NULL, *cmdline_addons = NULL;
        _cleanup_(initrds_free) struct iovec initrds[_INITRD_MAX] = {};
        PeSectionVector sections[ELEMENTSOF(unified_sections)] = {};
        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        _cleanup_free_ char *uname = NULL;
        NamedAddon *dt_addons = NULL, *initrd_addons = NULL, *ucode_addons = NULL;
        size_t n_dt_addons = 0, n_initrd_addons = 0, n_ucode_addons = 0;
        _cleanup_free_ struct iovec *all_initrds = NULL;
        size_t n_all_initrds = 0;
        unsigned profile = 0;
        EFI_STATUS err;

        err = BS->HandleProtocol(image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error getting a LoadedImageProtocol handle: %m");

        /* Pick up the arguments passed to us, split out the prefixing profile parameter, and return the rest
         * as potential command line to use. */
        (void) process_arguments(image, loaded_image, &profile, &cmdline);

        /* Find the sections we want to operate on, both the basic ones, and the one appropriate for the
         * selected profile. */
        err = find_sections(loaded_image, profile, sections);
        if (err != EFI_SUCCESS)
                return err;

        measure_profile(profile, &parameters_measured);
        measure_sections(loaded_image, sections, &sections_measured);

        /* Show splash screen as early as possible, but after measuring it */
        display_splash(loaded_image, sections);

        refresh_random_seed(loaded_image);

        uname = pe_section_to_str8(loaded_image, sections + UNIFIED_SECTION_UNAME);

        /* Let's now check if we actually want to use the command line, measure it if it was passed in. */
        settle_command_line(loaded_image, sections, &cmdline, &parameters_measured);

        /* Now that we have the UKI sections loaded, also load global first and then local (per-UKI)
         * addons. The data is loaded at once, and then used later. */
        CLEANUP_ARRAY(dt_addons, n_dt_addons, named_addon_free_many);
        CLEANUP_ARRAY(initrd_addons, n_initrd_addons, named_addon_free_many);
        CLEANUP_ARRAY(ucode_addons, n_ucode_addons, named_addon_free_many);
        load_all_addons(image, loaded_image, uname, &cmdline_addons, &dt_addons, &n_dt_addons, &initrd_addons, &n_initrd_addons, &ucode_addons, &n_ucode_addons);

        /* If we have any extra command line to add via PE addons, load them now and append, and measure the
         * additions together, after the embedded options, but before the smbios ones, so that the order is
         * reversed from "most hardcoded" to "most dynamic". The global addons are loaded first, and the
         * image-specific ones later, for the same reason. */
        cmdline_append_and_measure_addons(cmdline_addons, &cmdline, &parameters_measured);
        cmdline_append_and_measure_smbios(&cmdline, &parameters_measured);

        export_common_variables(loaded_image);
        export_stub_variables(loaded_image, profile);

        /* First load the base device tree, then fix it up using addons - global first, then per-UKI. */
        install_embedded_devicetree(loaded_image, sections, &dt_state);
        install_addon_devicetrees(&dt_state, dt_addons, n_dt_addons, &parameters_measured);

        /* Generate & find all initrds */
        generate_sidecar_initrds(loaded_image, initrds, &parameters_measured, &sysext_measured, &confext_measured);
        generate_embedded_initrds(loaded_image, sections, initrds);
        lookup_embedded_initrds(loaded_image, sections, initrds);

        /* Add initrds in the right order. Generally, later initrds can overwrite files in earlier ones,
         * except for ucode, where the kernel uses the first matching embedded filename.
         * We want addons to take precedence over the base initrds, so the order is:
         * 1. Ucode addons
         * 2. UKI ucode
         * 3. UKI initrd
         * 4. Generated initrds
         * 5. initrd addons */
        measure_and_append_ucode_addons(&all_initrds, &n_all_initrds, ucode_addons, n_ucode_addons, &parameters_measured);
        extend_initrds(initrds, &all_initrds, &n_all_initrds);
        measure_and_append_initrd_addons(&all_initrds, &n_all_initrds, initrd_addons, n_initrd_addons, &parameters_measured);

        /* Export variables indicating what we measured */
        export_pcr_variables(sections_measured, parameters_measured, sysext_measured, confext_measured);

        /* Combine the initrds into one */
        _cleanup_pages_ Pages initrd_pages = {};
        struct iovec final_initrd;
        if (n_all_initrds > 1) {
                /* There will always be a base initrd, if this counter is higher, we need to combine them */
                err = combine_initrds(all_initrds, n_all_initrds, &initrd_pages, &final_initrd.iov_len);
                if (err != EFI_SUCCESS)
                        return err;

                final_initrd.iov_base = PHYSICAL_ADDRESS_TO_POINTER(initrd_pages.addr);

                /* Given these might be large let's free them explicitly before we pass control to Linux */
                initrds_free(&initrds);
        } else
                final_initrd = all_initrds[0];

        struct iovec kernel = IOVEC_MAKE(
                        (const uint8_t*) loaded_image->ImageBase + sections[UNIFIED_SECTION_LINUX].memory_offset,
                        sections[UNIFIED_SECTION_LINUX].memory_size);

        err = linux_exec(image, cmdline, &kernel, &final_initrd);
        graphics_mode(false);
        return err;
}

DEFINE_EFI_MAIN_FUNCTION(run, "systemd-stub", /* wait_for_debugger= */ false);
