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

        return xstrn8_to_16((const char *) loaded_image->ImageBase + section->memory_offset, section->size);
}

static char *pe_section_to_str8(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector *section) {

        assert(loaded_image);
        assert(section);

        if (!PE_SECTION_VECTOR_IS_SET(section))
                return NULL;

        return xstrndup8((const char *)loaded_image->ImageBase + section->memory_offset, section->size);
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

        _cleanup_pages_ Pages pages = xmalloc_pages(
                        AllocateMaxAddress,
                        EfiLoaderData,
                        EFI_SIZE_TO_PAGES(n),
                        UINT32_MAX /* Below 4G boundary. */);
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

        *ret_initrd_pages = pages;
        *ret_initrd_size = n;
        pages.n_pages = 0;

        return EFI_SUCCESS;
}

static void export_stub_variables(EFI_LOADED_IMAGE_PROTOCOL *loaded_image) {
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
                0;

        assert(loaded_image);

        /* add StubInfo (this is one is owned by the stub, hence we unconditionally override this with our
         * own data) */
        (void) efivar_set_str16(MAKE_GUID_PTR(LOADER), u"StubInfo", u"systemd-stub " GIT_VERSION, 0);

        (void) efivar_set_uint64_le(MAKE_GUID_PTR(LOADER), u"StubFeatures", stub_features, 0);
}

static bool use_load_options(
                EFI_HANDLE stub_image,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                bool have_cmdline,
                char16_t **ret) {

        assert(stub_image);
        assert(loaded_image);
        assert(ret);

        /* We only allow custom command lines if we aren't in secure boot or if no cmdline was baked into
         * the stub image.
         * We also don't allow it if we are in confidential vms and secureboot is on. */
        if (secure_boot_enabled() && (have_cmdline || is_confidential_vm()))
                return false;

        /* The UEFI shell registers EFI_SHELL_PARAMETERS_PROTOCOL onto images it runs. This lets us know that
         * LoadOptions starts with the stub binary path which we want to strip off. */
        EFI_SHELL_PARAMETERS_PROTOCOL *shell;
        if (BS->HandleProtocol(stub_image, MAKE_GUID_PTR(EFI_SHELL_PARAMETERS_PROTOCOL), (void **) &shell) != EFI_SUCCESS) {

                /* We also do a superficial check whether first character of passed command line
                 * is printable character (for compat with some Dell systems which fill in garbage?). */
                if (loaded_image->LoadOptionsSize < sizeof(char16_t) || ((const char16_t *) loaded_image->LoadOptions)[0] <= 0x1F)
                        return false;

                /* Not running from EFI shell, use entire LoadOptions. Note that LoadOptions is a void*, so
                 * it could be anything! */
                *ret = mangle_stub_cmdline(xstrndup16(loaded_image->LoadOptions, loaded_image->LoadOptionsSize / sizeof(char16_t)));
                return true;
        }

        if (shell->Argc < 2)
                /* No arguments were provided? Then we fall back to built-in cmdline. */
                return false;

        /* Assemble the command line ourselves without our stub path. */
        *ret = xstrdup16(shell->Argv[1]);
        for (size_t i = 2; i < shell->Argc; i++) {
                _cleanup_free_ char16_t *old = *ret;
                *ret = xasprintf("%ls %ls", old, shell->Argv[i]);
        }

        return true;
}

static EFI_STATUS load_addons_from_dir(
                EFI_FILE *root,
                const char16_t *prefix,
                char16_t ***items,
                size_t *n_items,
                size_t *n_allocated) {

        _cleanup_(file_closep) EFI_FILE *extra_dir = NULL;
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
                NamedAddon **ucode_addons,                  /* Ditto */
                size_t *n_ucode_addons) {

        _cleanup_(strv_freep) char16_t **items = NULL;
        _cleanup_(file_closep) EFI_FILE *root = NULL;
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
                     !PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_UCODE))) {
                        if (err == EFI_SUCCESS)
                                err = EFI_NOT_FOUND;
                        log_error_status(err,
                                         "Unable to locate embedded .cmdline/.dtb/.ucode sections in %ls, ignoring: %m",
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
                                         sections[UNIFIED_SECTION_UNAME].size)) {
                        log_error(".uname mismatch between %ls and UKI, ignoring", items[i]);
                        continue;
                }

                if (cmdline && PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_CMDLINE)) {
                        _cleanup_free_ char16_t *tmp = TAKE_PTR(*cmdline),
                                *extra16 = mangle_stub_cmdline(pe_section_to_str16(loaded_addon, sections + UNIFIED_SECTION_CMDLINE));

                        *cmdline = xasprintf("%ls%ls%ls", strempty(tmp), isempty(tmp) ? u"" : u" ", extra16);
                }

                if (devicetree_addons && PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTB)) {
                        *devicetree_addons = xrealloc(*devicetree_addons,
                                                      *n_devicetree_addons * sizeof(NamedAddon),
                                                      (*n_devicetree_addons + 1) * sizeof(NamedAddon));

                        (*devicetree_addons)[(*n_devicetree_addons)++] = (NamedAddon) {
                                .blob = {
                                        .iov_base = xmemdup((const uint8_t*) loaded_addon->ImageBase + sections[UNIFIED_SECTION_DTB].memory_offset, sections[UNIFIED_SECTION_DTB].size),
                                        .iov_len = sections[UNIFIED_SECTION_DTB].size,
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
                                        .iov_base = xmemdup((const uint8_t*) loaded_addon->ImageBase + sections[UNIFIED_SECTION_UCODE].memory_offset, sections[UNIFIED_SECTION_UCODE].size),
                                        .iov_len = sections[UNIFIED_SECTION_UCODE].size,
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

        uint64_t loader_features = 0;
        err = efivar_get_uint64_le(MAKE_GUID_PTR(LOADER), u"LoaderFeatures", &loader_features);
        if (err != EFI_SUCCESS)
                return;

        /* Don't measure again, if sd-boot already initialized the random seed */
        if (!FLAGS_SET(loader_features, EFI_LOADER_FEATURE_RANDOM_SEED))
                return;

        _cleanup_(file_closep) EFI_FILE *esp_dir = NULL;
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
                                sections[section].size,
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
                      initrds + INITRD_CONFEXT,
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
                      initrds + INITRD_SYSEXT,
                      &m) == EFI_SUCCESS)
                combine_measured_flag(confext_measured, m);
}

static void generate_embedded_initrds(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector sections[static _UNIFIED_SECTION_MAX],
                struct iovec initrds[static _INITRD_MAX]) {

        assert(loaded_image);
        assert(initrds);

        /* If the PCR signature was embedded in the PE image, then let's wrap it in a cpio and also pass it
         * to the kernel, so that it can be read from /.extra/tpm2-pcr-signature.json. Note that this section
         * is not measured, neither as raw section (see above), nor as cpio (here), because it is the
         * signature of expected PCR values, i.e. its input are PCR measurements, and hence it shouldn't
         * itself be input for PCR measurements. */
        if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_PCRSIG))
                (void) pack_cpio_literal(
                                (const uint8_t*) loaded_image->ImageBase + sections[UNIFIED_SECTION_PCRSIG].memory_offset,
                                sections[UNIFIED_SECTION_PCRSIG].size,
                                ".extra",
                                u"tpm2-pcr-signature.json",
                                /* dir_mode= */ 0555,
                                /* access_mode= */ 0444,
                                /* tpm_pcr= */ UINT32_MAX,
                                /* tpm_description= */ NULL,
                                initrds + INITRD_PCRSIG,
                                /* ret_measured= */ NULL);

        /* If the public key used for the PCR signatures was embedded in the PE image, then let's wrap it in
         * a cpio and also pass it to the kernel, so that it can be read from
         * /.extra/tpm2-pcr-public-key.pem. This section is already measure above, hence we won't measure the
         * cpio. */
        if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_PCRPKEY))
                (void) pack_cpio_literal(
                                (const uint8_t*) loaded_image->ImageBase + sections[UNIFIED_SECTION_PCRPKEY].memory_offset,
                                sections[UNIFIED_SECTION_PCRPKEY].size,
                                ".extra",
                                u"tpm2-pcr-public-key.pem",
                                /* dir_mode= */ 0555,
                                /* access_mode= */ 0444,
                                /* tpm_pcr= */ UINT32_MAX,
                                /* tpm_description= */ NULL,
                                initrds + INITRD_PCRPKEY,
                                /* ret_measured= */ NULL);
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
                                sections[UNIFIED_SECTION_INITRD].size);

        if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_UCODE))
                initrds[INITRD_UCODE] = IOVEC_MAKE(
                                (const uint8_t*) loaded_image->ImageBase + sections[UNIFIED_SECTION_UCODE].memory_offset,
                                sections[UNIFIED_SECTION_UCODE].size);
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

        if (!PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTB))
                return;

        err = devicetree_install_from_memory(
                        dt_state,
                        (const uint8_t*) loaded_image->ImageBase + sections[UNIFIED_SECTION_DTB].memory_offset,
                        sections[UNIFIED_SECTION_DTB].size);
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
                NamedAddon **ucode_addons,
                size_t *n_ucode_addons) {

        EFI_STATUS err;

        assert(loaded_image);
        assert(cmdline_addons);
        assert(dt_addons);
        assert(n_dt_addons);
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

        graphics_splash((const uint8_t*) loaded_image->ImageBase + sections[UNIFIED_SECTION_SPLASH].memory_offset, sections[UNIFIED_SECTION_SPLASH].size);
}

static void determine_cmdline(
                EFI_HANDLE image,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector sections[static _UNIFIED_SECTION_MAX],
                char16_t **ret_cmdline,
                int *parameters_measured) {

        assert(loaded_image);
        assert(sections);

        if (use_load_options(image, loaded_image, /* have_cmdline= */ PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_CMDLINE), ret_cmdline)) {
                /* Let's measure the passed kernel command line into the TPM. Note that this possibly
                 * duplicates what we already did in the boot menu, if that was already used. However, since
                 * we want the boot menu to support an EFI binary, and want to this stub to be usable from
                 * any boot menu, let's measure things anyway. */
                bool m = false;
                (void) tpm_log_load_options(*ret_cmdline, &m);
                combine_measured_flag(parameters_measured, m);
        } else
                *ret_cmdline = mangle_stub_cmdline(pe_section_to_str16(loaded_image, sections + UNIFIED_SECTION_CMDLINE));
}

static EFI_STATUS run(EFI_HANDLE image) {
        int sections_measured = -1, parameters_measured = -1, sysext_measured = -1, confext_measured = -1;
        _cleanup_(devicetree_cleanup) struct devicetree_state dt_state = {};
        _cleanup_free_ char16_t *cmdline = NULL, *cmdline_addons = NULL;
        _cleanup_(initrds_free) struct iovec initrds[_INITRD_MAX] = {};
        PeSectionVector sections[ELEMENTSOF(unified_sections)] = {};
        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        _cleanup_free_ char *uname = NULL;
        NamedAddon *dt_addons = NULL, *ucode_addons = NULL;
        size_t n_dt_addons = 0, n_ucode_addons = 0;
        _cleanup_free_ struct iovec *all_initrds = NULL;
        size_t n_all_initrds = 0;
        EFI_STATUS err;

        err = BS->HandleProtocol(image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error getting a LoadedImageProtocol handle: %m");

        err = pe_memory_locate_sections(loaded_image->ImageBase, unified_sections, sections);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Unable to locate embedded PE sections: %m");
        if (!PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_LINUX))
                return log_error_status(EFI_NOT_FOUND, "Image lacks .linux section.");

        measure_sections(loaded_image, sections, &sections_measured);

        /* Show splash screen as early as possible, but after measuring it */
        display_splash(loaded_image, sections);

        refresh_random_seed(loaded_image);

        uname = pe_section_to_str8(loaded_image, sections + UNIFIED_SECTION_UNAME);

        determine_cmdline(image, loaded_image, sections, &cmdline, &parameters_measured);

        /* Now that we have the UKI sections loaded, also load global first and then local (per-UKI)
         * addons. The data is loaded at once, and then used later. */
        CLEANUP_ARRAY(dt_addons, n_dt_addons, named_addon_free_many);
        CLEANUP_ARRAY(ucode_addons, n_ucode_addons, named_addon_free_many);
        load_all_addons(image, loaded_image, uname, &cmdline_addons, &dt_addons, &n_dt_addons, &ucode_addons, &n_ucode_addons);

        /* If we have any extra command line to add via PE addons, load them now and append, and measure the
         * additions together, after the embedded options, but before the smbios ones, so that the order is
         * reversed from "most hardcoded" to "most dynamic". The global addons are loaded first, and the
         * image-specific ones later, for the same reason. */
        cmdline_append_and_measure_addons(cmdline_addons, &cmdline, &parameters_measured);
        cmdline_append_and_measure_smbios(&cmdline, &parameters_measured);

        export_common_variables(loaded_image);
        export_stub_variables(loaded_image);

        /* First load the base device tree, then fix it up using addons - global first, then per-UKI. */
        install_embedded_devicetree(loaded_image, sections, &dt_state);
        install_addon_devicetrees(&dt_state, dt_addons, n_dt_addons, &parameters_measured);

        /* Generate & find all initrds */
        generate_sidecar_initrds(loaded_image, initrds, &parameters_measured, &sysext_measured, &confext_measured);
        generate_embedded_initrds(loaded_image, sections, initrds);
        lookup_embedded_initrds(loaded_image, sections, initrds);

        /* Measures ucode addons and puts them into all_initrds */
        measure_and_append_ucode_addons(&all_initrds, &n_all_initrds, ucode_addons, n_ucode_addons, &parameters_measured);
        /* Adds all other initrds to all_initrds */
        extend_initrds(initrds, &all_initrds, &n_all_initrds);

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
                        sections[UNIFIED_SECTION_LINUX].size);

        err = linux_exec(image, cmdline, &kernel, &final_initrd);
        graphics_mode(false);
        return err;
}

DEFINE_EFI_MAIN_FUNCTION(run, "systemd-stub", /* wait_for_debugger= */ false);
