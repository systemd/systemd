/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cpio.h"
#include "device-path-util.h"
#include "devicetree.h"
#include "graphics.h"
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

/* magic string to find in the binary image */
DECLARE_NOALLOC_SECTION(".sdmagic", "#### LoaderInfo: systemd-stub " GIT_VERSION " ####");

DECLARE_SBAT(SBAT_STUB_SECTION_TEXT);

static EFI_STATUS combine_initrd(
                EFI_PHYSICAL_ADDRESS initrd_base, size_t initrd_size,
                const void * const extra_initrds[], const size_t extra_initrd_sizes[], size_t n_extra_initrds,
                Pages *ret_initr_pages, size_t *ret_initrd_size) {

        size_t n;

        assert(ret_initr_pages);
        assert(ret_initrd_size);

        /* Combines four initrds into one, by simple concatenation in memory */

        n = ALIGN4(initrd_size); /* main initrd might not be padded yet */

        for (size_t i = 0; i < n_extra_initrds; i++) {
                if (!extra_initrds[i])
                        continue;

                if (n > SIZE_MAX - extra_initrd_sizes[i])
                        return EFI_OUT_OF_RESOURCES;

                n += extra_initrd_sizes[i];
        }

        _cleanup_pages_ Pages pages = xmalloc_pages(
                        AllocateMaxAddress,
                        EfiLoaderData,
                        EFI_SIZE_TO_PAGES(n),
                        UINT32_MAX /* Below 4G boundary. */);
        uint8_t *p = PHYSICAL_ADDRESS_TO_POINTER(pages.addr);
        if (initrd_base != 0) {
                size_t pad;

                /* Order matters, the real initrd must come first, since it might include microcode updates
                 * which the kernel only looks for in the first cpio archive */
                p = mempcpy(p, PHYSICAL_ADDRESS_TO_POINTER(initrd_base), initrd_size);

                pad = ALIGN4(initrd_size) - initrd_size;
                if (pad > 0)  {
                        memzero(p, pad);
                        p += pad;
                }
        }

        for (size_t i = 0; i < n_extra_initrds; i++) {
                if (!extra_initrds[i])
                        continue;

                p = mempcpy(p, extra_initrds[i], extra_initrd_sizes[i]);
        }

        assert(PHYSICAL_ADDRESS_TO_POINTER(pages.addr + n) == p);

        *ret_initr_pages = pages;
        *ret_initrd_size = n;
        pages.n_pages = 0;

        return EFI_SUCCESS;
}

static void export_variables(EFI_LOADED_IMAGE_PROTOCOL *loaded_image) {
        static const uint64_t stub_features =
                EFI_STUB_FEATURE_REPORT_BOOT_PARTITION |    /* We set LoaderDevicePartUUID */
                EFI_STUB_FEATURE_PICK_UP_CREDENTIALS |      /* We pick up credentials from the boot partition */
                EFI_STUB_FEATURE_PICK_UP_SYSEXTS |          /* We pick up system extensions from the boot partition */
                EFI_STUB_FEATURE_THREE_PCRS |               /* We can measure kernel image, parameters and sysext */
                EFI_STUB_FEATURE_RANDOM_SEED |              /* We pass a random seed to the kernel */
                EFI_STUB_FEATURE_CMDLINE_ADDONS |           /* We pick up .cmdline addons */
                EFI_STUB_FEATURE_CMDLINE_SMBIOS |           /* We support extending kernel cmdline from SMBIOS Type #11 */
                EFI_STUB_FEATURE_DEVICETREE_ADDONS |        /* We pick up .dtb addons */
                0;

        assert(loaded_image);

        /* Export the device path this image is started from, if it's not set yet */
        if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderDevicePartUUID", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_free_ char16_t *uuid = disk_get_part_uuid(loaded_image->DeviceHandle);
                if (uuid)
                        efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderDevicePartUUID", uuid, 0);
        }

        /* If LoaderImageIdentifier is not set, assume the image with this stub was loaded directly from the
         * UEFI firmware without any boot loader, and hence set the LoaderImageIdentifier ourselves. Note
         * that some boot chain loaders neither set LoaderImageIdentifier nor make FilePath available to us,
         * in which case there's simple nothing to set for us. (The UEFI spec doesn't really say who's wrong
         * here, i.e. whether FilePath may be NULL or not, hence handle this gracefully and check if FilePath
         * is non-NULL explicitly.) */
        if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderImageIdentifier", NULL, NULL) != EFI_SUCCESS &&
            loaded_image->FilePath) {
                _cleanup_free_ char16_t *s = NULL;
                if (device_path_to_str(loaded_image->FilePath, &s) == EFI_SUCCESS)
                        efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderImageIdentifier", s, 0);
        }

        /* if LoaderFirmwareInfo is not set, let's set it */
        if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareInfo", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_free_ char16_t *s = NULL;
                s = xasprintf("%ls %u.%02u", ST->FirmwareVendor, ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
                efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareInfo", s, 0);
        }

        /* ditto for LoaderFirmwareType */
        if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareType", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_free_ char16_t *s = NULL;
                s = xasprintf("UEFI %u.%02u", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
                efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareType", s, 0);
        }


        /* add StubInfo (this is one is owned by the stub, hence we unconditionally override this with our
         * own data) */
        (void) efivar_set(MAKE_GUID_PTR(LOADER), u"StubInfo", u"systemd-stub " GIT_VERSION, 0);

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

        /* We also do a superficial check whether first character of passed command line
         * is printable character (for compat with some Dell systems which fill in garbage?). */
        if (loaded_image->LoadOptionsSize < sizeof(char16_t) || ((char16_t *) loaded_image->LoadOptions)[0] <= 0x1F)
                return false;

        /* The UEFI shell registers EFI_SHELL_PARAMETERS_PROTOCOL onto images it runs. This lets us know that
         * LoadOptions starts with the stub binary path which we want to strip off. */
        EFI_SHELL_PARAMETERS_PROTOCOL *shell;
        if (BS->HandleProtocol(stub_image, MAKE_GUID_PTR(EFI_SHELL_PARAMETERS_PROTOCOL), (void **) &shell)
            != EFI_SUCCESS) {
                /* Not running from EFI shell, use entire LoadOptions. Note that LoadOptions is a void*, so
                 * it could be anything! */
                *ret = xstrndup16(loaded_image->LoadOptions, loaded_image->LoadOptionsSize / sizeof(char16_t));
                mangle_stub_cmdline(*ret);
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

        mangle_stub_cmdline(*ret);
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
                char16_t *cmdline_global,
                char16_t *cmdline_uki,
                char16_t **cmdline_append,
                bool *ret_parameters_measured) {

        _cleanup_free_ char16_t *tmp = NULL, *merged = NULL;
        bool m = false;

        assert(cmdline_append);
        assert(ret_parameters_measured);

        if (isempty(cmdline_global) && isempty(cmdline_uki))
                return;

        merged = xasprintf("%ls%ls%ls",
                           strempty(cmdline_global),
                           isempty(cmdline_global) || isempty(cmdline_uki) ? u"" : u" ",
                           strempty(cmdline_uki));

        mangle_stub_cmdline(merged);

        if (isempty(merged))
                return;

        (void) tpm_log_load_options(merged, &m);
        *ret_parameters_measured = m;

        tmp = TAKE_PTR(*cmdline_append);
        *cmdline_append = xasprintf("%ls%ls%ls", strempty(tmp), isempty(tmp) ? u"" : u" ", merged);
}

static void dtb_measure_addons(
                struct devicetree_state *dt_state,
                void **dt_bases,
                size_t *dt_sizes,
                char16_t **dt_filenames,
                size_t n_dts,
                bool *ret_parameters_measured) {

        int parameters_measured = -1;
        EFI_STATUS err;

        assert(dt_state);
        assert(n_dts == 0 || (dt_bases && dt_sizes && dt_filenames));
        assert(ret_parameters_measured);

        for (size_t i = 0; i < n_dts; ++i) {
                bool m = false;

                err = tpm_log_tagged_event(
                                TPM2_PCR_KERNEL_CONFIG,
                                POINTER_TO_PHYSICAL_ADDRESS(dt_bases[i]),
                                dt_sizes[i],
                                DEVICETREE_ADDON_EVENT_TAG_ID,
                                dt_filenames[i],
                                &m);
                if (err != EFI_SUCCESS)
                        return (void) log_error_status(
                                        err,
                                        "Unable to add measurement of DTB addon #%zu to PCR %i: %m",
                                        i,
                                        TPM2_PCR_KERNEL_CONFIG);

                parameters_measured = parameters_measured < 0 ? m : (parameters_measured && m);
        }

        *ret_parameters_measured = parameters_measured;
}

static void dt_bases_free(void **dt_bases, size_t n_dt) {
        assert(dt_bases || n_dt == 0);

        for (size_t i = 0; i < n_dt; ++i)
                free(dt_bases[i]);

        free(dt_bases);
}

static void dt_filenames_free(char16_t **dt_filenames, size_t n_dt) {
        assert(dt_filenames || n_dt == 0);

        for (size_t i = 0; i < n_dt; ++i)
                free(dt_filenames[i]);

        free(dt_filenames);
}

static EFI_STATUS load_addons(
                EFI_HANDLE stub_image,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const char16_t *prefix,
                const char *uname,
                char16_t **ret_cmdline,
                void ***ret_dt_bases,
                size_t **ret_dt_sizes,
                char16_t ***ret_dt_filenames,
                size_t *ret_n_dt) {

        _cleanup_free_ size_t *dt_sizes = NULL;
        _cleanup_(strv_freep) char16_t **items = NULL;
        _cleanup_(file_closep) EFI_FILE *root = NULL;
        _cleanup_free_ char16_t *cmdline = NULL;
        size_t n_items = 0, n_allocated = 0, n_dt = 0;
        char16_t **dt_filenames = NULL;
        void **dt_bases = NULL;
        EFI_STATUS err;

        assert(stub_image);
        assert(loaded_image);
        assert(prefix);
        assert(!!ret_dt_bases == !!ret_dt_sizes);
        assert(!!ret_dt_bases == !!ret_n_dt);
        assert(!!ret_dt_filenames == !!ret_n_dt);

        if (!loaded_image->DeviceHandle)
                return EFI_SUCCESS;

        CLEANUP_ARRAY(dt_bases, n_dt, dt_bases_free);
        CLEANUP_ARRAY(dt_filenames, n_dt, dt_filenames_free);

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
        sort_array((void *) items, sizeof *items, n_items, (compare_func_t) strcmp16_indirect);

        for (size_t i = 0; i < n_items; i++) {
                _cleanup_free_ PeSectionDescriptor *sections = NULL;
                size_t n_sections;
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

                err = pe_memory_locate_sections(loaded_addon->ImageBase, &sections, &n_sections);
                if (err != EFI_SUCCESS ||
                    (!pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_CMDLINE) &&
                        !pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_DTB))) {
                        if (err == EFI_SUCCESS)
                                err = EFI_NOT_FOUND;
                        log_error_status(err,
                                         "Unable to locate embedded .cmdline/.dtb sections in %ls, ignoring: %m",
                                         items[i]);
                        continue;
                }

                /* We want to enforce that addons are not UKIs, i.e.: they must not embed a kernel. */
                if (pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_LINUX)) {
                        log_error_status(EFI_INVALID_PARAMETER, "%ls is a UKI, not an addon, ignoring: %m", items[i]);
                        continue;
                }

                /* Also enforce that, in case it is specified, .uname matches as a quick way to allow
                 * enforcing compatibility with a specific UKI only */
                if (uname) {
                        PeSectionDescriptor *section_uname = pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_UNAME);
                        if (section_uname && strneq8(uname, (char *)loaded_addon->ImageBase + section_uname->offset, section_uname->size) == 0) {
                                log_error(".uname mismatch between %ls and UKI, ignoring", items[i]);
                                continue;
                        }
                }

                if (ret_cmdline) {
                        PeSectionDescriptor *section_cmdline = pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_CMDLINE);
                        if (section_cmdline) {
                                _cleanup_free_ char16_t *tmp = TAKE_PTR(cmdline),
                                                        *extra16 = xstrn8_to_16((char *)loaded_addon->ImageBase + section_cmdline->offset,
                                                                                section_cmdline->size);
                                cmdline = xasprintf("%ls%ls%ls", strempty(tmp), isempty(tmp) ? u"" : u" ", extra16);
                        }
                }

                if (ret_dt_bases) {
                        PeSectionDescriptor *section_dtb = pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_DTB);
                        for (; section_dtb && section_dtb < sections + n_sections && streq8(section_dtb->name, ".dtb"); ++section_dtb) {
                                dt_sizes = xrealloc(dt_sizes,
                                                    n_dt * sizeof(size_t),
                                                    (n_dt + 1)  * sizeof(size_t));
                                dt_sizes[n_dt] = section_dtb->size;

                                dt_bases = xrealloc(dt_bases,
                                                    n_dt * sizeof(void *),
                                                    (n_dt + 1) * sizeof(void *));
                                dt_bases[n_dt] = xmemdup((uint8_t*)loaded_addon->ImageBase + section_dtb->offset,
                                                         dt_sizes[n_dt]);

                                dt_filenames = xrealloc(dt_filenames,
                                                        n_dt * sizeof(char16_t *),
                                                        (n_dt + 1) * sizeof(char16_t *));
                                dt_filenames[n_dt] = xstrdup16(items[i]);

                                ++n_dt;
                        }
                }
        }

        if (ret_cmdline && !isempty(cmdline))
                *ret_cmdline = TAKE_PTR(cmdline);

        if (ret_n_dt && n_dt > 0) {
                *ret_dt_filenames = TAKE_PTR(dt_filenames);
                *ret_dt_bases = TAKE_PTR(dt_bases);
                *ret_dt_sizes = TAKE_PTR(dt_sizes);
                *ret_n_dt = n_dt;
        }

        return EFI_SUCCESS;
}

static EFI_STATUS run(EFI_HANDLE image) {
        _cleanup_free_ void *credential_initrd = NULL, *global_credential_initrd = NULL, *sysext_initrd = NULL, *pcrsig_initrd = NULL, *pcrpkey_initrd = NULL;
        size_t credential_initrd_size = 0, global_credential_initrd_size = 0, sysext_initrd_size = 0, pcrsig_initrd_size = 0, pcrpkey_initrd_size = 0;
        void **dt_bases_addons_global = NULL, **dt_bases_addons_uki = NULL;
        char16_t **dt_filenames_addons_global = NULL, **dt_filenames_addons_uki = NULL;
        _cleanup_free_ size_t *dt_sizes_addons_global = NULL, *dt_sizes_addons_uki = NULL;
        size_t linux_size, initrd_size = 0, n_dts_addons_global = 0, n_dts_addons_uki = 0, n_sections;
        EFI_PHYSICAL_ADDRESS linux_base, initrd_base = 0;
        _cleanup_(devicetree_cleanup) struct devicetree_state dt_state = {};
        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        _cleanup_free_ PeSectionDescriptor *sections = NULL;
        _cleanup_free_ char16_t *cmdline = NULL, *cmdline_addons_global = NULL, *cmdline_addons_uki = NULL;
        int sections_measured = -1, parameters_measured = -1;
        _cleanup_free_ char *uname = NULL;
        bool sysext_measured = false, m;
        uint64_t loader_features = 0;
        EFI_STATUS err;

        err = BS->HandleProtocol(image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error getting a LoadedImageProtocol handle: %m");

        if (loaded_image->DeviceHandle && /* Handle case, where bootloader doesn't support DeviceHandle. */
            (efivar_get_uint64_le(MAKE_GUID_PTR(LOADER), u"LoaderFeatures", &loader_features) != EFI_SUCCESS ||
            !FLAGS_SET(loader_features, EFI_LOADER_FEATURE_RANDOM_SEED))) {
                _cleanup_(file_closep) EFI_FILE *esp_dir = NULL;

                err = partition_open(MAKE_GUID_PTR(ESP), loaded_image->DeviceHandle, NULL, &esp_dir);
                if (err == EFI_SUCCESS) /* Non-fatal on failure, so that we still boot without it. */
                        (void) process_random_seed(esp_dir);
        }

        err = pe_memory_locate_sections(loaded_image->ImageBase, &sections, &n_sections);
        if (err != EFI_SUCCESS || !pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_LINUX)) {
                if (err == EFI_SUCCESS)
                        err = EFI_NOT_FOUND;
                return log_error_status(err, "Unable to locate embedded .linux section: %m");
        }

        CLEANUP_ARRAY(dt_bases_addons_global, n_dts_addons_global, dt_bases_free);
        CLEANUP_ARRAY(dt_bases_addons_uki, n_dts_addons_uki, dt_bases_free);
        CLEANUP_ARRAY(dt_filenames_addons_global, n_dts_addons_global, dt_filenames_free);
        CLEANUP_ARRAY(dt_filenames_addons_uki, n_dts_addons_uki, dt_filenames_free);

        /* Now that we have the UKI sections loaded, also load global first and then local (per-UKI)
         * addons. The data is loaded at once, and then used later. */
        err = load_addons(
                        image,
                        loaded_image,
                        u"\\loader\\addons",
                        uname,
                        &cmdline_addons_global,
                        &dt_bases_addons_global,
                        &dt_sizes_addons_global,
                        &dt_filenames_addons_global,
                        &n_dts_addons_global);
        if (err != EFI_SUCCESS)
                log_error_status(err, "Error loading global addons, ignoring: %m");

        /* Some bootloaders always pass NULL in FilePath, so we need to check for it here. */
        _cleanup_free_ char16_t *dropin_dir = get_extra_dir(loaded_image->FilePath);
        if (dropin_dir) {
                err = load_addons(
                                image,
                                loaded_image,
                                dropin_dir,
                                uname,
                                &cmdline_addons_uki,
                                &dt_bases_addons_uki,
                                &dt_sizes_addons_uki,
                                &dt_filenames_addons_uki,
                                &n_dts_addons_uki);
                if (err != EFI_SUCCESS)
                        log_error_status(err, "Error loading UKI-specific addons, ignoring: %m");
        }

        /* Measure all "payload" of this PE image into a separate PCR (i.e. where nothing else is written
         * into so far), so that we have one PCR that we can nicely write policies against because it
         * contains all static data of this image, and thus can be easily be pre-calculated. */
        for (UnifiedSection unified_section = 0; unified_section < _UNIFIED_SECTION_MAX; unified_section++) {

                if (!unified_section_measure(unified_section)) /* shall not measure? */
                        continue;

                PeSectionDescriptor *section = pe_find_unified_section(sections, n_sections, unified_section);
                if (unified_section == UNIFIED_SECTION_DTB) {
                        for (; section && section < sections + n_sections && streq8(section->name, ".dtb"); ++section) {
                                m = false;

                                /* First measure the name of the section */
                                (void) tpm_log_event_ascii(
                                                TPM2_PCR_KERNEL_BOOT,
                                                POINTER_TO_PHYSICAL_ADDRESS(section->name),
                                                strsize8(section->name), /* including NUL byte */
                                                section->name,
                                                &m);

                                sections_measured = sections_measured < 0 ? m : (sections_measured && m);

                                /* Then measure the data of the section */
                                (void) tpm_log_event_ascii(
                                                TPM2_PCR_KERNEL_BOOT,
                                                POINTER_TO_PHYSICAL_ADDRESS(loaded_image->ImageBase) + section->offset,
                                                section->size,
                                                section->name,
                                                &m);

                                sections_measured = sections_measured < 0 ? m : (sections_measured && m);
                        }
                } else if (section) {
                        m = false;

                        /* First measure the name of the section */
                        (void) tpm_log_event_ascii(
                                        TPM2_PCR_KERNEL_BOOT,
                                        POINTER_TO_PHYSICAL_ADDRESS(section->name),
                                        strsize8(section->name), /* including NUL byte */
                                        section->name,
                                        &m);

                        sections_measured = sections_measured < 0 ? m : (sections_measured && m);

                        /* Then measure the data of the section */
                        (void) tpm_log_event_ascii(
                                        TPM2_PCR_KERNEL_BOOT,
                                        POINTER_TO_PHYSICAL_ADDRESS(loaded_image->ImageBase) + section->offset,
                                        section->size,
                                        section->name,
                                        &m);

                        sections_measured = sections_measured < 0 ? m : (sections_measured && m);
                }
        }

        /* After we are done, set an EFI variable that tells userspace this was done successfully, and encode
         * in it which PCR was used. */
        if (sections_measured > 0)
                (void) efivar_set_uint_string(MAKE_GUID_PTR(LOADER), u"StubPcrKernelImage", TPM2_PCR_KERNEL_BOOT, 0);

        /* Show splash screen as early as possible */
        PeSectionDescriptor *section_splash = pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_SPLASH);
        if (section_splash)
                graphics_splash((const uint8_t*) loaded_image->ImageBase + section_splash->offset, section_splash->size);

        PeSectionDescriptor *section_uname = pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_UNAME);
        if (section_uname)
                uname = xstrndup8((char *)loaded_image->ImageBase + section_uname->offset,
                                  section_uname->size);

        PeSectionDescriptor *section_cmdline = pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_CMDLINE);
        if (use_load_options(image, loaded_image, section_cmdline != NULL, &cmdline)) {
                /* Let's measure the passed kernel command line into the TPM. Note that this possibly
                 * duplicates what we already did in the boot menu, if that was already used. However, since
                 * we want the boot menu to support an EFI binary, and want to this stub to be usable from
                 * any boot menu, let's measure things anyway. */
                m = false;
                (void) tpm_log_load_options(cmdline, &m);
                parameters_measured = m;
        } else if (section_cmdline) {
                cmdline = xstrn8_to_16(
                                (char *) loaded_image->ImageBase + section_cmdline->offset,
                                section_cmdline->size);
                mangle_stub_cmdline(cmdline);
        }

        /* If we have any extra command line to add via PE addons, load them now and append, and
         * measure the additions together, after the embedded options, but before the smbios ones,
         * so that the order is reversed from "most hardcoded" to "most dynamic". The global addons are
         * loaded first, and the image-specific ones later, for the same reason. */
        cmdline_append_and_measure_addons(cmdline_addons_global, cmdline_addons_uki, &cmdline, &m);
        parameters_measured = parameters_measured < 0 ? m : (parameters_measured && m);

        /* SMBIOS OEM Strings data is controlled by the host admin and not covered
         * by the VM attestation, so MUST NOT be trusted when in a confidential VM */
        if (!is_confidential_vm()) {
                const char *extra = smbios_find_oem_string("io.systemd.stub.kernel-cmdline-extra");
                if (extra) {
                        _cleanup_free_ char16_t *tmp = TAKE_PTR(cmdline), *extra16 = xstr8_to_16(extra);
                        cmdline = xasprintf("%ls %ls", tmp, extra16);

                        /* SMBIOS strings are measured in PCR1, but we also want to measure them in our specific
                         * PCR12, as firmware-owned PCRs are very difficult to use as they'll contain unpredictable
                         * measurements that are not under control of the machine owner. */
                        m = false;
                        (void) tpm_log_load_options(extra16, &m);
                        parameters_measured = parameters_measured < 0 ? m : (parameters_measured && m);
                }
        }

        export_variables(loaded_image);

        if (pack_cpio(loaded_image,
                      NULL,
                      u".cred",
                      ".extra/credentials",
                      /* dir_mode= */ 0500,
                      /* access_mode= */ 0400,
                      /* tpm_pcr= */ TPM2_PCR_KERNEL_CONFIG,
                      u"Credentials initrd",
                      &credential_initrd,
                      &credential_initrd_size,
                      &m) == EFI_SUCCESS)
                parameters_measured = parameters_measured < 0 ? m : (parameters_measured && m);

        if (pack_cpio(loaded_image,
                      u"\\loader\\credentials",
                      u".cred",
                      ".extra/global_credentials",
                      /* dir_mode= */ 0500,
                      /* access_mode= */ 0400,
                      /* tpm_pcr= */ TPM2_PCR_KERNEL_CONFIG,
                      u"Global credentials initrd",
                      &global_credential_initrd,
                      &global_credential_initrd_size,
                      &m) == EFI_SUCCESS)
                parameters_measured = parameters_measured < 0 ? m : (parameters_measured && m);

        if (pack_cpio(loaded_image,
                      NULL,
                      u".raw",
                      ".extra/sysext",
                      /* dir_mode= */ 0555,
                      /* access_mode= */ 0444,
                      /* tpm_pcr= */ TPM2_PCR_SYSEXTS,
                      u"System extension initrd",
                      &sysext_initrd,
                      &sysext_initrd_size,
                      &m) == EFI_SUCCESS)
                sysext_measured = m;

        /* Measure DTBs contained in addons */
        dtb_measure_addons(&dt_state,
                           dt_bases_addons_global,
                           dt_sizes_addons_global,
                           dt_filenames_addons_global,
                           n_dts_addons_global,
                           &m);
        parameters_measured = parameters_measured < 0 ? m : (parameters_measured && m);
        dtb_measure_addons(&dt_state,
                           dt_bases_addons_uki,
                           dt_sizes_addons_uki,
                           dt_filenames_addons_uki,
                           n_dts_addons_uki,
                           &m);
        parameters_measured = parameters_measured < 0 ? m : (parameters_measured && m);

        if (parameters_measured > 0)
                (void) efivar_set_uint_string(MAKE_GUID_PTR(LOADER), u"StubPcrKernelParameters", TPM2_PCR_KERNEL_CONFIG, 0);
        if (sysext_measured)
                (void) efivar_set_uint_string(MAKE_GUID_PTR(LOADER), u"StubPcrInitRDSysExts", TPM2_PCR_SYSEXTS, 0);

        /* If the PCR signature was embedded in the PE image, then let's wrap it in a cpio and also pass it
         * to the kernel, so that it can be read from /.extra/tpm2-pcr-signature.json. Note that this section
         * is not measured, neither as raw section (see above), nor as cpio (here), because it is the
         * signature of expected PCR values, i.e. its input are PCR measurements, and hence it shouldn't
         * itself be input for PCR measurements. */
        PeSectionDescriptor *section_pcrsig = pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_PCRSIG);
        if (section_pcrsig)
                (void) pack_cpio_literal(
                                (uint8_t*) loaded_image->ImageBase + section_pcrsig->offset,
                                section_pcrsig->size,
                                ".extra",
                                u"tpm2-pcr-signature.json",
                                /* dir_mode= */ 0555,
                                /* access_mode= */ 0444,
                                /* tpm_pcr= */ UINT32_MAX,
                                /* tpm_description= */ NULL,
                                &pcrsig_initrd,
                                &pcrsig_initrd_size,
                                /* ret_measured= */ NULL);

        /* If the public key used for the PCR signatures was embedded in the PE image, then let's wrap it in
         * a cpio and also pass it to the kernel, so that it can be read from
         * /.extra/tpm2-pcr-public-key.pem. This section is already measure above, hence we won't measure the
         * cpio. */
        PeSectionDescriptor *section_pcrpkey = pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_PCRPKEY);
        if (section_pcrpkey)
                (void) pack_cpio_literal(
                                (uint8_t*) loaded_image->ImageBase + section_pcrpkey->offset,
                                section_pcrpkey->size,
                                ".extra",
                                u"tpm2-pcr-public-key.pem",
                                /* dir_mode= */ 0555,
                                /* access_mode= */ 0444,
                                /* tpm_pcr= */ UINT32_MAX,
                                /* tpm_description= */ NULL,
                                &pcrpkey_initrd,
                                &pcrpkey_initrd_size,
                                /* ret_measured= */ NULL);

        /*
         * Try to locate then install a compatible dtb, in the following order:
         *  - UKI specific addons first
         *  - Then try global addons
         *  - Finally the UKI itself
         */

        bool had_compatible_dtb = false;

        for (size_t dtb_idx = 0; !had_compatible_dtb && dtb_idx < n_dts_addons_uki; ++dtb_idx) {
                if (devicetree_match(dt_bases_addons_uki[dtb_idx], dt_sizes_addons_uki[dtb_idx]) == EFI_SUCCESS) {
                        err = devicetree_install_from_memory(
                                &dt_state, dt_bases_addons_uki[dtb_idx], dt_sizes_addons_uki[dtb_idx]);
                        if (err != EFI_SUCCESS)
                                log_error_status(err, "Error loading addon devicetree: %m");
                        had_compatible_dtb = true;
                }
        }


        for (size_t dtb_idx = 0; !had_compatible_dtb && dtb_idx < n_dts_addons_global; ++dtb_idx) {
                if (devicetree_match(dt_bases_addons_global[dtb_idx], dt_sizes_addons_global[dtb_idx]) == EFI_SUCCESS) {
                        err = devicetree_install_from_memory(
                                &dt_state, dt_bases_addons_global[dtb_idx], dt_sizes_addons_global[dtb_idx]);
                        if (err != EFI_SUCCESS)
                                log_error_status(err, "Error loading addon devicetree: %m");
                        had_compatible_dtb = true;
                }
        }

        PeSectionDescriptor *section_dtb = pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_DTB);
        if (section_dtb) {
                for (; !had_compatible_dtb && section_dtb < sections + n_sections && streq8(section_dtb->name, ".dtb"); ++section_dtb) {
                        if (devicetree_match((const uint8_t*) loaded_image->ImageBase + section_dtb->offset, section_dtb->size) == EFI_SUCCESS) {
                                err = devicetree_install_from_memory(&dt_state, (const uint8_t*) loaded_image->ImageBase + section_dtb->offset, section_dtb->size);
                                if (err != EFI_SUCCESS)
                                        log_error_status(err, "Error loading embedded devicetree: %m");
                                had_compatible_dtb = true;
                        }
                }
        }

        PeSectionDescriptor *section_linux = ASSERT_PTR(pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_LINUX));
        linux_size = section_linux->size;
        linux_base = POINTER_TO_PHYSICAL_ADDRESS(loaded_image->ImageBase) + section_linux->offset;

        PeSectionDescriptor *section_initrd = pe_find_unified_section(sections, n_sections, UNIFIED_SECTION_INITRD);
        if (section_initrd) {
                initrd_size = section_initrd->size;
                initrd_base = POINTER_TO_PHYSICAL_ADDRESS(loaded_image->ImageBase) + section_initrd->offset;
        }

        _cleanup_pages_ Pages initrd_pages = {};
        if (credential_initrd || global_credential_initrd || sysext_initrd || pcrsig_initrd || pcrpkey_initrd) {
                /* If we have generated initrds dynamically, let's combine them with the built-in initrd. */
                err = combine_initrd(
                                initrd_base, initrd_size,
                                (const void*const[]) {
                                        credential_initrd,
                                        global_credential_initrd,
                                        sysext_initrd,
                                        pcrsig_initrd,
                                        pcrpkey_initrd,
                                },
                                (const size_t[]) {
                                        credential_initrd_size,
                                        global_credential_initrd_size,
                                        sysext_initrd_size,
                                        pcrsig_initrd_size,
                                        pcrpkey_initrd_size,
                                },
                                5,
                                &initrd_pages, &initrd_size);
                if (err != EFI_SUCCESS)
                        return err;

                initrd_base = initrd_pages.addr;

                /* Given these might be large let's free them explicitly, quickly. */
                credential_initrd = mfree(credential_initrd);
                global_credential_initrd = mfree(global_credential_initrd);
                sysext_initrd = mfree(sysext_initrd);
                pcrsig_initrd = mfree(pcrsig_initrd);
                pcrpkey_initrd = mfree(pcrpkey_initrd);
        }

        err = linux_exec(image, cmdline,
                         PHYSICAL_ADDRESS_TO_POINTER(linux_base), linux_size,
                         PHYSICAL_ADDRESS_TO_POINTER(initrd_base), initrd_size);
        graphics_mode(false);
        return err;
}

DEFINE_EFI_MAIN_FUNCTION(run, "systemd-stub", /*wait_for_debugger=*/false);
