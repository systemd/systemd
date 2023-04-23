/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cpio.h"
#include "device-path-util.h"
#include "devicetree.h"
#include "graphics.h"
#include "linux.h"
#include "measure.h"
#include "part-discovery.h"
#include "pe.h"
#include "proto/shell-parameters.h"
#include "random-seed.h"
#include "secure-boot.h"
#include "splash.h"
#include "tpm-pcr.h"
#include "util.h"
#include "version.h"
#include "vmm.h"

/* magic string to find in the binary image */
_used_ _section_(".sdmagic") static const char magic[] = "#### LoaderInfo: systemd-stub " GIT_VERSION " ####";

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
                        memset(p, 0, pad);
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
         * the stub image. */
        if (secure_boot_enabled() && have_cmdline)
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

static EFI_STATUS run(EFI_HANDLE image) {
        _cleanup_free_ void *credential_initrd = NULL, *global_credential_initrd = NULL, *sysext_initrd = NULL, *pcrsig_initrd = NULL, *pcrpkey_initrd = NULL;
        size_t credential_initrd_size = 0, global_credential_initrd_size = 0, sysext_initrd_size = 0, pcrsig_initrd_size = 0, pcrpkey_initrd_size = 0;
        size_t linux_size, initrd_size, dt_size;
        EFI_PHYSICAL_ADDRESS linux_base, initrd_base, dt_base;
        _cleanup_(devicetree_cleanup) struct devicetree_state dt_state = {};
        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        size_t addrs[_UNIFIED_SECTION_MAX] = {}, szs[_UNIFIED_SECTION_MAX] = {};
        _cleanup_free_ char16_t *cmdline = NULL;
        int sections_measured = -1, parameters_measured = -1;
        bool sysext_measured = false, m;
        uint64_t loader_features = 0;
        EFI_STATUS err;

        err = BS->OpenProtocol(
                        image,
                        MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL),
                        (void **) &loaded_image,
                        image,
                        NULL,
                        EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error getting a LoadedImageProtocol handle: %m");

        if (efivar_get_uint64_le(MAKE_GUID_PTR(LOADER), u"LoaderFeatures", &loader_features) != EFI_SUCCESS ||
            !FLAGS_SET(loader_features, EFI_LOADER_FEATURE_RANDOM_SEED)) {
                _cleanup_(file_closep) EFI_FILE *esp_dir = NULL;

                err = partition_open(MAKE_GUID_PTR(ESP), loaded_image->DeviceHandle, NULL, &esp_dir);
                if (err == EFI_SUCCESS) /* Non-fatal on failure, so that we still boot without it. */
                        (void) process_random_seed(esp_dir);
        }

        err = pe_memory_locate_sections(loaded_image->ImageBase, unified_sections, addrs, szs);
        if (err != EFI_SUCCESS || szs[UNIFIED_SECTION_LINUX] == 0) {
                if (err == EFI_SUCCESS)
                        err = EFI_NOT_FOUND;
                return log_error_status(err, "Unable to locate embedded .linux section: %m");
        }

        /* Measure all "payload" of this PE image into a separate PCR (i.e. where nothing else is written
         * into so far), so that we have one PCR that we can nicely write policies against because it
         * contains all static data of this image, and thus can be easily be pre-calculated. */
        for (UnifiedSection section = 0; section < _UNIFIED_SECTION_MAX; section++) {

                if (!unified_section_measure(section)) /* shall not measure? */
                        continue;

                if (szs[section] == 0) /* not found */
                        continue;

                m = false;

                /* First measure the name of the section */
                (void) tpm_log_event_ascii(
                                TPM_PCR_INDEX_KERNEL_IMAGE,
                                POINTER_TO_PHYSICAL_ADDRESS(unified_sections[section]),
                                strsize8(unified_sections[section]), /* including NUL byte */
                                unified_sections[section],
                                &m);

                sections_measured = sections_measured < 0 ? m : (sections_measured && m);

                /* Then measure the data of the section */
                (void) tpm_log_event_ascii(
                                TPM_PCR_INDEX_KERNEL_IMAGE,
                                POINTER_TO_PHYSICAL_ADDRESS(loaded_image->ImageBase) + addrs[section],
                                szs[section],
                                unified_sections[section],
                                &m);

                sections_measured = sections_measured < 0 ? m : (sections_measured && m);
        }

        /* After we are done, set an EFI variable that tells userspace this was done successfully, and encode
         * in it which PCR was used. */
        if (sections_measured > 0)
                (void) efivar_set_uint_string(MAKE_GUID_PTR(LOADER), u"StubPcrKernelImage", TPM_PCR_INDEX_KERNEL_IMAGE, 0);

        /* Show splash screen as early as possible */
        graphics_splash((const uint8_t*) loaded_image->ImageBase + addrs[UNIFIED_SECTION_SPLASH], szs[UNIFIED_SECTION_SPLASH]);

        if (use_load_options(image, loaded_image, szs[UNIFIED_SECTION_CMDLINE] > 0, &cmdline)) {
                /* Let's measure the passed kernel command line into the TPM. Note that this possibly
                 * duplicates what we already did in the boot menu, if that was already used. However, since
                 * we want the boot menu to support an EFI binary, and want to this stub to be usable from
                 * any boot menu, let's measure things anyway. */
                m = false;
                (void) tpm_log_load_options(cmdline, &m);
                parameters_measured = m;
        } else if (szs[UNIFIED_SECTION_CMDLINE] > 0) {
                cmdline = xstrn8_to_16(
                                (char *) loaded_image->ImageBase + addrs[UNIFIED_SECTION_CMDLINE],
                                szs[UNIFIED_SECTION_CMDLINE]);
                mangle_stub_cmdline(cmdline);
        }

        const char *extra = smbios_find_oem_string("io.systemd.stub.kernel-cmdline-extra");
        if (extra) {
                _cleanup_free_ char16_t *tmp = TAKE_PTR(cmdline), *extra16 = xstr8_to_16(extra);
                cmdline = xasprintf("%ls %ls", tmp, extra16);

                m = false;
                (void) tpm_log_load_options(extra16, &m);
        }

        export_variables(loaded_image);

        if (pack_cpio(loaded_image,
                      NULL,
                      u".cred",
                      ".extra/credentials",
                      /* dir_mode= */ 0500,
                      /* access_mode= */ 0400,
                      /* tpm_pcr= */ TPM_PCR_INDEX_KERNEL_PARAMETERS,
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
                      /* tpm_pcr= */ TPM_PCR_INDEX_KERNEL_PARAMETERS,
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
                      /* tpm_pcr= */ TPM_PCR_INDEX_INITRD_SYSEXTS,
                      u"System extension initrd",
                      &sysext_initrd,
                      &sysext_initrd_size,
                      &m) == EFI_SUCCESS)
                sysext_measured = m;

        if (parameters_measured > 0)
                (void) efivar_set_uint_string(MAKE_GUID_PTR(LOADER), u"StubPcrKernelParameters", TPM_PCR_INDEX_KERNEL_PARAMETERS, 0);
        if (sysext_measured)
                (void) efivar_set_uint_string(MAKE_GUID_PTR(LOADER), u"StubPcrInitRDSysExts", TPM_PCR_INDEX_INITRD_SYSEXTS, 0);

        /* If the PCR signature was embedded in the PE image, then let's wrap it in a cpio and also pass it
         * to the kernel, so that it can be read from /.extra/tpm2-pcr-signature.json. Note that this section
         * is not measured, neither as raw section (see above), nor as cpio (here), because it is the
         * signature of expected PCR values, i.e. its input are PCR measurements, and hence it shouldn't
         * itself be input for PCR measurements. */
        if (szs[UNIFIED_SECTION_PCRSIG] > 0)
                (void) pack_cpio_literal(
                                (uint8_t*) loaded_image->ImageBase + addrs[UNIFIED_SECTION_PCRSIG],
                                szs[UNIFIED_SECTION_PCRSIG],
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
        if (szs[UNIFIED_SECTION_PCRPKEY] > 0)
                (void) pack_cpio_literal(
                                (uint8_t*) loaded_image->ImageBase + addrs[UNIFIED_SECTION_PCRPKEY],
                                szs[UNIFIED_SECTION_PCRPKEY],
                                ".extra",
                                u"tpm2-pcr-public-key.pem",
                                /* dir_mode= */ 0555,
                                /* access_mode= */ 0444,
                                /* tpm_pcr= */ UINT32_MAX,
                                /* tpm_description= */ NULL,
                                &pcrpkey_initrd,
                                &pcrpkey_initrd_size,
                                /* ret_measured= */ NULL);

        linux_size = szs[UNIFIED_SECTION_LINUX];
        linux_base = POINTER_TO_PHYSICAL_ADDRESS(loaded_image->ImageBase) + addrs[UNIFIED_SECTION_LINUX];

        initrd_size = szs[UNIFIED_SECTION_INITRD];
        initrd_base = initrd_size != 0 ? POINTER_TO_PHYSICAL_ADDRESS(loaded_image->ImageBase) + addrs[UNIFIED_SECTION_INITRD] : 0;

        dt_size = szs[UNIFIED_SECTION_DTB];
        dt_base = dt_size != 0 ? POINTER_TO_PHYSICAL_ADDRESS(loaded_image->ImageBase) + addrs[UNIFIED_SECTION_DTB] : 0;

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

        if (dt_size > 0) {
                err = devicetree_install_from_memory(
                                &dt_state, PHYSICAL_ADDRESS_TO_POINTER(dt_base), dt_size);
                if (err != EFI_SUCCESS)
                        log_error_status(err, "Error loading embedded devicetree: %m");
        }

        err = linux_exec(image, cmdline,
                         PHYSICAL_ADDRESS_TO_POINTER(linux_base), linux_size,
                         PHYSICAL_ADDRESS_TO_POINTER(initrd_base), initrd_size);
        graphics_mode(false);
        return err;
}

DEFINE_EFI_MAIN_FUNCTION(run, "systemd-stub", /*wait_for_debugger=*/false);
