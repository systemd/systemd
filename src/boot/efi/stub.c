/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "cpio.h"
#include "disk.h"
#include "graphics.h"
#include "linux.h"
#include "measure.h"
#include "pe.h"
#include "secure-boot.h"
#include "splash.h"
#include "util.h"

/* magic string to find in the binary image */
static const char __attribute__((used)) magic[] = "#### LoaderInfo: systemd-stub " GIT_VERSION " ####";

static EFI_STATUS combine_initrd(
                EFI_PHYSICAL_ADDRESS initrd_base, UINTN initrd_size,
                const VOID *credential_initrd, UINTN credential_initrd_size,
                const VOID *sysext_initrd, UINTN sysext_initrd_size,
                EFI_PHYSICAL_ADDRESS *ret_initrd_base, UINTN *ret_initrd_size) {

        EFI_PHYSICAL_ADDRESS base = UINT32_MAX; /* allocate an area below the 32bit boundary for this */
        EFI_STATUS err;
        UINT8 *p;
        UINTN n;

        assert(ret_initrd_base);
        assert(ret_initrd_size);

        /* Combines three initrds into one, by simple concatenation in memory */

        n = ALIGN_TO(initrd_size, 4); /* main initrd might not be padded yet */
        if (credential_initrd) {
                if (n > UINTN_MAX - credential_initrd_size)
                        return EFI_OUT_OF_RESOURCES;

                n += credential_initrd_size;
        }
        if (sysext_initrd) {
                if (n > UINTN_MAX - sysext_initrd_size)
                        return EFI_OUT_OF_RESOURCES;

                n += sysext_initrd_size;
        }

        err = uefi_call_wrapper(
                        BS->AllocatePages, 4,
                        AllocateMaxAddress,
                        EfiLoaderData,
                        EFI_SIZE_TO_PAGES(n),
                        &base);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Failed to allocate space for combined initrd: %r", err);

        p = (UINT8*) (UINTN) base;
        if (initrd_base != 0) {
                UINTN pad;

                /* Order matters, the real initrd must come first, since it might include microcode updates
                 * which the kernel only looks for in the first cpio archive */
                CopyMem(p, (VOID*) (UINTN) initrd_base, initrd_size);
                p += initrd_size;

                pad = ALIGN_TO(initrd_size, 4) - initrd_size;
                if (pad > 0)  {
                        ZeroMem(p, pad);
                        p += pad;
                }
        }

        if (credential_initrd) {
                CopyMem(p, credential_initrd, credential_initrd_size);
                p += credential_initrd_size;
        }

        if (sysext_initrd) {
                CopyMem(p, sysext_initrd, sysext_initrd_size);
                p += sysext_initrd_size;
        }

        assert((UINT8*) (UINTN) base + n == p);

        *ret_initrd_base = base;
        *ret_initrd_size = n;

        return EFI_SUCCESS;
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table) {

        enum {
                SECTION_CMDLINE,
                SECTION_LINUX,
                SECTION_INITRD,
                SECTION_SPLASH,
                _SECTION_MAX,
        };

        const CHAR8* const sections[] = {
                [SECTION_CMDLINE] = (const CHAR8*) ".cmdline",
                [SECTION_LINUX]   = (const CHAR8*) ".linux",
                [SECTION_INITRD]  = (const CHAR8*) ".initrd",
                [SECTION_SPLASH]  = (const CHAR8*) ".splash",
                NULL,
        };

        UINTN cmdline_len = 0, initrd_size, credential_initrd_size = 0, sysext_initrd_size = 0;
        _cleanup_freepool_ VOID *credential_initrd = NULL, *sysext_initrd = NULL;
        EFI_PHYSICAL_ADDRESS linux_base, initrd_base;
        EFI_LOADED_IMAGE *loaded_image;
        UINTN addrs[_SECTION_MAX] = {};
        UINTN szs[_SECTION_MAX] = {};
        CHAR8 *cmdline = NULL;
        CHAR16 uuid[37];
        EFI_STATUS err;

        InitializeLib(image, sys_table);

        err = uefi_call_wrapper(BS->OpenProtocol, 6, image, &LoadedImageProtocol, (VOID **)&loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Error getting a LoadedImageProtocol handle: %r", err);

        err = pe_memory_locate_sections(loaded_image->ImageBase, (const CHAR8**) sections, addrs, szs);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Unable to locate embedded .linux section: %r", err);

        if (szs[SECTION_CMDLINE] > 0) {
                cmdline = (CHAR8*) loaded_image->ImageBase + addrs[SECTION_CMDLINE];
                cmdline_len = szs[SECTION_CMDLINE];
        }

        /* if we are not in secure boot mode, or none was provided, accept a custom command line and replace the built-in one */
        if ((!secure_boot_enabled() || cmdline_len == 0) && loaded_image->LoadOptionsSize > 0 &&
            *(CHAR16 *) loaded_image->LoadOptions > 0x1F) {
                CHAR16 *options;
                CHAR8 *line;

                options = (CHAR16 *)loaded_image->LoadOptions;
                cmdline_len = (loaded_image->LoadOptionsSize / sizeof(CHAR16)) * sizeof(CHAR8);
                line = AllocatePool(cmdline_len);
                for (UINTN i = 0; i < cmdline_len; i++)
                        line[i] = options[i];
                cmdline = line;

#if ENABLE_TPM
                /* Try to log any options to the TPM, especially manually edited options */
                err = tpm_log_event(SD_TPM_PCR,
                                    (EFI_PHYSICAL_ADDRESS) (UINTN) loaded_image->LoadOptions,
                                    loaded_image->LoadOptionsSize, loaded_image->LoadOptions);
                if (EFI_ERROR(err))
                        log_error_stall(L"Unable to add image options measurement: %r", err);
#endif
        }

        /* Export the device path this image is started from, if it's not set yet */
        if (efivar_get_raw(LOADER_GUID, L"LoaderDevicePartUUID", NULL, NULL) != EFI_SUCCESS)
                if (disk_get_part_uuid(loaded_image->DeviceHandle, uuid) == EFI_SUCCESS)
                        efivar_set(LOADER_GUID, L"LoaderDevicePartUUID", uuid, 0);

        /* If LoaderImageIdentifier is not set, assume the image with this stub was loaded directly from the
         * UEFI firmware without any boot loader, and hence set the LoaderImageIdentifier ourselves. Note
         * that some boot chain loaders neither set LoaderImageIdentifier nor make FilePath available to us,
         * in which case there's simple nothing to set for us. (The UEFI spec doesn't really say who's wrong
         * here, i.e. whether FilePath may be NULL or not, hence handle this gracefully and check if FilePath
         * is non-NULL explicitly.) */
        if (efivar_get_raw(LOADER_GUID, L"LoaderImageIdentifier", NULL, NULL) != EFI_SUCCESS &&
            loaded_image->FilePath) {
                _cleanup_freepool_ CHAR16 *s = NULL;

                s = DevicePathToStr(loaded_image->FilePath);
                efivar_set(LOADER_GUID, L"LoaderImageIdentifier", s, 0);
        }

        /* if LoaderFirmwareInfo is not set, let's set it */
        if (efivar_get_raw(LOADER_GUID, L"LoaderFirmwareInfo", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_freepool_ CHAR16 *s = NULL;

                s = PoolPrint(L"%s %d.%02d", ST->FirmwareVendor, ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
                efivar_set(LOADER_GUID, L"LoaderFirmwareInfo", s, 0);
        }

        /* ditto for LoaderFirmwareType */
        if (efivar_get_raw(LOADER_GUID, L"LoaderFirmwareType", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_freepool_ CHAR16 *s = NULL;

                s = PoolPrint(L"UEFI %d.%02d", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
                efivar_set(LOADER_GUID, L"LoaderFirmwareType", s, 0);
        }

        /* add StubInfo */
        if (efivar_get_raw(LOADER_GUID, L"StubInfo", NULL, NULL) != EFI_SUCCESS)
                efivar_set(LOADER_GUID, L"StubInfo", L"systemd-stub " GIT_VERSION, 0);

        if (szs[SECTION_SPLASH] > 0)
                graphics_splash((UINT8*) (UINTN) loaded_image->ImageBase + addrs[SECTION_SPLASH], szs[SECTION_SPLASH], NULL);

        (VOID) pack_cpio(loaded_image,
                         L".cred",
                         (const CHAR8*) ".extra/credentials",
                         /* dir_mode= */ 0500,
                         /* access_mode= */ 0400,
                         /* tpm_pcr= */ TPM_PCR_INDEX_KERNEL_PARAMETERS,
                         L"Credentials initrd",
                         &credential_initrd,
                         &credential_initrd_size);

        (VOID) pack_cpio(loaded_image,
                         L".raw",
                         (const CHAR8*) ".extra/sysext",
                         /* dir_mode= */ 0555,
                         /* access_mode= */ 0444,
                         /* tpm_pcr= */ TPM_PCR_INDEX_INITRD,
                         L"System extension initrd",
                         &sysext_initrd,
                         &sysext_initrd_size);

        linux_base = (EFI_PHYSICAL_ADDRESS) (UINTN) loaded_image->ImageBase + addrs[SECTION_LINUX];

        initrd_size = szs[SECTION_INITRD];
        initrd_base = initrd_size != 0 ? (EFI_PHYSICAL_ADDRESS) (UINTN) loaded_image->ImageBase + addrs[SECTION_INITRD] : 0;

        if (credential_initrd || sysext_initrd) {
                /* If we have generated initrds dynamically, let's combine them with the built-in initrd. */
                err = combine_initrd(
                                initrd_base, initrd_size,
                                credential_initrd, credential_initrd_size,
                                sysext_initrd, sysext_initrd_size,
                                &initrd_base, &initrd_size);
                if (EFI_ERROR(err))
                        return err;

                /* Given these might be large let's free them explicitly, quickly. */
                if (credential_initrd) {
                        FreePool(credential_initrd);
                        credential_initrd = NULL;
                }

                if (sysext_initrd) {
                        FreePool(sysext_initrd);
                        sysext_initrd = NULL;
                }
        }

        err = linux_exec(image, cmdline, cmdline_len, linux_base, initrd_base, initrd_size);
        graphics_mode(FALSE);
        return log_error_status_stall(err, L"Execution of embedded linux image failed: %r", err);
}
