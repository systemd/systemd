/* SPDX-License-Identifier: LGPL-2.1+ */

#include <efi.h>
#include <efilib.h>

#include "disk.h"
#include "graphics.h"
#include "linux.h"
#include "measure.h"
#include "pe.h"
#include "splash.h"
#include "util.h"

/* magic string to find in the binary image */
static const char __attribute__((used)) magic[] = "#### LoaderInfo: systemd-stub " GIT_VERSION " ####";

static const EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table) {
        EFI_LOADED_IMAGE *loaded_image;
        _cleanup_freepool_ CHAR8 *b = NULL;
        UINTN size;
        BOOLEAN secure = FALSE;
        CHAR8 *sections[] = {
                (UINT8 *)".cmdline",
                (UINT8 *)".linux",
                (UINT8 *)".initrd",
                (UINT8 *)".splash",
                NULL
        };
        UINTN addrs[ELEMENTSOF(sections)-1] = {};
        UINTN offs[ELEMENTSOF(sections)-1] = {};
        UINTN szs[ELEMENTSOF(sections)-1] = {};
        CHAR8 *cmdline = NULL;
        UINTN cmdline_len;
        CHAR16 uuid[37];
        EFI_STATUS err;

        InitializeLib(image, sys_table);

        err = uefi_call_wrapper(BS->OpenProtocol, 6, image, &LoadedImageProtocol, (VOID **)&loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(err)) {
                Print(L"Error getting a LoadedImageProtocol handle: %r ", err);
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return err;
        }

        if (efivar_get_raw(&global_guid, L"SecureBoot", &b, &size) == EFI_SUCCESS)
                if (*b > 0)
                        secure = TRUE;

        err = pe_memory_locate_sections(loaded_image->ImageBase, sections, addrs, offs, szs);
        if (EFI_ERROR(err)) {
                Print(L"Unable to locate embedded .linux section: %r ", err);
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return err;
        }

        if (szs[0] > 0)
                cmdline = (CHAR8 *)(loaded_image->ImageBase + addrs[0]);

        cmdline_len = szs[0];

        /* if we are not in secure boot mode, accept a custom command line and replace the built-in one */
        if (!secure && loaded_image->LoadOptionsSize > 0 && *(CHAR16 *)loaded_image->LoadOptions > 0x1F) {
                CHAR16 *options;
                CHAR8 *line;
                UINTN i;

                options = (CHAR16 *)loaded_image->LoadOptions;
                cmdline_len = (loaded_image->LoadOptionsSize / sizeof(CHAR16)) * sizeof(CHAR8);
                line = AllocatePool(cmdline_len);
                for (i = 0; i < cmdline_len; i++)
                        line[i] = options[i];
                cmdline = line;

#if ENABLE_TPM
                /* Try to log any options to the TPM, especially manually edited options */
                err = tpm_log_event(SD_TPM_PCR,
                                    (EFI_PHYSICAL_ADDRESS) (UINTN) loaded_image->LoadOptions,
                                    loaded_image->LoadOptionsSize, loaded_image->LoadOptions);
                if (EFI_ERROR(err)) {
                        Print(L"Unable to add image options measurement: %r", err);
                        uefi_call_wrapper(BS->Stall, 1, 200 * 1000);
                }
#endif
        }

        /* Export the device path this image is started from, if it's not set yet */
        if (efivar_get_raw(&loader_guid, L"LoaderDevicePartUUID", NULL, NULL) != EFI_SUCCESS)
                if (disk_get_part_uuid(loaded_image->DeviceHandle, uuid) == EFI_SUCCESS)
                        efivar_set(L"LoaderDevicePartUUID", uuid, FALSE);

        /* if LoaderImageIdentifier is not set, assume the image with this stub was loaded directly from UEFI */
        if (efivar_get_raw(&loader_guid, L"LoaderImageIdentifier", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_freepool_ CHAR16 *s;

                s = DevicePathToStr(loaded_image->FilePath);
                efivar_set(L"LoaderImageIdentifier", s, FALSE);
        }

        /* if LoaderFirmwareInfo is not set, let's set it */
        if (efivar_get_raw(&loader_guid, L"LoaderFirmwareInfo", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_freepool_ CHAR16 *s;

                s = PoolPrint(L"%s %d.%02d", ST->FirmwareVendor, ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
                efivar_set(L"LoaderFirmwareInfo", s, FALSE);
        }

        /* ditto for LoaderFirmwareType */
        if (efivar_get_raw(&loader_guid, L"LoaderFirmwareType", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_freepool_ CHAR16 *s;

                s = PoolPrint(L"UEFI %d.%02d", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
                efivar_set(L"LoaderFirmwareType", s, FALSE);
        }

        /* add StubInfo */
        if (efivar_get_raw(&loader_guid, L"StubInfo", NULL, NULL) != EFI_SUCCESS)
                efivar_set(L"StubInfo", L"systemd-stub " GIT_VERSION, FALSE);

        if (szs[3] > 0)
                graphics_splash((UINT8 *)((UINTN)loaded_image->ImageBase + addrs[3]), szs[3], NULL);

        err = linux_exec(image, cmdline, cmdline_len,
                         (UINTN)loaded_image->ImageBase + addrs[1],
                         (UINTN)loaded_image->ImageBase + addrs[2], szs[2]);

        graphics_mode(FALSE);
        Print(L"Execution of embedded linux image failed: %r\n", err);
        uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
        return err;
}
