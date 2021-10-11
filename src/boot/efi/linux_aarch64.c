/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "linux.h"
#include "initrd.h"
#include "pe.h"
#include "util.h"

EFI_STATUS linux_exec(
                EFI_HANDLE image,
                const CHAR8 *cmdline, UINTN cmdline_len,
                const VOID *linux_buffer,
                const VOID *initrd_buffer, UINTN initrd_length) {

        EFI_HANDLE initrd_handle = NULL;
        EFI_IMAGE_ENTRY_POINT kernel_entry;
        EFI_LOADED_IMAGE* loaded_image;
        EFI_HANDLE loaded_image_handle = NULL;
        EFI_STATUS err;

        assert(image);
        assert(cmdline || cmdline_len == 0);
        assert(linux_buffer);
        assert(initrd_buffer || initrd_length == 0);

        kernel_entry = pe_entry_point(linux_buffer);
        if (!kernel_entry)
                return EFI_LOAD_ERROR;

        /* create and install new LoadedImage Protocol */
        loaded_image = AllocatePool(sizeof(EFI_LOADED_IMAGE));
        if (!loaded_image)
                return EFI_OUT_OF_RESOURCES;

        SetMem(loaded_image, sizeof(EFI_LOADED_IMAGE), 0);
        loaded_image->ImageBase = (VOID *) linux_buffer;
        if (cmdline) {
                loaded_image->LoadOptions = stra_to_str(cmdline);
                loaded_image->LoadOptionsSize = cmdline_len * 2;
        }
        err = uefi_call_wrapper(BS->InstallMultipleProtocolInterfaces, 4,
                        &loaded_image_handle,
                        &LoadedImageProtocol, loaded_image,
                        NULL);

        err = initrd_register(initrd_buffer, initrd_length, &initrd_handle);
        if (EFI_ERROR(err))
                return err;
        err = uefi_call_wrapper(kernel_entry, 2, image, ST);
        (void) initrd_unregister(initrd_handle);
        initrd_handle = NULL;

        /* uninstall and free LoadedImage Protocol */
        (void) uefi_call_wrapper(BS->UninstallMultipleProtocolInterfaces, 4,
                        loaded_image_handle,
                        &LoadedImageProtocol, loaded_image,
                        NULL);
        if (loaded_image->LoadOptions)
                FreePool(loaded_image->LoadOptions);
        FreePool(loaded_image);
        loaded_image_handle = NULL;
        return err;
}
