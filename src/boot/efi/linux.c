/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "linux.h"
#include "initrd.h"
#include "util.h"

EFI_STATUS linux_exec(
        EFI_HANDLE image,
        CHAR8* cmdline, UINTN cmdline_len,
        VOID* linux_buffer, UINTN linux_length,
        VOID* initrd_buffer, UINTN initrd_size
) {
        EFI_STATUS err;
        EFI_HANDLE handle;
        EFI_LOADED_IMAGE* loaded_image;

        err = uefi_call_wrapper(
                BS->OpenProtocol, 6,
                image, &LoadedImageProtocol, (VOID**) &loaded_image,
                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL
        );
        if (EFI_ERROR(err))
                return EFI_LOAD_ERROR;

        err = uefi_call_wrapper(
                BS->LoadImage, 6,
                false, image, (EFI_DEVICE_PATH*) loaded_image->FilePath,
                linux_buffer, linux_length, &handle
        );
        if (EFI_ERROR(err)) {
                return EFI_LOAD_ERROR;
        }

        err = uefi_call_wrapper(
                BS->OpenProtocol, 6,
                handle, &LoadedImageProtocol, (VOID**) &loaded_image,
                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL
        );

        if (EFI_ERROR(err)) {
                uefi_call_wrapper(BS->UnloadImage, 1, handle);
                return EFI_LOAD_ERROR;
        }

        if (cmdline_len) {
                loaded_image->LoadOptions = stra_to_str(cmdline);
                loaded_image->LoadOptionsSize = cmdline_len * 2;
        }

        err = initrd_register(initrd_buffer, initrd_size);
        if (EFI_ERROR(err)) {
                uefi_call_wrapper(BS->UnloadImage, 1, handle);
                return EFI_LOAD_ERROR;
        }

        // execute kernel
        /* err = */ uefi_call_wrapper(BS->StartImage, 3, handle, NULL, NULL);

        // cleanup
        initrd_deregister();
        uefi_call_wrapper(BS->UnloadImage, 1, handle);
        return EFI_LOAD_ERROR;
}
