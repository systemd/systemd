/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "linux.h"
#include "initrd.h"
#include "util.h"

static void cleanup_initrd_handle(EFI_HANDLE *handle) {
        if (handle)
                initrd_deregister(*handle);
}

static void cleanup_loaded_image(EFI_HANDLE *handle) {
        if (handle)
                uefi_call_wrapper(BS->UnloadImage, 1, handle);
}

EFI_STATUS linux_exec(
                EFI_HANDLE image,
                CHAR8 *cmdline, UINTN cmdline_len,
                VOID *linux_buffer, UINTN linux_length,
                VOID *initrd_buffer, UINTN initrd_size) {

        EFI_STATUS err;
        _cleanup_(cleanup_loaded_image) EFI_HANDLE handle = NULL;
        _cleanup_(cleanup_initrd_handle) EFI_HANDLE initrd_handle = NULL;
        EFI_LOADED_IMAGE *loaded_image;

        assert(image);
        assert(cmdline || cmdline_len == 0);
        assert(linux_buffer && linux_length > 0);
        assert(initrd_buffer || initrd_size == 0);

        err = uefi_call_wrapper(BS->OpenProtocol, 6,
                                image, &LoadedImageProtocol, (VOID **) &loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(err))
                return EFI_LOAD_ERROR;

        err = uefi_call_wrapper(BS->LoadImage, 6,
                                false, image, (EFI_DEVICE_PATH *) loaded_image->FilePath,
                                linux_buffer, linux_length, &handle);
        if (EFI_ERROR(err))
                return EFI_LOAD_ERROR;

        err = uefi_call_wrapper(BS->OpenProtocol, 6,
                                handle, &LoadedImageProtocol, (VOID **) &loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);

        if (EFI_ERROR(err))
                return EFI_LOAD_ERROR;

        if (cmdline_len > 0) {
                loaded_image->LoadOptions = stra_to_str(cmdline);
                loaded_image->LoadOptionsSize = cmdline_len * 2;
        }

        err = initrd_register(initrd_buffer, initrd_size, &initrd_handle);
        if (EFI_ERROR(err))
                return EFI_LOAD_ERROR;

        return uefi_call_wrapper(BS->StartImage, 3, handle, NULL, NULL);
}
