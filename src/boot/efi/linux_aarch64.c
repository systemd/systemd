/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "linux.h"
#include "initrd.h"
#include "pe.h"
#include "util.h"

static EFI_STATUS loaded_image_register(
                const CHAR8 *cmdline, UINTN cmdline_len,
                const CHAR8 *linux_buffer, UINTN linux_length,
                EFI_HANDLE *ret_image) {

        EFI_LOADED_IMAGE *loaded_image = NULL;
        EFI_STATUS err;

        assert(ret_image);

        /* create and install new LoadedImage Protocol */
        loaded_image = AllocatePool(sizeof(EFI_LOADED_IMAGE));
        if (!loaded_image)
                return EFI_OUT_OF_RESOURCES;

        *loaded_image = (EFI_LOADED_IMAGE) {
                .ImageBase = (VOID *) linux_buffer,
                .ImageSize = linux_length,
                0
        };
        if (cmdline) {
                loaded_image->LoadOptions = stra_to_str(cmdline);
                /* length of LoadOptions + '\0' */
                loaded_image->LoadOptionsSize = (StrLen(loaded_image->LoadOptions) + 1 ) * sizeof(CHAR16);
        }
        err = uefi_call_wrapper(BS->InstallMultipleProtocolInterfaces, 4,
                        ret_image,
                        &LoadedImageProtocol, loaded_image,
                        NULL);
        if (EFI_ERROR(err))
                FreePool(loaded_image);

        return err;
}

static EFI_STATUS loaded_image_unregister(EFI_HANDLE loaded_image_handle) {
        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        EFI_STATUS err;

        if (!loaded_image_handle)
                return EFI_SUCCESS;

        /* get the LoadedImage protocol that we allocated earlier */
        err = uefi_call_wrapper(
                        BS->OpenProtocol, 6,
                        loaded_image_handle, &LoadedImageProtocol, (VOID **) &loaded_image,
                        NULL, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(err))
                return err;

        /* close the handle */
        (void) uefi_call_wrapper(
                        BS->CloseProtocol, 4,
                        loaded_image_handle, &LoadedImageProtocol, NULL, NULL);
        err = uefi_call_wrapper(BS->UninstallMultipleProtocolInterfaces, 4,
                        loaded_image_handle,
                        &LoadedImageProtocol, loaded_image,
                        NULL);
        if (EFI_ERROR(err))
                return err;
        loaded_image_handle = NULL;

        if (loaded_image->LoadOptions)
                FreePool(loaded_image->LoadOptions);
        FreePool(loaded_image);

        return EFI_SUCCESS;
}

static void cleanup_initrd(EFI_HANDLE *initrd_handle) {
        (void) initrd_unregister(*initrd_handle);
        *initrd_handle = NULL;
}

static void cleanup_loaded_image(EFI_HANDLE *loaded_image_handle) {
        (void) loaded_image_unregister(*loaded_image_handle);
        *loaded_image_handle = NULL;
}

EFI_STATUS linux_exec(
                EFI_HANDLE image,
                const CHAR8 *cmdline, UINTN cmdline_len,
                const VOID *linux_buffer, const UINTN linux_length,
                const VOID *initrd_buffer, UINTN initrd_length) {

        _cleanup_(cleanup_initrd) EFI_HANDLE initrd_handle = NULL;
        _cleanup_(cleanup_loaded_image) EFI_HANDLE loaded_image_handle = NULL;
        EFI_IMAGE_ENTRY_POINT kernel_entry;
        EFI_STATUS err;

        assert(image);
        assert(cmdline || cmdline_len == 0);
        assert(linux_buffer);
        assert(initrd_buffer || initrd_length == 0);

        kernel_entry = pe_entry_point(linux_buffer);
        if (!kernel_entry)
                return EFI_LOAD_ERROR;

        err = loaded_image_register(cmdline, cmdline_len, linux_buffer, linux_length, &loaded_image_handle);
        if (EFI_ERROR(err))
                return err;

        err = initrd_register(initrd_buffer, initrd_length, &initrd_handle);
        if (EFI_ERROR(err))
                return err;
        err = uefi_call_wrapper(kernel_entry, 2, loaded_image_handle, ST);

        return err;
}
