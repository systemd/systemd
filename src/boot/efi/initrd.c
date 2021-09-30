/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "initrd.h"
#include "macro-fundamental.h"
#include "missing_efi.h"

/* extend LoadFileProtocol */
struct initrd_loader {
        EFI_LOAD_FILE_PROTOCOL load_file;
        VOID *address;
        UINTN length;
};

/* static structure for LINUX_INITRD_MEDIA device path
   see https://github.com/torvalds/linux/blob/v5.13/drivers/firmware/efi/libstub/efi-stub-helper.c
 */
static const struct {
        VENDOR_DEVICE_PATH vendor;
        EFI_DEVICE_PATH end;
} _packed_ efi_initrd_device_path = {
        .vendor = {
                {
                        MEDIA_DEVICE_PATH,
                        MEDIA_VENDOR_DP,
                        { sizeof(efi_initrd_device_path.vendor), 0 }
                },
                LINUX_INITRD_MEDIA_GUID
        },
        .end = {
                END_DEVICE_PATH_TYPE,
                END_ENTIRE_DEVICE_PATH_SUBTYPE,
                { sizeof(efi_initrd_device_path.end), 0 }
        }
};

EFIAPI EFI_STATUS initrd_load_file(
                EFI_LOAD_FILE_PROTOCOL *this,
                EFI_DEVICE_PATH *file_path,
                BOOLEAN boot_policy,
                UINTN *buffer_size,
                VOID *buffer) {

        if (!buffer_size || !file_path)
                return EFI_INVALID_PARAMETER;
        if (boot_policy)
                return EFI_UNSUPPORTED;

        struct initrd_loader *loader = (struct initrd_loader *) this;

        if (loader->length == 0 || !loader->address)
                return EFI_NOT_FOUND;

        if (!buffer || *buffer_size < loader->length) {
                *buffer_size = loader->length;
                return EFI_BUFFER_TOO_SMALL;
        }

        CopyMem(buffer, loader->address, loader->length);
        *buffer_size = loader->length;
        return EFI_SUCCESS;
}

EFI_STATUS initrd_register(
                VOID *initrd_address,
                UINTN initrd_length,
                EFI_HANDLE *initrd_handle) {

        EFI_STATUS err;
        EFI_DEVICE_PATH *dp = (EFI_DEVICE_PATH *) &efi_initrd_device_path;
        EFI_HANDLE handle;
        struct initrd_loader *loader;

        assert(initrd_handle);

        if (!initrd_address || initrd_length == 0)
                return EFI_SUCCESS;

        /* check if a InitrdMedia DevicePath is alreay registed.
           LocateDevicePath checks for the "closest DevicePath" and returns its handle,
           where as InstallMultipleProtocolInterfaces only maches identical DevicePaths.
         */
        err = uefi_call_wrapper(BS->LocateDevicePath, 3, &EfiLoadFile2Protocol , &dp, &handle);
        if (err != EFI_NOT_FOUND) /* InitrdMedia is already registered */
                return EFI_ALREADY_STARTED;

        loader = AllocatePool(sizeof(struct initrd_loader));
        if (!loader)
                return EFI_LOAD_ERROR;

        loader->load_file.LoadFile = initrd_load_file;
        loader->address = initrd_address;
        loader->length = initrd_length;

        /* create a new handle and register the LoadFile2 protocol with the InitrdMediaPath on it */
        err = uefi_call_wrapper(BS->InstallMultipleProtocolInterfaces, 8,
                                initrd_handle,
                                &DevicePathProtocol, &efi_initrd_device_path,
                                &EfiLoadFile2Protocol, loader,
                                NULL);
        if (EFI_ERROR(err)) {
                *initrd_handle = NULL;
                FreePool(loader);
        }

        return err;
}

EFI_STATUS initrd_deregister(EFI_HANDLE initrd_handle) {
        EFI_STATUS err;
        struct initrd_loader *loader;

        if (initrd_handle) {
                /* get the LoadFile2 protocol that we allocated earlier */
                err = uefi_call_wrapper(BS->OpenProtocol, 3,
                                        initrd_handle, &EfiLoadFile2Protocol, (VOID **) &loader,
                                        NULL, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
                if (EFI_ERROR(err))
                        return EFI_SUCCESS;

                /* uninstall all protocols thus destroying the handle */
                err = uefi_call_wrapper(BS->UninstallMultipleProtocolInterfaces, 6,
                                        initrd_handle,
                                        &DevicePathProtocol, &efi_initrd_device_path,
                                        &EfiLoadFile2Protocol, loader,
                                        NULL);

                if (!EFI_ERROR(err))
                        FreePool(loader);
        }

        return EFI_SUCCESS;
}
