/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "initrd.h"
#include "macro-fundamental.h"
#include "missing_efi.h"
#include "util.h"

/* extend LoadFileProtocol */
struct initrd_loader {
        EFI_LOAD_FILE_PROTOCOL load_file;
        const void *address;
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
                .Header = {
                        .Type = MEDIA_DEVICE_PATH,
                        .SubType = MEDIA_VENDOR_DP,
                        .Length = { sizeof(efi_initrd_device_path.vendor), 0 }
                },
                .Guid = LINUX_INITRD_MEDIA_GUID
        },
        .end = {
                .Type = END_DEVICE_PATH_TYPE,
                .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
                .Length = { sizeof(efi_initrd_device_path.end), 0 }
        }
};

static EFIAPI EFI_STATUS initrd_load_file(
                EFI_LOAD_FILE_PROTOCOL *this,
                EFI_DEVICE_PATH *file_path,
                BOOLEAN boot_policy,
                UINTN *buffer_size,
                void *buffer) {

        struct initrd_loader *loader;

        if (!this || !buffer_size || !file_path)
                return EFI_INVALID_PARAMETER;
        if (boot_policy)
                return EFI_UNSUPPORTED;

        loader = (struct initrd_loader *) this;

        if (loader->length == 0 || !loader->address)
                return EFI_NOT_FOUND;

        if (!buffer || *buffer_size < loader->length) {
                *buffer_size = loader->length;
                return EFI_BUFFER_TOO_SMALL;
        }

        memcpy(buffer, loader->address, loader->length);
        *buffer_size = loader->length;
        return EFI_SUCCESS;
}

EFI_STATUS initrd_register(
                const void *initrd_address,
                UINTN initrd_length,
                EFI_HANDLE *ret_initrd_handle) {

        EFI_STATUS err;
        EFI_DEVICE_PATH *dp = (EFI_DEVICE_PATH *) &efi_initrd_device_path;
        EFI_HANDLE handle;
        struct initrd_loader *loader;

        assert(ret_initrd_handle);

        if (!initrd_address || initrd_length == 0)
                return EFI_SUCCESS;

        /* check if a LINUX_INITRD_MEDIA_GUID DevicePath is already registered.
           LocateDevicePath checks for the "closest DevicePath" and returns its handle,
           where as InstallMultipleProtocolInterfaces only matches identical DevicePaths.
         */
        err = BS->LocateDevicePath(&EfiLoadFile2Protocol, &dp, &handle);
        if (err != EFI_NOT_FOUND) /* InitrdMedia is already registered */
                return EFI_ALREADY_STARTED;

        loader = xnew(struct initrd_loader, 1);
        *loader = (struct initrd_loader) {
                .load_file.LoadFile = initrd_load_file,
                .address = initrd_address,
                .length = initrd_length
        };

        /* create a new handle and register the LoadFile2 protocol with the InitrdMediaPath on it */
        err = BS->InstallMultipleProtocolInterfaces(
                        ret_initrd_handle,
                        &DevicePathProtocol, &efi_initrd_device_path,
                        &EfiLoadFile2Protocol, loader,
                        NULL);
        if (err != EFI_SUCCESS)
                free(loader);

        return err;
}

EFI_STATUS initrd_unregister(EFI_HANDLE initrd_handle) {
        EFI_STATUS err;
        struct initrd_loader *loader;

        if (!initrd_handle)
                return EFI_SUCCESS;

        /* get the LoadFile2 protocol that we allocated earlier */
        err = BS->OpenProtocol(
                        initrd_handle, &EfiLoadFile2Protocol, (void **) &loader,
                        NULL, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (err != EFI_SUCCESS)
                return err;

        /* close the handle */
        (void) BS->CloseProtocol(initrd_handle, &EfiLoadFile2Protocol, NULL, NULL);

        /* uninstall all protocols thus destroying the handle */
        err = BS->UninstallMultipleProtocolInterfaces(
                        initrd_handle,
                        &DevicePathProtocol, &efi_initrd_device_path,
                        &EfiLoadFile2Protocol, loader,
                        NULL);
        if (err != EFI_SUCCESS)
                return err;

        initrd_handle = NULL;
        free(loader);
        return EFI_SUCCESS;
}
