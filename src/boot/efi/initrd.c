/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "initrd.h"
#include "macro-fundamental.h"
#include "proto/device-path.h"
#include "proto/load-file.h"
#include "util.h"

#define LINUX_EFI_INITRD_MEDIA_GUID \
        GUID_DEF(0x5568e427, 0x68fc, 0x4f3d, 0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68)
#define LINUX_EFI_INITRD_LF2_PROTOCOL_GUID\
        GUID_DEF(0xf9e3378e, 0xb3b1, 0x423a, 0xbd, 0x9a, 0x2d, 0x08, 0x60, 0x28, 0x7f, 0x72)

struct InitrdLoader {
        EFI_LOAD_FILE_PROTOCOL load_file;
        const void *address;
        size_t length;
        EFI_HANDLE dp_handle;
        EFI_HANDLE image_handle;
};

/* static structure for LINUX_EFI_INITRD_MEDIA device path
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
                        .Length = sizeof(efi_initrd_device_path.vendor),
                },
                .Guid = LINUX_EFI_INITRD_MEDIA_GUID
        },
        .end = {
                .Type = END_DEVICE_PATH_TYPE,
                .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
                .Length = sizeof(efi_initrd_device_path.end),
        }
};

static EFIAPI EFI_STATUS initrd_load_file(
                InitrdLoader *this,
                EFI_DEVICE_PATH *file_path,
                bool boot_policy,
                size_t *buffer_size,
                void *buffer) {

        if (!this || !buffer_size || !file_path)
                return EFI_INVALID_PARAMETER;
        if (boot_policy)
                return EFI_UNSUPPORTED;
        if (this->length == 0 || !this->address)
                return EFI_NOT_FOUND;
        if (!buffer || *buffer_size < this->length) {
                *buffer_size = this->length;
                return EFI_BUFFER_TOO_SMALL;
        }

        memcpy(buffer, this->address, this->length);
        *buffer_size = this->length;
        return EFI_SUCCESS;
}

EFI_STATUS initrd_register(
                const void *initrd_address,
                size_t initrd_length,
                EFI_HANDLE image,
                InitrdLoader **ret_loader) {

        EFI_STATUS err;

        assert(ret_loader);

        if (!initrd_address || initrd_length == 0) {
                *ret_loader = NULL;
                return EFI_SUCCESS;
        }

        _cleanup_free_ InitrdLoader *loader = xnew(InitrdLoader, 1);
        *loader = (InitrdLoader) {
                .load_file.LoadFile = (void*) initrd_load_file,
                .address = initrd_address,
                .length = initrd_length,
                .image_handle = image,
        };

        if (image) {
                /* Prefer the newer protocol as it does not require a globally unique device path. This
                 * allows intermediate boot loaders to use the same protocol on their handle to receive
                 * payloads without interfering with us loading the kernel. */
                err = BS->InstallMultipleProtocolInterfaces(
                                &loader->image_handle,
                                MAKE_GUID_PTR(LINUX_EFI_INITRD_LF2_PROTOCOL), loader,
                                NULL);
                if (err != EFI_SUCCESS)
                        return err;
        } else {
                /* Check if a LINUX_EFI_INITRD_MEDIA_GUID DevicePath is already registered.
                 * LocateDevicePath checks for the "closest DevicePath" and returns its handle,
                 * whereas InstallMultipleProtocolInterfaces only matches identical DevicePaths. */
                EFI_HANDLE handle;
                EFI_DEVICE_PATH *dp = (EFI_DEVICE_PATH *) &efi_initrd_device_path;
                err = BS->LocateDevicePath(MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), &dp, &handle);
                if (err != EFI_NOT_FOUND) /* InitrdMedia is already registered */
                        return EFI_ALREADY_STARTED;

                /* create a new handle and register the LoadFile2 protocol with the InitrdMediaPath on it */
                err = BS->InstallMultipleProtocolInterfaces(
                                &loader->dp_handle,
                                MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), &efi_initrd_device_path,
                                MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), loader,
                                NULL);
                if (err != EFI_SUCCESS)
                        return err;
        }

        *ret_loader = TAKE_PTR(loader);
        return EFI_SUCCESS;
}

EFI_STATUS initrd_unregister(InitrdLoader *loader) {
        EFI_STATUS err;

        if (!loader)
                return EFI_SUCCESS;

        if (loader->image_handle)
                err = BS->UninstallMultipleProtocolInterfaces(
                                loader->image_handle,
                                MAKE_GUID_PTR(LINUX_EFI_INITRD_LF2_PROTOCOL), loader,
                                NULL);
        else
                err = BS->UninstallMultipleProtocolInterfaces(
                                loader->dp_handle,
                                MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), &efi_initrd_device_path,
                                MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), loader,
                                NULL);

        if (err != EFI_SUCCESS)
                return err;

        free(loader);
        return EFI_SUCCESS;
}
