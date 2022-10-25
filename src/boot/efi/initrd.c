/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "initrd.h"
#include "macro-fundamental.h"
#include "missing_efi.h"
#include "util.h"

typedef struct {
        EFI_LOAD_FILE_PROTOCOL load_file;

        /* Our EFI_LOAD_FILE_PROTOCOL extensions. */
        const void *address;
        size_t length;
} InitrdLoader;

struct Initrd {
        EFI_HANDLE handle;
        InitrdLoader loader;
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

EFIAPI EFI_STATUS initrd_load_file(
                InitrdLoader *this,
                EFI_DEVICE_PATH *file_path,
                BOOLEAN boot_policy,
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
                Initrd **ret) {

        EFI_STATUS err;

        assert(ret);

        if (!initrd_address || initrd_length == 0)
                return EFI_SUCCESS;

        _cleanup_free_ Initrd *initrd = xnew(Initrd, 1);
        *initrd = (Initrd) {
                .loader = {
                        .load_file.LoadFile = (void *) initrd_load_file,
                        .address = initrd_address,
                        .length = initrd_length,
                },
        };

        err = BS->InstallMultipleProtocolInterfaces(
                        &initrd->handle,
                        &DevicePathProtocol, &efi_initrd_device_path,
                        &EfiLoadFile2Protocol, &initrd->loader,
                        NULL);
        if (err != EFI_SUCCESS)
                return err;

        *ret = TAKE_PTR(initrd);
        return EFI_SUCCESS;
}

EFI_STATUS initrd_unregister(Initrd *initrd) {
        EFI_STATUS err;

        if (!initrd)
                return EFI_SUCCESS;

        err = BS->UninstallMultipleProtocolInterfaces(
                        initrd->handle,
                        &DevicePathProtocol, &efi_initrd_device_path,
                        &EfiLoadFile2Protocol, &initrd->loader,
                        NULL);

        free(initrd);
        return err;
}
