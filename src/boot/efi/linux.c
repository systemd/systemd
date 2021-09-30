/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "linux.h"
#include "macro-fundamental.h"
#include "missing_efi.h"
#include "util.h"

#define LINUX_INITRD_MEDIA_GUID \
     {0x5568e427, 0x68fc, 0x4f3d, {0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68} }

/* initrd that is served to the kernel */
static VOID *_initrd_buffer = NULL;
/* length of the initrd */
static UINTN _initrd_length = 0;
/* handle of the registerd protocol */
static EFI_HANDLE _initrd_handle = NULL;

/* work-arround for GCC bug 25137 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-braces"

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
                        sizeof(efi_initrd_device_path.vendor)
                },
                LINUX_INITRD_MEDIA_GUID
        },
        .end = {
                END_DEVICE_PATH_TYPE,
                END_ENTIRE_DEVICE_PATH_SUBTYPE,
                sizeof(efi_initrd_device_path.end)
        }
};

#pragma GCC diagnostic pop

EFIAPI EFI_STATUS initrd_load_file(
                EFI_LOAD_FILE_PROTOCOL *this,
                EFI_DEVICE_PATH *file_path,
                BOOLEAN boot_policy,
                UINTN *buffer_size,
                VOID *buffer
);

static const EFI_LOAD_FILE_INTERFACE load_file2_interface = {
        .LoadFile = initrd_load_file
};

EFIAPI EFI_STATUS initrd_load_file(
                EFI_LOAD_FILE_PROTOCOL* this,
                EFI_DEVICE_PATH* file_path,
                BOOLEAN boot_policy,
                UINTN* buffer_size,
                VOID* buffer) {

        if (this != &load_file2_interface || !buffer_size || !file_path)
                return EFI_INVALID_PARAMETER;
        if (boot_policy)
                return EFI_UNSUPPORTED;

        if (!_initrd_length || !_initrd_buffer)
                return EFI_NOT_FOUND;

        if (!buffer || *buffer_size < _initrd_length) {
                *buffer_size = _initrd_length;
                return EFI_BUFFER_TOO_SMALL;
        }

        CopyMem(buffer, _initrd_buffer, _initrd_length);
        *buffer_size = _initrd_length;
        return EFI_SUCCESS;
}

static EFI_STATUS initrd_register(
                VOID *initrd_buffer,
                UINTN initrd_length) {

        EFI_STATUS err;
        EFI_DEVICE_PATH *dp = (EFI_DEVICE_PATH *) &efi_initrd_device_path;
        EFI_HANDLE handle;

        if (!initrd_buffer || !initrd_length)
                return EFI_SUCCESS;

        err = uefi_call_wrapper(BS->LocateDevicePath, 3, &EfiLoadFile2Protocol , &dp, &handle);

        // InitrdMedia is already registered
        if (err != EFI_NOT_FOUND)
                return EFI_ALREADY_STARTED;


        _initrd_buffer = initrd_buffer;
        _initrd_length = initrd_length;

        // crate a new handle and register the LoadFile2 protocol with the InitrdMediaPath on it
        err = uefi_call_wrapper(
                                BS->InstallMultipleProtocolInterfaces, 6,
                                &_initrd_handle,
                                &DevicePathProtocol, &efi_initrd_device_path,
                                &EfiLoadFile2Protocol, &load_file2_interface,
                                NULL);

        return err;
}

static EFI_STATUS initrd_deregister(void) {
        EFI_STATUS err;

        if (_initrd_handle) {
                // uninstall all protocols thus destroying the handle
                err = uefi_call_wrapper(
                                        BS->UninstallMultipleProtocolInterfaces, 6,
                                        &_initrd_handle,
                                        &DevicePathProtocol, &efi_initrd_device_path,
                                        &EfiLoadFile2Protocol, &load_file2_interface,
                                        NULL
                );

                if (!EFI_ERROR(err)) {
                        _initrd_handle = NULL;
                        _initrd_buffer = NULL;
                        _initrd_length = 0;
                }

                return err;
        }

        return EFI_SUCCESS;
}

EFI_STATUS linux_exec(
                EFI_HANDLE image,
                CHAR8 *cmdline, UINTN cmdline_len,
                VOID *linux_buffer, UINTN linux_length,
                VOID *initrd_buffer, UINTN initrd_size) {

        EFI_STATUS err;
        EFI_HANDLE handle;
        EFI_LOADED_IMAGE *loaded_image;

        assert(image);
        assert(cmdline || cmdline_len == 0);
        assert(linux_buffer);
        assert(initrd_buffer || initrd_size == 0);

        err = uefi_call_wrapper(
                                BS->OpenProtocol, 6,
                                image, &LoadedImageProtocol, (VOID **) &loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(err))
                return EFI_LOAD_ERROR;

        err = uefi_call_wrapper(
                                BS->LoadImage, 6,
                                false, image, (EFI_DEVICE_PATH *) loaded_image->FilePath,
                                linux_buffer, linux_length, &handle);
        if (EFI_ERROR(err))
                return EFI_LOAD_ERROR;

        err = uefi_call_wrapper(
                                BS->OpenProtocol, 6,
                                handle, &LoadedImageProtocol, (VOID **) &loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);

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
        err = uefi_call_wrapper(BS->StartImage, 3, handle, NULL, NULL);

        // cleanup
        initrd_deregister();
        uefi_call_wrapper(BS->UnloadImage, 1, handle);
        return err;
}
