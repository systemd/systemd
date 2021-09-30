/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "initrd.h"
#include "missing_efi.h"
#include "macro-fundamental.h"

// initrd that is served to the kernel
static VOID* _initrd_buffer = NULL;
// length of the initrd
static UINTN _initrd_length = 0;

// handle of the registerd protocol
static EFI_HANDLE _initrd_handle = NULL;


// work-arround for GCC bug 25137
#pragma GCC diagnostic ignored "-Wmissing-braces"

// static structure for LINUX_INITRD_MEDIA device path
// see https://github.com/torvalds/linux/blob/v5.13/drivers/firmware/efi/libstub/efi-stub-helper.c
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

EFIAPI
EFI_STATUS _initrd_load_file(
        EFI_LOAD_FILE_PROTOCOL* this,
        EFI_DEVICE_PATH* file_path,
        BOOLEAN boot_policy,
        UINTN* buffer_size,
        VOID* buffer
);

static const EFI_LOAD_FILE_INTERFACE load_file2_interface = {
        .LoadFile = _initrd_load_file
};

EFIAPI
EFI_STATUS _initrd_load_file(
        EFI_LOAD_FILE_PROTOCOL* this,
        EFI_DEVICE_PATH* file_path,
        BOOLEAN boot_policy,
        UINTN* buffer_size,
        VOID* buffer
) {
        if (!this || this != &load_file2_interface || !buffer_size || !file_path)
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

EFI_STATUS initrd_register(
        VOID* initrd_buffer,
        UINTN initrd_length
) {
        EFI_STATUS err;
        EFI_DEVICE_PATH* dp = (EFI_DEVICE_PATH*) &efi_initrd_device_path;
        EFI_HANDLE handle;

        if (!initrd_buffer || !initrd_length)
                return EFI_SUCCESS;

        err = uefi_call_wrapper(BS->LocateDevicePath, 3, &EfiLoadFile2Protocol , &dp, &handle);

        if (err == EFI_NOT_FOUND) {
                _initrd_buffer = initrd_buffer;
                _initrd_length = initrd_length;

                // crate a new handle and register the LoadFile2 protocol with the InitrdMediaPath on it
                err = uefi_call_wrapper(
                        BS->InstallMultipleProtocolInterfaces, 6,
                        &_initrd_handle,
                        &DevicePathProtocol, &efi_initrd_device_path,
                        &EfiLoadFile2Protocol, &load_file2_interface,
                        NULL
                );

                return err;
        } else {
                // InitrdMedia is already registered
                return EFI_ALREADY_STARTED;
        }
}

EFI_STATUS initrd_deregister(void) {
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

                if (err == EFI_SUCCESS)
                        _initrd_handle = NULL;

                return err;
        }

        return EFI_SUCCESS;
}
