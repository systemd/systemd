/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "initrd.h"
#include "macro-fundamental.h"
#include "missing_efi.h"
#include "util.h"

typedef struct {
        EFI_FILE_PROTOCOL efi_file;

        /* Our EFI_FILE_PROTOCOL instance extensions. */
        uint64_t read_pos;
        const void *initrd_addr;
        size_t initrd_size;
} InitrdFsFile;

typedef struct {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL efi_fs;

        /* Our EFI_SIMPLE_FILE_SYSTEM_PROTOCOL instance extensions. */
        InitrdFsFile initrd;
} InitrdFs;

typedef struct {
        EFI_LOAD_FILE_PROTOCOL load_file;

        /* Our EFI_LOAD_FILE_PROTOCOL extensions. */
        const void *address;
        size_t length;
} InitrdLoader;

struct Initrd {
        EFI_HANDLE handle;
        const EFI_DEVICE_PATH *dp;
        union {
                InitrdLoader loader;
                InitrdFs fs;
        };
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

#if defined(__i386__) || defined(__x86_64__)
EFI_STATUS EFIAPI initrd_fs_open(
                EFI_FILE *this, EFI_FILE **ret_file, char16_t *file_name, uint64_t open_mode, uint64_t attributes) {

        if (!this || !ret_file || !file_name || open_mode != EFI_FILE_MODE_READ || attributes != 0)
                return EFI_INVALID_PARAMETER;

        if (!streq16(file_name, STUB_INITRD_FILE_NAME))
                return EFI_NOT_FOUND;

        /* We keep this simple. Only the kernel will read from our FS and will only ever need to fetch our
         * initrd. One file instance is enough for that. */
        *ret_file = this;
        return EFI_SUCCESS;
}

EFI_STATUS EFIAPI initrd_fs_close(EFI_FILE *this) {
        return EFI_SUCCESS;
}

EFI_STATUS EFIAPI initrd_fs_delete(EFI_FILE *this) {
        return EFI_WARN_DELETE_FAILURE;
}

EFI_STATUS EFIAPI initrd_fs_read(InitrdFsFile *this, size_t *buffer_size, void *buffer) {
        if (!this || !buffer || !buffer_size)
                return EFI_INVALID_PARAMETER;

        *buffer_size = MIN(*buffer_size, this->initrd_size - this->read_pos);
        memcpy(buffer, (uint8_t *) this->initrd_addr + this->read_pos, *buffer_size);

        this->read_pos += *buffer_size;
        return EFI_SUCCESS;
}

EFI_STATUS EFIAPI initrd_fs_write(EFI_FILE *this, size_t *buffer_size, void *buffer) {
        return EFI_WRITE_PROTECTED;
}

EFI_STATUS EFIAPI initrd_fs_get_position(EFI_FILE *this, uint64_t *position) {
        return EFI_UNSUPPORTED;
}

EFI_STATUS EFIAPI initrd_fs_set_position(EFI_FILE *this, uint64_t position) {
        return EFI_UNSUPPORTED;
}

EFI_STATUS EFIAPI initrd_fs_get_info(
                InitrdFsFile *this, EFI_GUID *information_type, size_t *buffer_size, void *buffer) {

        if (!this || !information_type || !buffer_size)
                return EFI_INVALID_PARAMETER;

        if (memcmp(information_type, &(EFI_GUID) EFI_FILE_INFO_ID, sizeof(EFI_GUID)) != 0)
                return EFI_UNSUPPORTED;

        size_t name_offset = offsetof(EFI_FILE_INFO, FileName);
        size_t info_size = name_offset + sizeof(STUB_INITRD_FILE_NAME);

        if (!buffer || *buffer_size < info_size)
                return EFI_BUFFER_TOO_SMALL;

        EFI_FILE_INFO info = {
                .Size = info_size,
                .FileSize = this->initrd_size,
        };
        memcpy(buffer, &info, name_offset);
        memcpy((uint8_t *) buffer + name_offset, STUB_INITRD_FILE_NAME, sizeof(STUB_INITRD_FILE_NAME));

        return EFI_SUCCESS;
}

EFI_STATUS EFIAPI initrd_fs_set_info(
                EFI_FILE *this, EFI_GUID *information_type, size_t buffer_size, void *buffer) {
        return EFI_WRITE_PROTECTED;
}

EFI_STATUS EFIAPI initrd_fs_flush(EFI_FILE *this) {
        return EFI_WRITE_PROTECTED;
}

EFI_STATUS EFIAPI initrd_fs_volume_open(InitrdFs *this, InitrdFsFile **ret_root) {
        if (!this || !ret_root)
                return EFI_INVALID_PARAMETER;

        *ret_root = &this->initrd;
        return EFI_SUCCESS;
}

static EFI_STATUS initrd_register_fs(
                const void *initrd_address,
                size_t initrd_size,
                const EFI_DEVICE_PATH *dp,
                Initrd **ret) {

        EFI_STATUS err;

        assert(initrd_address);
        assert(dp);
        assert(ret);

        /* For older kernels that do not support LINUX_INITRD_MEDIA we can provide the initrd by exposing
         * our own EFI filesystem instance and letting the kernel pick it up from a "initrd=" command line
         * parameter added by the stub.
         *
         * To make this work we must register the device path protocol on the device path we pass to
         * LoadImage() so that the created EFI_LOADED_IMAGE_PROTOCOL has a DeviceHandle. The kernel will use
         * that handle to get the EFI_SIMPLE_FILE_SYSTEM_PROTOCOL created here and look up any initrds passed
         * as command line. */

        _cleanup_free_ Initrd *initrd = xnew(Initrd, 1);
        *initrd = (Initrd) {
                .dp = dp,
                .fs = {
                        .efi_fs = {
                                .Revision =  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_REVISION,
                                .OpenVolume = (void *) initrd_fs_volume_open,
                        },
                        .initrd = {
                                .efi_file = {
                                        /* With this revision we do not need to provide *Ex family functions. */
                                        .Revision = EFI_FILE_PROTOCOL_REVISION,
                                        .Open = initrd_fs_open,
                                        .Close = initrd_fs_close,
                                        .Delete = initrd_fs_delete,
                                        .Read = (void *) initrd_fs_read,
                                        .Write = initrd_fs_write,
                                        .GetPosition = initrd_fs_get_position,
                                        .SetPosition = initrd_fs_set_position,
                                        .GetInfo = (void *) initrd_fs_get_info,
                                        .SetInfo = initrd_fs_set_info,
                                        .Flush = initrd_fs_flush,
                                },
                                .initrd_addr = initrd_address,
                                .initrd_size = initrd_size,
                        },
                },
        };

        err = BS->InstallMultipleProtocolInterfaces(
                        &initrd->handle,
                        &(EFI_GUID) EFI_DEVICE_PATH_PROTOCOL_GUID, initrd->dp,
                        &(EFI_GUID) EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID, &initrd->fs.efi_fs,
                        NULL);
        if (err != EFI_SUCCESS)
                return err;

        *ret = TAKE_PTR(initrd);
        return EFI_SUCCESS;
}
#endif

EFI_STATUS initrd_register(
                const void *initrd_address,
                size_t initrd_length,
                const EFI_DEVICE_PATH *install_fs_onto_dp,
                Initrd **ret) {

        EFI_STATUS err;

        assert(ret);

        if (!initrd_address || initrd_length == 0)
                return EFI_SUCCESS;

#if defined(__i386__) || defined(__x86_64__)
        /* Only x86 kernels can load initrds via command line. */
        if (install_fs_onto_dp)
                return initrd_register_fs(initrd_address, initrd_length, install_fs_onto_dp, ret);
#endif

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

        if (initrd->dp)
                err = BS->UninstallMultipleProtocolInterfaces(
                                initrd->handle,
                                &(EFI_GUID) EFI_DEVICE_PATH_PROTOCOL_GUID, initrd->dp,
                                &(EFI_GUID) EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID, &initrd->fs.efi_fs,
                                NULL);
        else
                err = BS->UninstallMultipleProtocolInterfaces(
                                initrd->handle,
                                &(EFI_GUID) EFI_DEVICE_PATH_PROTOCOL_GUID, &efi_initrd_device_path,
                                &(EFI_GUID) EFI_LOAD_FILE2_PROTOCOL_GUID, &initrd->loader,
                                NULL);

        free(initrd);
        return err;
}
