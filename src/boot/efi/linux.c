/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Generic Linux boot protocol using the EFI/PE entry point of the kernel. Passes
 * initrd with the LINUX_INITRD_MEDIA_GUID DevicePath and cmdline with
 * EFI LoadedImageProtocol.
 *
 * This method works for Linux 5.8 and newer on ARM/Aarch64, x86/x68_64 and RISC-V.
 */

#include <efi.h>
#include <efilib.h>

#include "initrd.h"
#include "linux.h"
#include "pe.h"
#include "secure-boot.h"
#include "util.h"

#define STUB_VOLUME_GUID \
        { 0x18033529, 0xb953, 0x46cf, { 0xa8, 0xff, 0x7c, 0x1d, 0x37, 0x10, 0x99, 0xed } }
#define STUB_PAYLOAD_GUID \
        { 0x55c5d1f8, 0x04cd, 0x46b5, { 0x8a, 0x20, 0xe5, 0x6c, 0xbb, 0x30, 0x52, 0xd0 } }

#define EFI_FIRMWARE_VOLUME2_PROTOCOL_GUID \
        { 0x220e73b6, 0x6bdb, 0x4413, { 0x84, 0x05, 0xb9, 0x74, 0xb1, 0x08, 0x61, 0x9a } }

enum {
        EFI_SECTION_PE32             = 0x10,
        EFI_AUTH_STATUS_IMAGE_SIGNED = 0x02,
        EFI_FV2_READ_STATUS          = 0x04,
        EFI_FV2_LOCK_STATUS          = 0x80,
};

typedef struct {
        void *get_volume_attributes;
        void *set_volume_attributes;
        void *read_file;
        void *read_section;
        void *write_file;
        void *get_next_file;
        uint32_t key_size;
        EFI_HANDLE parent_handle;
        void *get_info;
        void *set_info;

        /* End of official EFI_FIRMWARE_VOLUME2_PROTOCOL. Remainder is for our own instances accessed by
         * "this" pointers. */

        const void *payload_addr;
        size_t payload_len;
} StubFirmwareVolume;

EFI_STATUS EFIAPI stub_volume_get_attributes(const StubFirmwareVolume *this, uint64_t *attributes) {
        *attributes = EFI_FV2_READ_STATUS | EFI_FV2_LOCK_STATUS;
        return EFI_SUCCESS;
}

EFI_STATUS EFIAPI stub_volume_set_attributes(const StubFirmwareVolume *this, uint64_t *attributes) {
        return EFI_ACCESS_DENIED;
}

EFI_STATUS EFIAPI stub_volume_read_section(
                const StubFirmwareVolume *this,
                const EFI_GUID *name,
                uint8_t section_type,
                size_t section_instance,
                void **buffer,
                size_t *buffer_size,
                uint32_t *auth_status) {

        if (section_type != EFI_SECTION_PE32 || section_instance != 0 ||
            memcmp(name, &(EFI_GUID) STUB_PAYLOAD_GUID, sizeof(EFI_GUID)) != 0)
                return EFI_NOT_FOUND;

        if (!*buffer) {
                *buffer = xmalloc(this->payload_len);
                *buffer_size = this->payload_len;
        } else
                *buffer_size = MIN(*buffer_size, this->payload_len);
        memcpy(*buffer, this->payload_addr, *buffer_size);

        *auth_status = EFI_AUTH_STATUS_IMAGE_SIGNED;

        return *buffer_size < this->payload_len ? EFI_WARN_BUFFER_TOO_SMALL : EFI_SUCCESS;
}

EFI_STATUS EFIAPI stub_volume_read_file(
                const StubFirmwareVolume *this,
                const EFI_GUID *name,
                void **buffer,
                size_t *buffer_size,
                uint8_t *type,
                uint32_t *attributes,
                uint32_t *auth_status) {

        if (memcmp(name, &(EFI_GUID) STUB_PAYLOAD_GUID, sizeof(EFI_GUID)) != 0)
                return EFI_NOT_FOUND;

        *type = EFI_SECTION_PE32;
        *attributes = 0;
        *buffer_size = this->payload_len;
        if (!buffer)
                return EFI_SUCCESS;

        return stub_volume_read_section(this, name, *type, 0, buffer, buffer_size, auth_status);
}

EFI_STATUS EFIAPI stub_volume_write_file(
                const StubFirmwareVolume *this, uint32_t n_files, uint32_t write_policy, void *file) {
        return EFI_WRITE_PROTECTED;
}

EFI_STATUS EFIAPI stub_volume_next_file(
                const StubFirmwareVolume *this,
                void *key,
                uint8_t *type,
                EFI_GUID *name,
                uint32_t *attributes,
                size_t *size) {
        return EFI_NOT_FOUND;
}

EFI_STATUS EFIAPI stub_volume_get_info(
                const StubFirmwareVolume *this, const EFI_GUID *type, size_t *buffer_size, void *buffer) {
        return EFI_UNSUPPORTED;
}

EFI_STATUS EFIAPI stub_volume_set_info(
                const StubFirmwareVolume *this, const EFI_GUID *type, size_t buffer_size, const void *buffer) {
        return EFI_WRITE_PROTECTED;
}

EFI_STATUS load_image_by_firmware_volume(
                EFI_HANDLE parent, const void *source, size_t len, EFI_HANDLE *ret_image) {
        EFI_STATUS err;

        assert(parent);
        assert(source);
        assert(ret_image);

        static const struct {
                VENDOR_DEVICE_PATH volume;
                EFI_DEVICE_PATH end;
        } _packed_ volume_device_path = {
                .volume = {
                        .Header = {
                                .Type = MEDIA_DEVICE_PATH,
                                .SubType = MEDIA_PIWG_FW_VOL_DP,
                                .Length = { sizeof(volume_device_path.volume), 0 }
                        },
                        .Guid = STUB_VOLUME_GUID
                },
                .end = {
                        .Type = END_DEVICE_PATH_TYPE,
                        .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
                        .Length = { sizeof(volume_device_path.end), 0 }
                }
        };

        static const struct {
                VENDOR_DEVICE_PATH volume;
                VENDOR_DEVICE_PATH payload;
                EFI_DEVICE_PATH end;
        } _packed_ payload_device_path = {
                .volume = {
                        .Header = {
                                .Type = MEDIA_DEVICE_PATH,
                                .SubType = MEDIA_PIWG_FW_VOL_DP,
                                .Length = { sizeof(payload_device_path.volume), 0 }
                        },
                        .Guid = STUB_VOLUME_GUID
                },
                .payload = {
                        .Header = {
                                .Type = MEDIA_DEVICE_PATH,
                                .SubType = MEDIA_PIWG_FW_FILE_DP,
                                .Length = { sizeof(payload_device_path.payload), 0 }
                        },
                        .Guid = STUB_PAYLOAD_GUID
                },
                .end = {
                        .Type = END_DEVICE_PATH_TYPE,
                        .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
                        .Length = { sizeof(payload_device_path.end), 0 }
                }
        };

        EFI_HANDLE volume_handle = NULL;
        EFI_GUID volume_dp_guid = EFI_DEVICE_PATH_PROTOCOL_GUID;
        EFI_GUID volume_guid = EFI_FIRMWARE_VOLUME2_PROTOCOL_GUID;

        StubFirmwareVolume volume = {
                .get_volume_attributes = stub_volume_get_attributes,
                .set_volume_attributes = stub_volume_set_attributes,
                .read_file = stub_volume_read_file,
                .read_section = stub_volume_read_section,
                .write_file = stub_volume_write_file,
                .get_next_file = stub_volume_next_file,
                .key_size = 4,
                .parent_handle = NULL,
                .get_info = stub_volume_get_info,
                .set_info = stub_volume_set_info,

                .payload_addr = source,
                .payload_len = len,
        };

        err = BS->InstallMultipleProtocolInterfaces(
                        &volume_handle,
                        &volume_guid, &volume,
                        &volume_dp_guid, &volume_device_path,
                        NULL);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, u"Error installing firmware volume: %r", err);

        err = BS->LoadImage(false, parent, (EFI_DEVICE_PATH *) &payload_device_path, NULL, 0, ret_image);

        /* We only need the volume during LoadImage. */
        (void) BS->UninstallMultipleProtocolInterfaces(
                        volume_handle,
                        &volume_guid, &volume,
                        &volume_dp_guid, &volume_device_path,
                        NULL);

        return err;
}

EFI_STATUS load_image(EFI_HANDLE parent, const void *source, size_t len, EFI_HANDLE *ret_image) {
        EFI_STATUS err;

        assert(parent);
        assert(source);
        assert(ret_image);

        if (secure_boot_enabled()) {
                /* We want to support unsigned kernel images as payload, which is safe to do under secure
                 * boot because it is embedded in this stub loader (and since it is already running it must
                 * be trusted).
                 *
                 * Unfortunately, there is no direct API to load unsigned images. But we can create a
                 * EFI_FIRMWARE_VOLUME2_PROTOCOL volume (defined in the UEFI Platform Integration
                 * Specification) that exposes our payload. Firmware will implicitly trust images coming from
                 * such devices as they are supposed to be internal to the firmware. */

                err = load_image_by_firmware_volume(parent, source, len, ret_image);
                if (err == EFI_SUCCESS)
                        return EFI_SUCCESS;

                /* Fall back to regular LoadImage if something went wrong or the firmware doesn't want to
                 * use our firmware image. This is likely to fail if the payload is not trusted. */
        }

        static const struct {
                VENDOR_DEVICE_PATH payload;
                EFI_DEVICE_PATH end;
        } _packed_ payload_device_path = {
                .payload = {
                        .Header = {
                                .Type = MEDIA_DEVICE_PATH,
                                .SubType = MEDIA_VENDOR_DP,
                                .Length = { sizeof(payload_device_path.payload), 0 }
                        },
                        .Guid = STUB_PAYLOAD_GUID
                },
                .end = {
                        .Type = END_DEVICE_PATH_TYPE,
                        .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
                        .Length = { sizeof(payload_device_path.end), 0 }
                }
        };

        /* We could pass a NULL device path, but it's nicer to provide something. */
        return BS->LoadImage(
                        false, parent, (EFI_DEVICE_PATH *) &payload_device_path, (void *) source, len, ret_image);
}

EFI_STATUS linux_exec(
                EFI_HANDLE parent,
                const char *cmdline, UINTN cmdline_len,
                const void *linux_buffer, UINTN linux_length,
                const void *initrd_buffer, UINTN initrd_length) {

        uint32_t compat_address;
        EFI_STATUS err;

        assert(parent);
        assert(cmdline || cmdline_len == 0);
        assert(linux_buffer && linux_length > 0);
        assert(initrd_buffer || initrd_length == 0);

        err = pe_kernel_info(linux_buffer, &compat_address);
#if defined(__i386__) || defined(__x86_64__)
        if (err == EFI_UNSUPPORTED)
                /* Kernel is too old to support LINUX_INITRD_MEDIA_GUID, try the deprecated EFI handover
                 * protocol. */
                return linux_exec_efi_handover(
                                parent,
                                cmdline,
                                cmdline_len,
                                linux_buffer,
                                linux_length,
                                initrd_buffer,
                                initrd_length);
#endif
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, u"Bad kernel image: %r", err);

        _cleanup_(unload_imagep) EFI_HANDLE kernel_image = NULL;
        err = load_image(parent, linux_buffer, linux_length, &kernel_image);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, u"Error loading kernel image: %r", err);

        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        err = BS->HandleProtocol(kernel_image, &LoadedImageProtocol, (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, u"Error getting kernel loaded image protocol: %r", err);

        if (cmdline) {
                loaded_image->LoadOptions = xstra_to_str(cmdline);
                loaded_image->LoadOptionsSize = strsize16(loaded_image->LoadOptions);
        }

        _cleanup_(cleanup_initrd) EFI_HANDLE initrd_handle = NULL;
        err = initrd_register(initrd_buffer, initrd_length, &initrd_handle);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, u"Error registering initrd: %r", err);

        err = BS->StartImage(kernel_image, NULL, NULL);

        /* Try calling the kernel compat entry point if one exists. */
        if (err == EFI_UNSUPPORTED && compat_address > 0) {
                EFI_IMAGE_ENTRY_POINT compat_entry =
                                (EFI_IMAGE_ENTRY_POINT) ((uint8_t *) loaded_image->ImageBase + compat_address);
                err = compat_entry(kernel_image, ST);
        }

        return log_error_status_stall(err, u"Error starting kernel image: %r", err);
}
