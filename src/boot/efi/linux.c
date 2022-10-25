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

#define STUB_PAYLOAD_GUID \
        { 0x55c5d1f8, 0x04cd, 0x46b5, { 0x8a, 0x20, 0xe5, 0x6c, 0xbb, 0x30, 0x52, 0xd0 } }

/* We could pass a NULL device path, but it's nicer to provide something and it allows us to identify
 * the loaded image from within the security hooks. We also need this in case where we need to provide the
 * initrd via EFI fs. */
static const struct {
        VENDOR_DEVICE_PATH payload;
        EFI_DEVICE_PATH end;
} _packed_ payload_device_path = {
        .payload = {
                .Header = {
                        .Type = MEDIA_DEVICE_PATH,
                        .SubType = MEDIA_VENDOR_DP,
                        .Length = { sizeof(payload_device_path.payload), 0 },
                },
                .Guid = STUB_PAYLOAD_GUID,
        },
        .end = {
                .Type = END_DEVICE_PATH_TYPE,
                .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
                .Length = { sizeof(payload_device_path.end), 0 },
        },
};

static EFIAPI EFI_STATUS security_hook(
                const SecurityOverride *this, uint32_t authentication_status, const EFI_DEVICE_PATH *file) {

        assert(this);
        assert(this->hook == security_hook);

        if (file == this->payload_device_path)
                return EFI_SUCCESS;

        return this->original_security->FileAuthenticationState(
                        this->original_security, authentication_status, file);
}

static EFIAPI EFI_STATUS security2_hook(
                const SecurityOverride *this,
                const EFI_DEVICE_PATH *device_path,
                void *file_buffer,
                size_t file_size,
                BOOLEAN boot_policy) {

        assert(this);
        assert(this->hook == security2_hook);

        if (file_buffer == this->payload && file_size == this->payload_len &&
            device_path == this->payload_device_path)
                return EFI_SUCCESS;

        return this->original_security2->FileAuthentication(
                        this->original_security2, device_path, file_buffer, file_size, boot_policy);
}

EFI_STATUS load_image(EFI_HANDLE parent, const void *source, size_t len, EFI_HANDLE *ret_image) {
        assert(parent);
        assert(source);
        assert(ret_image);

        /* We want to support unsigned kernel images as payload, which is safe to do under secure boot
         * because it is embedded in this stub loader (and since it is already running it must be trusted). */
        SecurityOverride security_override = {
                .hook = security_hook,
                .payload = source,
                .payload_len = len,
                .payload_device_path = &payload_device_path.payload.Header,
        }, security2_override = {
                .hook = security2_hook,
                .payload = source,
                .payload_len = len,
                .payload_device_path = &payload_device_path.payload.Header,
        };

        install_security_override(&security_override, &security2_override);

        /* If source/len is ever removed here in favor of EFI_LOAD_FILE2_PROTOCOL, than the initrd fs code
         * would need adjustments as the firmware would try to read the kernel from the fs instance first. */
        EFI_STATUS ret = BS->LoadImage(
                        /*BootPolicy=*/false,
                        parent,
                        (EFI_DEVICE_PATH *) &payload_device_path,
                        (void *) source,
                        len,
                        ret_image);

        uninstall_security_override(&security_override, &security2_override);

        return ret;
}

EFI_STATUS linux_exec(
                EFI_HANDLE parent,
                const char *cmdline, UINTN cmdline_len,
                const void *linux_buffer, UINTN linux_length,
                const void *initrd_buffer, UINTN initrd_length) {

        bool has_initrd_media_support;
        uint32_t compat_address;
        EFI_STATUS err;

        assert(parent);
        assert(cmdline || cmdline_len == 0);
        assert(linux_buffer && linux_length > 0);
        assert(initrd_buffer || initrd_length == 0);

        err = pe_kernel_info(linux_buffer, &compat_address, &has_initrd_media_support);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, u"Bad kernel image: %r", err);

        _cleanup_(cleanup_initrd) Initrd *initrd_handle = NULL;
        err = initrd_register(
                        initrd_buffer,
                        initrd_length,
                        has_initrd_media_support ? NULL : (const EFI_DEVICE_PATH *) &payload_device_path,
                        &initrd_handle);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, u"Error registering initrd: %r", err);

        _cleanup_(unload_imagep) EFI_HANDLE kernel_image = NULL;
        err = load_image(parent, linux_buffer, linux_length, &kernel_image);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, u"Error loading kernel image: %r", err);

        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        err = BS->HandleProtocol(kernel_image, &LoadedImageProtocol, (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, u"Error getting kernel loaded image protocol: %r", err);

        /* If we provide the initrd by fs, we have to tell the kernel where to find it on the fs! */
        if (cmdline) {
                _cleanup_free_ char16_t *tmp = xstra_to_str(cmdline);
                loaded_image->LoadOptions = has_initrd_media_support ?
                                TAKE_PTR(tmp) :
                                xpool_print(u"initrd=" STUB_INITRD_FILE_NAME " %s", tmp);
        } else if (!has_initrd_media_support)
                loaded_image->LoadOptions = xstrdup16(u"initrd=" STUB_INITRD_FILE_NAME);
        loaded_image->LoadOptionsSize = strsize16(loaded_image->LoadOptions);

        err = BS->StartImage(kernel_image, NULL, NULL);

        /* Try calling the kernel compat entry point if one exists. */
        if (err == EFI_UNSUPPORTED && compat_address > 0) {
                EFI_IMAGE_ENTRY_POINT compat_entry =
                                (EFI_IMAGE_ENTRY_POINT) ((uint8_t *) loaded_image->ImageBase + compat_address);
                err = compat_entry(kernel_image, ST);
        }

        return log_error_status_stall(err, u"Error starting kernel image: %r", err);
}
