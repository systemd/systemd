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
#include "missing_efi.h"
#include "pe.h"
#include "secure-boot.h"
#include "util.h"

#if HAVE_ZSTD
#  include "zstd.h"
#endif

EFI_STATUS decompress_zstd(const void *src, size_t src_size, void **dst, size_t *dst_size) {
#if HAVE_ZSTD
        assert(src && src_size > 0);
        assert(dst);
        assert(dst_size);

        unsigned long long size = ZSTD_getFrameContentSize(src, src_size);
        if (size == ZSTD_CONTENTSIZE_ERROR)
                return EFI_UNSUPPORTED;
        if (size == ZSTD_CONTENTSIZE_UNKNOWN)
                return EFI_INVALID_PARAMETER;
        if (size > SIZE_MAX)
                return EFI_BAD_BUFFER_SIZE;

        _cleanup_free_ void *buf = xmalloc(size);
        size_t r = ZSTD_decompress(buf, size, src, src_size);
        if (ZSTD_isError(r))
                return log_error_status_stall(
                                EFI_LOAD_ERROR, u"ZSTD decompression error: %a", ZSTD_getErrorName(r));
        if (r != size)
                return EFI_BAD_BUFFER_SIZE;

        *dst = TAKE_PTR(buf);
        *dst_size = size;
        return EFI_SUCCESS;
#endif

        return EFI_UNSUPPORTED;
}

static struct TrustedState {
        EFI_SECURITY_FILE_AUTHENTICATION_STATE origianl_file_authentication;
        EFI_SECURITY2_FILE_AUTHENTICATION original_file_authentication2;
        const void *buffer;
        size_t size;
        const EFI_DEVICE_PATH *device_path;
} *trusted = NULL;

static EFIAPI EFI_STATUS security_hook(
                const EFI_SECURITY_ARCH_PROTOCOL *this,
                uint32_t authentication_status,
                const EFI_DEVICE_PATH *file) {

        assert(trusted);
        assert(trusted->origianl_file_authentication);

        if (file == trusted->device_path)
                return EFI_SUCCESS;

        return trusted->origianl_file_authentication(this, authentication_status, file);
}

static EFIAPI EFI_STATUS security2_hook(
                const EFI_SECURITY2_ARCH_PROTOCOL *this,
                const EFI_DEVICE_PATH *device_path,
                void *file_buffer,
                size_t file_size,
                BOOLEAN boot_policy) {

        assert(trusted);
        assert(trusted->original_file_authentication2);

        if (file_buffer == trusted->buffer && file_size == trusted->size && device_path == trusted->device_path)
                return EFI_SUCCESS;

        return trusted->original_file_authentication2(this, device_path, file_buffer, file_size, boot_policy);
}

EFI_STATUS load_image(EFI_HANDLE parent, const void *source, size_t len, EFI_HANDLE *ret_image) {
        EFI_STATUS err;

        /* We want to be nice and provide a device path. Since the kernel is embedded into our stub we can
         * just reuse our own device path. */
        EFI_DEVICE_PATH *loaded_dp;
        err = BS->HandleProtocol(
                        parent, &(EFI_GUID) EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID, (void **) &loaded_dp);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, u"Error getting loaded image device path: %r", err);

        bool use_secure_boot_workaround = true;
        (void) efivar_get_boolean_u8(LOADER_GUID, u"StubSecureBootWorkaround", &use_secure_boot_workaround);

        if (!secure_boot_enabled() || !use_secure_boot_workaround)
                return BS->LoadImage(false, parent, loaded_dp, (void *) source, len, ret_image);

        /* We want to support unsigned kernel images (which is safe to do since it is embedded in this stub,
         * which is already running and therefore trusted). We hook into security arch protocol to trick the
         * firmware into trusting our image.
         *
         * This is really a nasty hack, but better than seeing a security violation error. Note that these
         * protocols are technically internal to the platform and not some kind of public API. They may not
         * even be available (hence why we do this opportunistically). */

        EFI_SECURITY_ARCH_PROTOCOL *security = NULL;
        EFI_SECURITY2_ARCH_PROTOCOL *security2 = NULL;

        (void) BS->LocateProtocol((EFI_GUID *) EFI_SECURITY_ARCH_PROTOCOL_GUID, NULL, (void **) &security);
        (void) BS->LocateProtocol((EFI_GUID *) EFI_SECURITY2_ARCH_PROTOCOL_GUID, NULL, (void **) &security2);

        trusted = &(struct TrustedState) {
                .buffer = source,
                .size = len,
                .device_path = loaded_dp,
                .origianl_file_authentication = security ? security->FileAuthenticationState : NULL,
                .original_file_authentication2 = security2 ? security2->FileAuthentication : NULL,
        };

        if (security)
                security->FileAuthenticationState = security_hook;
        if (security2)
                security2->FileAuthentication = security2_hook;

        err = BS->LoadImage(false, parent, loaded_dp, (void *) source, len, ret_image);

        if (security)
                security->FileAuthenticationState = trusted->origianl_file_authentication;
        if (security2)
                security2->FileAuthentication = trusted->original_file_authentication2;
        trusted = NULL;

        return err;
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

        _cleanup_free_ void *linux_decompressed = NULL;
        size_t linux_decompressed_size = 0;
        err = decompress_zstd(linux_buffer, linux_length, &linux_decompressed, &linux_decompressed_size);
        if (err == EFI_SUCCESS) {
                linux_buffer = linux_decompressed;
                linux_length = linux_decompressed_size;
        } else if (err != EFI_UNSUPPORTED)
                return err;

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
                return err;

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
                return err;

        err = BS->StartImage(kernel_image, NULL, NULL);

        /* Try calling the kernel compat entry point if one exists. */
        if (err == EFI_UNSUPPORTED && compat_address > 0) {
                EFI_IMAGE_ENTRY_POINT compat_entry =
                                (EFI_IMAGE_ENTRY_POINT) ((uint8_t *) loaded_image->ImageBase + compat_address);
                err = compat_entry(kernel_image, ST);
        }

        return err;
}
