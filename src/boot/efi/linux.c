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
#include "util.h"

EFI_STATUS load_trusted_image(EFI_HANDLE parent, const void *source, size_t len, EFI_HANDLE *ret_image) {
        EFI_STATUS err;

        /* We want to be nice and provide a device path. Since the kernel is embedded into our stub we can
         * just reuse our own device path. */
        EFI_DEVICE_PATH *loaded_dp;
        err = BS->HandleProtocol(
                        parent, &(EFI_GUID) EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID, (void **) &loaded_dp);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, u"Error getting loaded image device path: %r", err);

        return BS->LoadImage(false, parent, loaded_dp, (void *) source, len, ret_image);
}

EFI_STATUS linux_exec(
                EFI_HANDLE parent,
                const char *cmdline, UINTN cmdline_len,
                const void *linux_buffer, UINTN linux_length,
                const void *initrd_buffer, UINTN initrd_length) {

        uint32_t kernel_alignment, kernel_size_of_image, kernel_entry_address = 0;
        EFI_STATUS err;

        assert(parent);
        assert(cmdline || cmdline_len == 0);
        assert(linux_buffer && linux_length > 0);
        assert(initrd_buffer || initrd_length == 0);

        /* get the necessary fields from the PE header */
        err = pe_kernel_info(linux_buffer, &kernel_entry_address, &kernel_size_of_image, &kernel_alignment);
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
        err = load_trusted_image(parent, linux_buffer, linux_length, &kernel_image);
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
        if (err == EFI_UNSUPPORTED && kernel_entry_address > 0) {
                EFI_IMAGE_ENTRY_POINT compat_entry =
                                (EFI_IMAGE_ENTRY_POINT) ((uint8_t *) loaded_image->ImageBase + kernel_entry_address);
                err = compat_entry(kernel_image, ST);
        }

        return err;
}
