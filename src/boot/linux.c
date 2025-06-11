/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Generic Linux boot protocol using the EFI/PE entry point of the kernel. Passes
 * initrd with the LINUX_INITRD_MEDIA_GUID DevicePath and cmdline with
 * EFI LoadedImageProtocol.
 *
 * This method works for Linux 5.8 and newer on ARM/Aarch64, x86/x68_64 and RISC-V.
 */

#include "device-path-util.h"
#include "efi-log.h"
#include "initrd.h"
#include "linux.h"
#include "pe.h"
#include "proto/device-path.h"
#include "proto/loaded-image.h"
#include "secure-boot.h"
#include "shim.h"
#include "util.h"

#define STUB_PAYLOAD_GUID \
        { 0x55c5d1f8, 0x04cd, 0x46b5, { 0x8a, 0x20, 0xe5, 0x6c, 0xbb, 0x30, 0x52, 0xd0 } }

static EFI_STATUS load_via_boot_services(
                EFI_HANDLE parent,
                EFI_LOADED_IMAGE_PROTOCOL* parent_loaded_image,
                uint32_t compat_entry_point,
                const struct iovec *kernel,
                const struct iovec *initrd) {
        _cleanup_(unload_imagep) EFI_HANDLE kernel_image = NULL;
        EFI_LOADED_IMAGE_PROTOCOL* loaded_image = NULL;
        EFI_STATUS err;

        VENDOR_DEVICE_PATH device_node = {
                .Header = {
                        .Type = MEDIA_DEVICE_PATH,
                        .SubType = MEDIA_VENDOR_DP,
                        .Length = sizeof(device_node),
                },
                .Guid = STUB_PAYLOAD_GUID,
        };

        _cleanup_free_ EFI_DEVICE_PATH* file_path = device_path_replace_node(parent_loaded_image->FilePath, NULL, &device_node.Header);

        err = BS->LoadImage(/* BootPolicy= */false,
                            parent,
                            file_path,
                            kernel->iov_base,
                            kernel->iov_len,
                            &kernel_image);

        if (err != EFI_SUCCESS)
                return log_error_status(EFI_LOAD_ERROR, "Error loading inner kernel with shim: %m");

        err = BS->HandleProtocol(
                        kernel_image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(EFI_LOAD_ERROR, "Error getting kernel image from protocol from shim: %m");

        _cleanup_(cleanup_initrd) EFI_HANDLE initrd_handle = NULL;
        err = initrd_register(initrd->iov_base, initrd->iov_len, &initrd_handle);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error registering initrd: %m");

        log_wait();

        err = BS->StartImage(kernel_image, NULL, NULL);
        /* Try calling the kernel compat entry point if one exists. */
        if (err == EFI_UNSUPPORTED && compat_entry_point > 0) {
                EFI_IMAGE_ENTRY_POINT compat_entry =
                        (EFI_IMAGE_ENTRY_POINT) ((const uint8_t *) loaded_image->ImageBase + compat_entry_point);
                err = compat_entry(kernel_image, ST);
        }

        return log_error_status(err, "Error starting kernel image with shim: %m");
}

EFI_STATUS linux_exec(
                EFI_HANDLE parent,
                const char16_t *cmdline,
                const struct iovec *kernel,
                const struct iovec *initrd) {

        size_t kernel_size_in_memory = 0;
        uint32_t compat_entry_point, entry_point;
        uint64_t image_base;
        EFI_STATUS err;

        assert(parent);
        assert(iovec_is_set(kernel));
        assert(iovec_is_valid(initrd));

        err = pe_kernel_info(kernel->iov_base, &entry_point, &compat_entry_point, &image_base, &kernel_size_in_memory);
#if defined(__i386__) || defined(__x86_64__)
        if (err == EFI_UNSUPPORTED)
                /* Kernel is too old to support LINUX_INITRD_MEDIA_GUID, try the deprecated EFI handover
                 * protocol. */
                return linux_exec_efi_handover(
                                parent,
                                cmdline,
                                kernel,
                                initrd,
                                kernel_size_in_memory);
#endif
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Bad kernel image: %m");

        EFI_LOADED_IMAGE_PROTOCOL* parent_loaded_image;
        err = BS->HandleProtocol(
                        parent, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &parent_loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot get parent loaded image: %m");

        /* If shim provides LoadImage, it comes from version 16.1 or later and does the following:
         * - It keeps a database of all PE sections that it already authenticated.
         * - shim's LoadImage always verifies PE images against denylists: dbx, mokx, sbat.
         * - If the PE image was not authenticated as a PE section it will also:
         *   + verify it against allowlists: db, mok
         *   + measure it on PCR 4
         *
         * In our case, we are loading a PE section that was already authenticated as part of the UKI.
         * So in contrast to a normal UEFI LoadImage, shim will verify extra denylists (mokx, sbat),
         * while skipping all allowlists and measurements.
         *
         * See https://github.com/rhboot/shim/blob/main/README.md#shim-loader-protocol
         */
        if (secure_boot_enabled() && shim_loader_available())
                return load_via_boot_services(
                                parent,
                                parent_loaded_image,
                                compat_entry_point,
                                kernel,
                                initrd);

        err = pe_kernel_check_no_relocation(kernel->iov_base);
        if (err != EFI_SUCCESS)
                return err;

        const PeSectionHeader *headers;
        size_t n_headers;

        /* Do we need to validate anyting here? the len? */
        err = pe_section_table_from_base(kernel->iov_base, &headers, &n_headers);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot read sections: %m");

        /* Do we need to ensure under 4gb address on x86? */
        _cleanup_pages_ Pages loaded_kernel_pages = xmalloc_pages(
                        AllocateAnyPages, EfiLoaderCode, EFI_SIZE_TO_PAGES(kernel_size_in_memory), 0);

        uint8_t* loaded_kernel = PHYSICAL_ADDRESS_TO_POINTER(loaded_kernel_pages.addr);
        FOREACH_ARRAY(h, headers, n_headers) {
                if (h->PointerToRelocations != 0)
                        return log_error_status(EFI_LOAD_ERROR, "Inner kernel image contains sections with relocations, which we do not support.");
                if (h->SizeOfRawData == 0)
                        continue;

                if ((h->VirtualAddress < image_base)
                    || (h->VirtualAddress - image_base + h->SizeOfRawData > kernel_size_in_memory))
                        return log_error_status(EFI_LOAD_ERROR, "Section would write outside of memory");
                memcpy(loaded_kernel + h->VirtualAddress - image_base,
                       (const uint8_t*)kernel->iov_base + h->PointerToRawData,
                       h->SizeOfRawData);
                memzero(loaded_kernel + h->VirtualAddress + h->SizeOfRawData,
                        h->VirtualSize - h->SizeOfRawData);
        }

        _cleanup_free_ EFI_LOADED_IMAGE_PROTOCOL* loaded_image = xnew(EFI_LOADED_IMAGE_PROTOCOL, 1);

        VENDOR_DEVICE_PATH device_node = {
                     .Header = {
                             .Type = MEDIA_DEVICE_PATH,
                             .SubType = MEDIA_VENDOR_DP,
                             .Length = sizeof(device_node),
                     },
                     .Guid = STUB_PAYLOAD_GUID,
        };

        _cleanup_free_ EFI_DEVICE_PATH* file_path = device_path_replace_node(parent_loaded_image->FilePath, NULL, &device_node.Header);

        *loaded_image = (EFI_LOADED_IMAGE_PROTOCOL) {
                .Revision = 0x1000,
                .ParentHandle = parent,
                .SystemTable = ST,
                .DeviceHandle = parent_loaded_image->DeviceHandle,
                .FilePath = file_path,
                .ImageBase = loaded_kernel,
                .ImageSize = kernel_size_in_memory,
                .ImageCodeType = /*EFI_LOADER_CODE*/1,
                .ImageDataType = /*EFI_LOADER_DATA*/2,
        };

        if (cmdline) {
                loaded_image->LoadOptions = (void *) cmdline;
                loaded_image->LoadOptionsSize = strsize16(loaded_image->LoadOptions);
        }

        _cleanup_(cleanup_initrd) EFI_HANDLE initrd_handle = NULL;
        err = initrd_register(initrd->iov_base, initrd->iov_len, &initrd_handle);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error registering initrd: %m");

        EFI_HANDLE kernel_image = NULL;

        err = BS->InstallMultipleProtocolInterfaces(
                        &kernel_image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), loaded_image,
                        NULL);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot install loaded image protocol: %m");

        log_wait();

        if (entry_point > 0) {
                EFI_IMAGE_ENTRY_POINT entry =
                        (EFI_IMAGE_ENTRY_POINT) ((const uint8_t *) loaded_image->ImageBase + entry_point);
                err = entry(kernel_image, ST);
        } else if (compat_entry_point > 0) {
                /* Try calling the kernel compat entry point if one exists. */
                EFI_IMAGE_ENTRY_POINT compat_entry =
                                (EFI_IMAGE_ENTRY_POINT) ((const uint8_t *) loaded_image->ImageBase + compat_entry_point);
                err = compat_entry(kernel_image, ST);
        }

        EFI_STATUS uninstall_err = BS->UninstallMultipleProtocolInterfaces(
                        kernel_image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), loaded_image,
                        NULL);
        if (uninstall_err != EFI_SUCCESS)
                return log_error_status(uninstall_err, "Cannot uninstall loaded image protocol: %m");

        return log_error_status(err, "Error starting kernel image: %m");
}
