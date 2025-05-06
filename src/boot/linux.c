/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Generic Linux boot protocol using the EFI/PE entry point of the kernel. Passes
 * initrd with the LINUX_INITRD_MEDIA_GUID DevicePath and cmdline with
 * EFI LoadedImageProtocol.
 *
 * This method works for Linux 5.8 and newer on ARM/Aarch64, x86/x68_64 and RISC-V.
 */

#include "initrd.h"
#include "linux.h"
#include "pe.h"
#include "proto/device-path.h"
#include "proto/loaded-image.h"
#include "secure-boot.h"
#include "util.h"

EFI_STATUS linux_exec(
                EFI_HANDLE parent,
                const char16_t *cmdline,
                const struct iovec *kernel,
                const struct iovec *initrd) {

        size_t kernel_size_in_memory = 0;
        uint32_t compat_address, address;
        uint64_t image_base;
        EFI_STATUS err;

        assert(parent);
        assert(iovec_is_set(kernel));
        assert(iovec_is_valid(initrd));

        err = pe_kernel_info(kernel->iov_base, &address, &compat_address, &image_base, &kernel_size_in_memory);
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

        const PeSectionHeader *headers;
        size_t n_headers;

        /* Do we need to validate anyting here? the len? */
        err = pe_section_table_from_base(kernel->iov_base, &headers, &n_headers);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot read sections: %m");

        /* Do we need to ensure under 4gb address on x86? */
        _cleanup_pages_ Pages loaded_kernel_pages = xmalloc_pages(
                        AllocateAnyPages, EfiLoaderCode, EFI_SIZE_TO_PAGES(kernel_size_in_memory), 0);

        uint8_t* loaded_kernel = (uint8_t*)PHYSICAL_ADDRESS_TO_POINTER(loaded_kernel_pages.addr);
        FOREACH_ARRAY(h, headers, n_headers) {
                if (h->PointerToRelocations != 0)
                        return log_error_status(EFI_LOAD_ERROR, "Inner kernel image contains sections with relocations, which we do not support.");
                if (h->SizeOfRawData != 0) {
                        if ((h->VirtualAddress < image_base)
                            || (h->VirtualAddress - image_base + h->SizeOfRawData > kernel_size_in_memory))
                                return log_error_status(EFI_LOAD_ERROR, "Section would write outside of memory");
                        memcpy(loaded_kernel + h->VirtualAddress - image_base,
                               (const uint8_t*)kernel->iov_base + h->PointerToRawData,
                               h->SizeOfRawData);
                        if (h->VirtualSize > h->SizeOfRawData) {
                                memzero(loaded_kernel + h->VirtualAddress + h->SizeOfRawData,
                                        h->VirtualSize - h->SizeOfRawData);
                        }
                }
        }

        _cleanup_free_ EFI_LOADED_IMAGE_PROTOCOL* loaded_image = xnew(EFI_LOADED_IMAGE_PROTOCOL, 1);
        if (!loaded_image)
                return log_error_status(EFI_LOAD_ERROR, "Cannot allocate loaded image protocol");

        EFI_LOADED_IMAGE_PROTOCOL* parent_loaded_image;

        err = BS->HandleProtocol(
                        parent, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &parent_loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot get parent loaded image: %m");

        *loaded_image = (EFI_LOADED_IMAGE_PROTOCOL) {
                .Revision = 0x1000,
                .ParentHandle = parent,
                .SystemTable = ST,
                .DeviceHandle = parent_loaded_image->DeviceHandle,
                .FilePath = parent_loaded_image->FilePath,
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

        if (address < UINT32_MAX) {
                EFI_IMAGE_ENTRY_POINT entry =
                        (EFI_IMAGE_ENTRY_POINT) ((uint8_t *) loaded_image->ImageBase + address);
                err = entry(kernel_image, ST);
        } else if (compat_address > 0) {
                /* Try calling the kernel compat entry point if one exists. */
                EFI_IMAGE_ENTRY_POINT compat_entry =
                                (EFI_IMAGE_ENTRY_POINT) ((uint8_t *) loaded_image->ImageBase + compat_address);
                err = compat_entry(kernel_image, ST);
        }

        EFI_STATUS uninstall_err = BS->UninstallMultipleProtocolInterfaces(
                        kernel_image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), loaded_image,
                        NULL);
        if (uninstall_err != EFI_SUCCESS)
                return log_error_status(uninstall_err, "Cannot uninstall loaded image protocol: %m");

        return log_error_status(err, "Error starting kernel image: %m");
}
