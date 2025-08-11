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
#include "proto/memory-attribute.h"
#include "secure-boot.h"
#include "shim.h"
#include "util.h"

#define STUB_PAYLOAD_GUID \
        { 0x55c5d1f8, 0x04cd, 0x46b5, { 0x8a, 0x20, 0xe5, 0x6c, 0xbb, 0x30, 0x52, 0xd0 } }

typedef struct {
        const void *addr;
        size_t len;
        const EFI_DEVICE_PATH *device_path;
} ValidationContext;

static bool validate_payload(
                const void *ctx, const EFI_DEVICE_PATH *device_path, const void *file_buffer, size_t file_size) {

        const ValidationContext *payload = ASSERT_PTR(ctx);

        if (device_path != payload->device_path)
                return false;

        /* Security arch (1) protocol does not provide a file buffer. Instead we are supposed to fetch the payload
         * ourselves, which is not needed as we already have everything in memory and the device paths match. */
        if (file_buffer && (file_buffer != payload->addr || file_size != payload->len))
                return false;

        return true;
}

static EFI_STATUS load_via_boot_services(
                EFI_HANDLE parent,
                EFI_LOADED_IMAGE_PROTOCOL* parent_loaded_image,
                uint32_t compat_entry_point,
                const char16_t *cmdline,
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

        /* When running with shim < v16 and booting a UKI directly from it, without a second stage loader,
         * the shim verify protocol needs to be called or it will raise a security violation when starting
         * the image (e.g.: Fedora Cloud Base UKI). TODO: drop once support for shim < v16 is not needed. */
        if (!shim_loader_available())
                install_security_override(
                                validate_payload,
                                &(ValidationContext) {
                                        .addr = kernel->iov_base,
                                        .len = kernel->iov_len,
                                        .device_path = file_path,
                                });


        err = BS->LoadImage(/* BootPolicy= */false,
                            parent,
                            file_path,
                            kernel->iov_base,
                            kernel->iov_len,
                            &kernel_image);

        if (!shim_loader_available())
                uninstall_security_override();

        if (err != EFI_SUCCESS)
                return log_error_status(EFI_LOAD_ERROR, "Error loading inner kernel with shim: %m");

        err = BS->HandleProtocol(
                        kernel_image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(EFI_LOAD_ERROR, "Error getting kernel image from protocol from shim: %m");

        if (cmdline) {
                loaded_image->LoadOptions = (void *) cmdline;
                loaded_image->LoadOptionsSize = strsize16(loaded_image->LoadOptions);
        }

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

static EFI_STATUS kernel_set_nx(Pages *loaded_kernel_pages) {
        EFI_MEMORY_ATTRIBUTE_PROTOCOL *memory_proto;
        EFI_STATUS err;

        assert(loaded_kernel_pages);

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_MEMORY_ATTRIBUTE_PROTOCOL), NULL, (void **) &memory_proto);
        if (err != EFI_SUCCESS)
                return EFI_SUCCESS; /* ignore if firmware lacks support */

        err = memory_proto->ClearMemoryAttributes(
                memory_proto,
                loaded_kernel_pages->addr,
                loaded_kernel_pages->n_pages * EFI_PAGE_SIZE,
                EFI_MEMORY_XP);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot make kernel image executable: %m");

        /* This needs kernel support before it can be enabled */
        if (!pe_kernel_check_nx_compat(PHYSICAL_ADDRESS_TO_POINTER(loaded_kernel_pages->addr)))
                return EFI_SUCCESS;

        err = memory_proto->SetMemoryAttributes(
                memory_proto,
                loaded_kernel_pages->addr,
                loaded_kernel_pages->n_pages * EFI_PAGE_SIZE,
                EFI_MEMORY_RO);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot make kernel image read-only: %m");

        log_debug("Changed kernel image to read-only for NX_COMPAT support");

        return EFI_SUCCESS;
}

static EFI_STATUS kernel_clear_nx(Pages *loaded_kernel_pages) {
        EFI_MEMORY_ATTRIBUTE_PROTOCOL *memory_proto;
        EFI_STATUS err;

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_MEMORY_ATTRIBUTE_PROTOCOL), NULL, (void **) &memory_proto);
        if (err != EFI_SUCCESS)
                return EFI_SUCCESS; /* ignore if firmware lacks support */

        err = memory_proto->ClearMemoryAttributes(
                memory_proto,
                loaded_kernel_pages->addr,
                loaded_kernel_pages->n_pages * EFI_PAGE_SIZE,
                EFI_MEMORY_RO);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot make kernel image writable: %m");

        err = memory_proto->SetMemoryAttributes(
                memory_proto,
                loaded_kernel_pages->addr,
                loaded_kernel_pages->n_pages * EFI_PAGE_SIZE,
                EFI_MEMORY_XP);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot make kernel image non-executable: %m");

        return EFI_SUCCESS;
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

        EFI_LOADED_IMAGE_PROTOCOL *parent_loaded_image;
        err = BS->HandleProtocol(
                        parent, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &parent_loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot get parent loaded image: %m");

        /* If shim provides LoadImage, it comes from the new SHIM_IMAGE_LOADER interface added in shim 16,
         * and implements the following:
         * - shim hashes PE sections of PE binaries it authenticates and stores the hashes in a global
         *   database.
         * - shim's LoadImage always verifies PE images against denylists: DBX, MOKX, SBAT.
         * - If the PE image was _not_ authenticated as a PE section it will also:
         *   + verify it against allowlists: DB, MOK,
         *   + measure it on PCR 4.
         *
         * (Compared to standard UEFI LoadImage(), the patched shim version of LoadImage() is both stricter —
         * as it checks SBAT + MOKX for all PE payloads — and more relaxed — as it disables DB checks for PE
         * payloads it has seen as part of another PE binary before.)
         *
         * In our case, we are loading a PE section that was already authenticated as part of the UKI. In
         * contrast to a normal UEFI LoadImage, shim will verify extra denylists (MOKX, SBAT), but skip all
         * allowlists and measurements.
         *
         * See https://github.com/rhboot/shim/blob/main/README.md#shim-loader-protocol
         */
        if (secure_boot_enabled() && (shim_loader_available() || (shim_loaded() && security_override_available())))
                return load_via_boot_services(
                                parent,
                                parent_loaded_image,
                                compat_entry_point,
                                cmdline,
                                kernel,
                                initrd);

        err = pe_kernel_check_no_relocation(kernel->iov_base);
        if (err != EFI_SUCCESS)
                return err;

        const PeSectionHeader *headers;
        size_t n_headers;

        /* Do we need to validate anything here? the len? */
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
                .ImageCodeType = 1 /* EFI_LOADER_CODE */,
                .ImageDataType = 2 /* EFI_LOADER_DATA */,
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

        /* As per NX requirement, executable memory needs to be read-only, and viceversa
         * https://www.kraxel.org/blog/2023/12/uefi-nx-linux-boot/ */
        err = kernel_set_nx(&loaded_kernel_pages);
        if (err != EFI_SUCCESS)
                return err;

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

        /* On failure we'll free the buffers. EDK2 requires the memory buffers to be writable and
         * non-executable, as in some configurations it will overwrite them with a fixed pattern,
         * so if the attributes are not restored FreePages() will crash. */
        (void) kernel_clear_nx(&loaded_kernel_pages);

        EFI_STATUS uninstall_err = BS->UninstallMultipleProtocolInterfaces(
                        kernel_image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), loaded_image,
                        NULL);
        if (uninstall_err != EFI_SUCCESS)
                return log_error_status(uninstall_err, "Cannot uninstall loaded image protocol: %m");

        return log_error_status(err, "Error starting kernel image: %m");
}
