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
#include "util.h"

static EFI_LOADED_IMAGE_PROTOCOL *loaded_image_free(EFI_LOADED_IMAGE_PROTOCOL *img) {
        if (!img)
                return NULL;
        mfree(img->LoadOptions);
        return mfree(img);
}

static EFI_STATUS loaded_image_register(
                const char *cmdline, UINTN cmdline_len,
                const void *linux_buffer, UINTN linux_length,
                EFI_HANDLE *ret_image) {

        EFI_LOADED_IMAGE_PROTOCOL *loaded_image = NULL;
        EFI_STATUS err;

        assert(cmdline || cmdline_len > 0);
        assert(linux_buffer && linux_length > 0);
        assert(ret_image);

        /* create and install new LoadedImage Protocol */
        loaded_image = xnew(EFI_LOADED_IMAGE_PROTOCOL, 1);
        *loaded_image = (EFI_LOADED_IMAGE_PROTOCOL) {
                .ImageBase = (void *) linux_buffer,
                .ImageSize = linux_length
        };

        /* if a cmdline is set convert it to UCS2 */
        if (cmdline) {
                loaded_image->LoadOptions = xstra_to_str(cmdline);
                loaded_image->LoadOptionsSize = strsize16(loaded_image->LoadOptions);
        }

        /* install a new LoadedImage protocol. ret_handle is a new image handle */
        err = BS->InstallMultipleProtocolInterfaces(
                        ret_image,
                        &LoadedImageProtocol, loaded_image,
                        NULL);
        if (err != EFI_SUCCESS)
                loaded_image = loaded_image_free(loaded_image);

        return err;
}

static EFI_STATUS loaded_image_unregister(EFI_HANDLE loaded_image_handle) {
        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        EFI_STATUS err;

        if (!loaded_image_handle)
                return EFI_SUCCESS;

        /* get the LoadedImage protocol that we allocated earlier */
        err = BS->OpenProtocol(
                        loaded_image_handle, &LoadedImageProtocol, (void **) &loaded_image,
                        NULL, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (err != EFI_SUCCESS)
                return err;

        /* close the handle */
        (void) BS->CloseProtocol(loaded_image_handle, &LoadedImageProtocol, NULL, NULL);
        err = BS->UninstallMultipleProtocolInterfaces(
                        loaded_image_handle,
                        &LoadedImageProtocol, loaded_image,
                        NULL);
        if (err != EFI_SUCCESS)
                return err;
        loaded_image_handle = NULL;
        loaded_image = loaded_image_free(loaded_image);

        return EFI_SUCCESS;
}

static inline void cleanup_loaded_image(EFI_HANDLE *loaded_image_handle) {
        (void) loaded_image_unregister(*loaded_image_handle);
        *loaded_image_handle = NULL;
}

EFI_STATUS linux_exec(
                EFI_HANDLE image,
                const char *cmdline, UINTN cmdline_len,
                const void *linux_buffer, UINTN linux_length,
                const void *initrd_buffer, UINTN initrd_length) {

        _cleanup_(cleanup_initrd) EFI_HANDLE initrd_handle = NULL;
        _cleanup_(cleanup_loaded_image) EFI_HANDLE loaded_image_handle = NULL;
        uint32_t kernel_alignment, kernel_size_of_image, kernel_entry_address;
        EFI_IMAGE_ENTRY_POINT kernel_entry;
        void *new_buffer;
        EFI_STATUS err;

        assert(image);
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
                                image,
                                cmdline,
                                cmdline_len,
                                linux_buffer,
                                linux_length,
                                initrd_buffer,
                                initrd_length);
#endif
        if (err != EFI_SUCCESS)
                return err;
        /* sanity check */
        assert(kernel_size_of_image >= linux_length);

        /* Linux kernel complains if it's not loaded at a properly aligned memory address. The correct alignment
           is provided by Linux as the SegmentAlignment in the PeOptionalHeader. Additionally the kernel needs to
           be in a memory segment that's SizeOfImage (again from PeOptionalHeader) large, so that the Kernel has
           space for its BSS section. SizeOfImage is always larger than linux_length, which is only the size of
           Code, (static) Data and Headers.

           Interrestingly only ARM/Aarch64 and RISC-V kernel stubs check these assertions and can even boot (with warnings)
           if they are not met. x86 and x86_64 kernel stubs don't do checks and fail if the BSS section is too small.
        */
        /* allocate SizeOfImage + SectionAlignment because the new_buffer can move up to Alignment-1 bytes */
        _cleanup_pages_ Pages kernel = xmalloc_pages(
                        AllocateAnyPages,
                        EfiLoaderCode,
                        EFI_SIZE_TO_PAGES(ALIGN_TO(kernel_size_of_image, kernel_alignment) + kernel_alignment),
                        0);
        new_buffer = PHYSICAL_ADDRESS_TO_POINTER(ALIGN_TO(kernel.addr, kernel_alignment));
        if (!new_buffer) /* Silence gcc 11.2.0, assert(new_buffer) doesn't work. */
                return EFI_OUT_OF_RESOURCES;

        memcpy(new_buffer, linux_buffer, linux_length);
        /* zero out rest of memory (probably not needed, but BSS section should be 0) */
        memset((uint8_t *)new_buffer + linux_length, 0, kernel_size_of_image - linux_length);

        /* get the entry point inside the relocated kernel */
        kernel_entry = (EFI_IMAGE_ENTRY_POINT) ((const uint8_t *)new_buffer + kernel_entry_address);

        /* register a LoadedImage Protocol in order to pass on the commandline */
        err = loaded_image_register(cmdline, cmdline_len, new_buffer, linux_length, &loaded_image_handle);
        if (err != EFI_SUCCESS)
                return err;

        /* register a LINUX_INITRD_MEDIA DevicePath to serve the initrd */
        err = initrd_register(initrd_buffer, initrd_length, &initrd_handle);
        if (err != EFI_SUCCESS)
                return err;

        /* call the kernel */
        return kernel_entry(loaded_image_handle, ST);
}
