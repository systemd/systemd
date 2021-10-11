/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "initrd.h"
#include "linux.h"
#include "pe.h"
#include "util.h"

static EFI_STATUS loaded_image_register(
                const CHAR8 *cmdline, UINTN cmdline_len,
                const VOID *linux_buffer, UINTN linux_length,
                EFI_HANDLE *ret_image) {

        EFI_LOADED_IMAGE *loaded_image = NULL;
        EFI_STATUS err;

        assert(ret_image);

        /* create and install new LoadedImage Protocol */
        loaded_image = AllocatePool(sizeof(EFI_LOADED_IMAGE));
        if (!loaded_image)
                return EFI_OUT_OF_RESOURCES;

        /* provide the image base address and size */
        *loaded_image = (EFI_LOADED_IMAGE) {
                .ImageBase = (VOID *) linux_buffer,
                .ImageSize = linux_length
        };

        /* if a cmdline is set convert it to UTF16 */
        if (cmdline) {
                loaded_image->LoadOptions = stra_to_str(cmdline);
                if (!loaded_image->LoadOptions) {
                        loaded_image = mfree(loaded_image);
                        return EFI_OUT_OF_RESOURCES;
                }
                loaded_image->LoadOptionsSize = StrSize(loaded_image->LoadOptions);
        }

        /* install a new LoadedImage protocol. ret_handle is a new image handle */
        err = uefi_call_wrapper(BS->InstallMultipleProtocolInterfaces, 4,
                        ret_image,
                        &LoadedImageProtocol, loaded_image,
                        NULL);
        if (EFI_ERROR(err)) {
                loaded_image->LoadOptions = mfree(loaded_image->LoadOptions);
                loaded_image = mfree(loaded_image);
        }

        return err;
}

static EFI_STATUS loaded_image_unregister(EFI_HANDLE loaded_image_handle) {
        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        EFI_STATUS err;

        if (!loaded_image_handle)
                return EFI_SUCCESS;

        /* get the LoadedImage protocol that we allocated earlier */
        err = uefi_call_wrapper(
                        BS->OpenProtocol, 6,
                        loaded_image_handle, &LoadedImageProtocol, (VOID **) &loaded_image,
                        NULL, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(err))
                return err;

        /* close the handle */
        (void) uefi_call_wrapper(
                        BS->CloseProtocol, 4,
                        loaded_image_handle, &LoadedImageProtocol, NULL, NULL);
        err = uefi_call_wrapper(BS->UninstallMultipleProtocolInterfaces, 4,
                        loaded_image_handle,
                        &LoadedImageProtocol, loaded_image,
                        NULL);
        if (EFI_ERROR(err))
                return err;
        loaded_image_handle = NULL;

        loaded_image->LoadOptions = mfree(loaded_image->LoadOptions);
        loaded_image = mfree(loaded_image);

        return EFI_SUCCESS;
}

static inline void cleanup_initrd(EFI_HANDLE *initrd_handle) {
        (void) initrd_unregister(*initrd_handle);
        *initrd_handle = NULL;
}

static inline void cleanup_loaded_image(EFI_HANDLE *loaded_image_handle) {
        (void) loaded_image_unregister(*loaded_image_handle);
        *loaded_image_handle = NULL;
}

/* struct to call cleanup_pages */
struct pages {
        UINT64 addr;
        UINT64 num;
};

static inline void cleanup_pages(struct pages *p) {
        if (p->addr == 0)
                return;
        (void) uefi_call_wrapper(BS->FreePages, 2, p->addr, p->num);
        SetMem(p, sizeof(struct pages), 0);
}

EFI_STATUS linux_exec(
                EFI_HANDLE image,
                const CHAR8 *cmdline, UINTN cmdline_len,
                const VOID *linux_buffer, UINTN linux_length,
                const VOID *initrd_buffer, UINTN initrd_length) {

        _cleanup_(cleanup_initrd) EFI_HANDLE initrd_handle = NULL;
        _cleanup_(cleanup_loaded_image) EFI_HANDLE loaded_image_handle = NULL;
        EFI_IMAGE_ENTRY_POINT kernel_entry;
        UINT64 image_size;
        EFI_STATUS err;
        _cleanup_(cleanup_pages) struct pages kernel = { 0 };

        assert(image);
        assert(cmdline || cmdline_len == 0);
        assert(linux_buffer);
        assert(initrd_buffer || initrd_length == 0);

        image_size = pe_image_size(linux_buffer);
        if (image_size == 0)
                return EFI_LOAD_ERROR;

        /* Allocate kernel at 64k boundary, and leave space of the BSS section */
        {
                VOID *new_buffer;
                kernel.num = EFI_SIZE_TO_PAGES((image_size / 0x1000 + 1) * 0x1000);

                err = uefi_call_wrapper(
                        BS->AllocatePages, 4,
                        AllocateAnyPages, EfiLoaderData,
                        kernel.num, &kernel.addr);
                if (EFI_ERROR(err))
                        return EFI_OUT_OF_RESOURCES;
                new_buffer = PHYSICAL_ADDRESS_TO_POINTER(ALIGN_TO(kernel.addr, 0x1000));
                CopyMem(new_buffer, linux_buffer, linux_length);
                linux_buffer = new_buffer;
        }

        /* get the PE entry point for the kernel */
        kernel_entry = pe_entry_point(linux_buffer);
        if (!kernel_entry)
                return EFI_LOAD_ERROR;

        /* register a LoadedImage Protocol in order to pass on the commandline */
        err = loaded_image_register(cmdline, cmdline_len, linux_buffer, image_size, &loaded_image_handle);
        if (EFI_ERROR(err))
                return err;

        /* register a LINUX_INITRD_MEDIA DevicePath to serve the initrd */
        err = initrd_register(initrd_buffer, initrd_length, &initrd_handle);
        if (EFI_ERROR(err))
                return err;

        /* call the kernel */
        err = uefi_call_wrapper(kernel_entry, 2, loaded_image_handle, ST);

        return err;
}
