/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "linux.h"
#include "initrd.h"
#include "util.h"

#ifdef __i386__
#define __regparm0__ __attribute__((regparm(0)))
#else
#define __regparm0__
#endif

typedef VOID(*handover_f)(VOID *image, EFI_SYSTEM_TABLE *table, struct boot_params *params) __regparm0__;

static VOID linux_efi_handover(EFI_HANDLE image, struct boot_params *params) {
        handover_f handover;
        UINTN start = (UINTN)params->hdr.code32_start;

        assert(params);

#ifdef __x86_64__
        asm volatile ("cli");
        start += 512;
#endif
        handover = (handover_f)(start + params->hdr.handover_offset);
        handover(image, ST, params);
}

EFI_STATUS linux_exec(
                EFI_HANDLE image,
                const CHAR8 *cmdline, UINTN cmdline_len,
                const VOID *linux_buffer,
                const VOID *initrd_buffer, UINTN initrd_length) {

        const struct boot_params *image_params;
        struct boot_params *boot_params;
        EFI_HANDLE initrd_handle = NULL;
        EFI_PHYSICAL_ADDRESS addr;
        UINT8 setup_sectors;
        EFI_STATUS err;

        assert(image);
        assert(cmdline || cmdline_len == 0);
        assert(linux_buffer);
        assert(initrd_buffer || initrd_length == 0);

        image_params = (const struct boot_params *) linux_buffer;

        if (image_params->hdr.boot_flag != 0xAA55 ||
            image_params->hdr.header != SETUP_MAGIC ||
            image_params->hdr.version < 0x20b ||
            !image_params->hdr.relocatable_kernel)
                return EFI_LOAD_ERROR;

        addr = UINT32_MAX; /* Below the 32bit boundary */
        err = uefi_call_wrapper(
                        BS->AllocatePages, 4,
                        AllocateMaxAddress,
                        EfiLoaderData,
                        EFI_SIZE_TO_PAGES(0x4000),
                        &addr);
        if (EFI_ERROR(err))
                return err;

        boot_params = (struct boot_params *) PHYSICAL_ADDRESS_TO_POINTER(addr);
        ZeroMem(boot_params, 0x4000);
        boot_params->hdr = image_params->hdr;
        boot_params->hdr.type_of_loader = 0xff;
        setup_sectors = image_params->hdr.setup_sects > 0 ? image_params->hdr.setup_sects : 4;
        boot_params->hdr.code32_start = (UINT32) POINTER_TO_PHYSICAL_ADDRESS(linux_buffer) + (setup_sectors + 1) * 512;

        if (cmdline) {
                addr = 0xA0000;

                err = uefi_call_wrapper(
                                BS->AllocatePages, 4,
                                AllocateMaxAddress,
                                EfiLoaderData,
                                EFI_SIZE_TO_PAGES(cmdline_len + 1),
                                &addr);
                if (EFI_ERROR(err))
                        return err;

                CopyMem(PHYSICAL_ADDRESS_TO_POINTER(addr), cmdline, cmdline_len);
                ((CHAR8 *) PHYSICAL_ADDRESS_TO_POINTER(addr))[cmdline_len] = 0;
                boot_params->hdr.cmd_line_ptr = (UINT32) addr;
        }

        /* Providing the initrd via LINUX_INITRD_MEDIA_GUID is only supported by Linux 5.8+ (5.7+ on ARM64).
           Until supported kernels become more established, we continue to set ramdisk in the handover struct.
           This value is overridden by kernels that support LINUX_INITRD_MEDIA_GUID.
           If you need to know which protocol was used by the kernel, pass "efi=debug" to the kernel,
           this will print a line when InitrdMediaGuid was successfully used to load the initrd.
         */
        boot_params->hdr.ramdisk_image = (UINT32) POINTER_TO_PHYSICAL_ADDRESS(initrd_buffer);
        boot_params->hdr.ramdisk_size = (UINT32) initrd_length;

        /* register LINUX_INITRD_MEDIA_GUID */
        err = initrd_register(initrd_buffer, initrd_length, &initrd_handle);
        if (EFI_ERROR(err))
                return err;
        linux_efi_handover(image, boot_params);
        (void) initrd_unregister(initrd_handle);
        initrd_handle = NULL;
        return EFI_LOAD_ERROR;
}
