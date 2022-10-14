/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Port to systemd-boot
 * Copyright © 2017 Max Resch <resch.max@gmail.com>
 *
 * Security Policy Handling
 * Copyright © 2012 <James.Bottomley@HansenPartnership.com>
 * https://github.com/mjg59/efitools
 */

#include <efi.h>
#include <efilib.h>

#include "missing_efi.h"
#include "util.h"
#include "secure-boot.h"
#include "shim.h"

#if defined(__x86_64__) || defined(__i386__)
#define __sysv_abi__ __attribute__((sysv_abi))
#else
#define __sysv_abi__
#endif

struct ShimLock {
        EFI_STATUS __sysv_abi__ (*shim_verify) (void *buffer, uint32_t size);

        /* context is actually a struct for the PE header, but it isn't needed so void is sufficient just do define the interface
         * see shim.c/shim.h and PeHeader.h in the github shim repo */
        EFI_STATUS __sysv_abi__ (*generate_hash) (void *data, uint32_t datasize, void *context, uint8_t *sha256hash, uint8_t *sha1hash);

        EFI_STATUS __sysv_abi__ (*read_header) (void *data, uint32_t datasize, void *context);
};

#define SHIM_LOCK_GUID \
        &(const EFI_GUID) { 0x605dab50, 0xe046, 0x4300, { 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23 } }

bool shim_loaded(void) {
        struct ShimLock *shim_lock;

        return BS->LocateProtocol((EFI_GUID*) SHIM_LOCK_GUID, NULL, (void**) &shim_lock) == EFI_SUCCESS;
}

static bool shim_validate(void *data, uint32_t size) {
        struct ShimLock *shim_lock;

        if (!data)
                return false;

        if (BS->LocateProtocol((EFI_GUID*) SHIM_LOCK_GUID, NULL, (void**) &shim_lock) != EFI_SUCCESS)
                return false;

        if (!shim_lock)
                return false;

        return shim_lock->shim_verify(data, size) == EFI_SUCCESS;
}

static EFIAPI EFI_STATUS security2_hook(
                const SecurityOverride *this,
                const EFI_DEVICE_PATH *device_path,
                void *file_buffer,
                UINTN file_size,
                BOOLEAN boot_policy) {

        assert(this);
        assert(this->hook == security2_hook);

        if (shim_validate(file_buffer, file_size))
                return EFI_SUCCESS;

        return this->original_security2->FileAuthentication(
                        this->original_security2, device_path, file_buffer, file_size, boot_policy);
}

static EFIAPI EFI_STATUS security_hook(
                const SecurityOverride *this,
                uint32_t authentication_status,
                const EFI_DEVICE_PATH *device_path) {

        EFI_STATUS err;

        assert(this);
        assert(this->hook == security_hook);

        if (!device_path)
                return this->original_security->FileAuthenticationState(
                                this->original_security, authentication_status, device_path);

        EFI_HANDLE device_handle;
        EFI_DEVICE_PATH *dp = (EFI_DEVICE_PATH *) device_path;
        err = BS->LocateDevicePath(&FileSystemProtocol, &dp, &device_handle);
        if (err != EFI_SUCCESS)
                return err;

        _cleanup_(file_closep) EFI_FILE *root = NULL;
        err = open_volume(device_handle, &root);
        if (err != EFI_SUCCESS)
                return err;

        _cleanup_free_ char16_t *dp_str = NULL;
        err = device_path_to_str(dp, &dp_str);
        if (err != EFI_SUCCESS)
                return err;

        char *file_buffer;
        size_t file_size;
        err = file_read(root, dp_str, 0, 0, &file_buffer, &file_size);
        if (err != EFI_SUCCESS)
                return err;

        if (shim_validate(file_buffer, file_size))
                return EFI_SUCCESS;

        return this->original_security->FileAuthenticationState(
                        this->original_security, authentication_status, device_path);
}

EFI_STATUS shim_load_image(EFI_HANDLE parent, const EFI_DEVICE_PATH *device_path, EFI_HANDLE *ret_image) {
        assert(device_path);
        assert(ret_image);

        bool have_shim = shim_loaded();

        SecurityOverride security_override = {
                .hook = security_hook,
        }, security2_override = {
                .hook = security2_hook,
        };

        if (have_shim)
                install_security_override(&security_override, &security2_override);

        EFI_STATUS ret = BS->LoadImage(
                        /*BootPolicy=*/false, parent, (EFI_DEVICE_PATH *) device_path, NULL, 0, ret_image);

        if (have_shim)
                uninstall_security_override(&security_override, &security2_override);

        return ret;
}
