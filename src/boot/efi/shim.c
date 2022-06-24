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

BOOLEAN shim_loaded(void) {
        struct ShimLock *shim_lock;

        return BS->LocateProtocol((EFI_GUID*) SHIM_LOCK_GUID, NULL, (void**) &shim_lock) == EFI_SUCCESS;
}

static BOOLEAN shim_validate(void *data, uint32_t size) {
        struct ShimLock *shim_lock;

        if (!data)
                return FALSE;

        if (BS->LocateProtocol((EFI_GUID*) SHIM_LOCK_GUID, NULL, (void**) &shim_lock) != EFI_SUCCESS)
                return FALSE;

        if (!shim_lock)
                return FALSE;

        return shim_lock->shim_verify(data, size) == EFI_SUCCESS;
}

/* Handle to the original authenticator for security1 protocol */
static EFI_SECURITY_FILE_AUTHENTICATION_STATE esfas = NULL;

/* Handle to the original authenticator for security2 protocol */
static EFI_SECURITY2_FILE_AUTHENTICATION es2fa = NULL;

/*
 * Perform shim/MOK and Secure Boot authentication on a binary that's already been
 * loaded into memory. This function does the platform SB authentication first
 * but preserves its return value in case of its failure, so that it can be
 * returned in case of a shim/MOK authentication failure. This is done because
 * the SB failure code seems to vary from one implementation to another, and I
 * don't want to interfere with that at this time.
 */
static EFIAPI EFI_STATUS security2_policy_authentication (const EFI_SECURITY2_PROTOCOL *this,
                                                          const EFI_DEVICE_PATH_PROTOCOL *device_path,
                                                          void *file_buffer, UINTN file_size, BOOLEAN boot_policy) {
        EFI_STATUS err;

        assert(this);
        /* device_path and file_buffer may be NULL */

        /* Chain original security policy */
        err = es2fa(this, device_path, file_buffer, file_size, boot_policy);

        /* if OK, don't bother with MOK check */
        if (err == EFI_SUCCESS)
                return err;

        if (shim_validate(file_buffer, file_size))
                return EFI_SUCCESS;

        return err;
}

/*
 * Perform both shim/MOK and platform Secure Boot authentication. This function loads
 * the file and performs shim/MOK authentication first simply to avoid double loads
 * of Linux kernels, which are much more likely to be shim/MOK-signed than platform-signed,
 * since kernels are big and can take several seconds to load on some computers and
 * filesystems. This also has the effect of returning whatever the platform code is for
 * authentication failure, be it EFI_ACCESS_DENIED, EFI_SECURITY_VIOLATION, or something
 * else. (This seems to vary between implementations.)
 */
static EFIAPI EFI_STATUS security_policy_authentication (const EFI_SECURITY_PROTOCOL *this, uint32_t authentication_status,
                                                         const EFI_DEVICE_PATH_PROTOCOL *device_path_const) {
        EFI_STATUS err;
        _cleanup_free_ char16_t *dev_path_str = NULL;
        EFI_HANDLE h;
        _cleanup_freepool_ CHAR8 *file_buffer = NULL;
        UINTN file_size;

        assert(this);

        if (!device_path_const)
                return EFI_INVALID_PARAMETER;

        EFI_DEVICE_PATH *dp = (EFI_DEVICE_PATH *) device_path_const;
        err = BS->LocateDevicePath(&FileSystemProtocol, &dp, &h);
        if (err != EFI_SUCCESS)
                return err;

        _cleanup_(file_closep) EFI_FILE *root = NULL;
        err = open_volume(h, &root);
        if (err != EFI_SUCCESS)
                return err;

        dev_path_str = DevicePathToStr(dp);
        if (!dev_path_str)
                return EFI_OUT_OF_RESOURCES;

        err = file_read(root, dev_path_str, 0, 0, &file_buffer, &file_size);
        if (err != EFI_SUCCESS)
                return err;

        if (shim_validate(file_buffer, file_size))
                return EFI_SUCCESS;

        /* Try using the platform's native policy.... */
        return esfas(this, authentication_status, device_path_const);
}

EFI_STATUS security_policy_install(void) {
        EFI_SECURITY_PROTOCOL *security_protocol;
        EFI_SECURITY2_PROTOCOL *security2_protocol = NULL;
        EFI_STATUS err;

        /* Already Installed */
        if (esfas)
                return EFI_ALREADY_STARTED;

        /*
         * Don't bother with status here. The call is allowed
         * to fail, since SECURITY2 was introduced in PI 1.2.1.
         * Use security2_protocol == NULL as indicator.
         */
        BS->LocateProtocol((EFI_GUID*) SECURITY_PROTOCOL2_GUID, NULL, (void**) &security2_protocol);

        err = BS->LocateProtocol((EFI_GUID*) SECURITY_PROTOCOL_GUID, NULL, (void**) &security_protocol);
         /* This one is mandatory, so there's a serious problem */
        if (err != EFI_SUCCESS)
                return err;

        esfas = security_protocol->FileAuthenticationState;
        security_protocol->FileAuthenticationState = security_policy_authentication;

        if (security2_protocol) {
                es2fa = security2_protocol->FileAuthentication;
                security2_protocol->FileAuthentication = security2_policy_authentication;
        }

        return EFI_SUCCESS;
}
