/* SPDX-License-Identifier: LGPL-2.1+ */
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

#include "util.h"
#include "shim.h"

#if defined(__x86_64__) || defined(__i386__)
#define __sysv_abi__ __attribute__((sysv_abi))
#else
#define __sysv_abi__
#endif

struct ShimLock {
        EFI_STATUS __sysv_abi__ (*shim_verify) (VOID *buffer, UINT32 size);

        /* context is actually a struct for the PE header, but it isn't needed so void is sufficient just do define the interface
         * see shim.c/shim.h and PeHeader.h in the github shim repo */
        EFI_STATUS __sysv_abi__ (*generate_hash) (VOID *data, UINT32 datasize, VOID *context, UINT8 *sha256hash, UINT8 *sha1hash);

        EFI_STATUS __sysv_abi__ (*read_header) (VOID *data, UINT32 datasize, VOID *context);
};

static const EFI_GUID simple_fs_guid = SIMPLE_FILE_SYSTEM_PROTOCOL;
static const EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;

static const EFI_GUID security_protocol_guid = { 0xa46423e3, 0x4617, 0x49f1, {0xb9, 0xff, 0xd1, 0xbf, 0xa9, 0x11, 0x58, 0x39 } };
static const EFI_GUID security2_protocol_guid = { 0x94ab2f58, 0x1438, 0x4ef1, {0x91, 0x52, 0x18, 0x94, 0x1a, 0x3a, 0x0e, 0x68 } };
static const EFI_GUID shim_lock_guid = { 0x605dab50, 0xe046, 0x4300, {0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23} };

BOOLEAN shim_loaded(void) {
        struct ShimLock *shim_lock;

        return uefi_call_wrapper(BS->LocateProtocol, 3, (EFI_GUID*) &shim_lock_guid, NULL, (VOID**) &shim_lock) == EFI_SUCCESS;
}

static BOOLEAN shim_validate(VOID *data, UINT32 size) {
        struct ShimLock *shim_lock;

        if (!data)
                return FALSE;

        if (uefi_call_wrapper(BS->LocateProtocol, 3, (EFI_GUID*) &shim_lock_guid, NULL, (VOID**) &shim_lock) != EFI_SUCCESS)
                return FALSE;

        if (!shim_lock)
                return FALSE;

        return shim_lock->shim_verify(data, size) == EFI_SUCCESS;
}

BOOLEAN secure_boot_enabled(void) {
        _cleanup_freepool_ CHAR8 *b = NULL;
        UINTN size;

        if (efivar_get_raw(&global_guid, L"SecureBoot", &b, &size) == EFI_SUCCESS)
                return *b > 0;

        return FALSE;
}

/*
 * See the UEFI Platform Initialization manual (Vol2: DXE) for this
 */
struct _EFI_SECURITY2_PROTOCOL;
struct _EFI_SECURITY_PROTOCOL;
struct _EFI_DEVICE_PATH_PROTOCOL;

typedef struct _EFI_SECURITY2_PROTOCOL EFI_SECURITY2_PROTOCOL;
typedef struct _EFI_SECURITY_PROTOCOL EFI_SECURITY_PROTOCOL;
typedef struct _EFI_DEVICE_PATH_PROTOCOL EFI_DEVICE_PATH_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_SECURITY_FILE_AUTHENTICATION_STATE) (
        const EFI_SECURITY_PROTOCOL *This,
        UINT32 AuthenticationStatus,
        const EFI_DEVICE_PATH_PROTOCOL *File
);

typedef EFI_STATUS (EFIAPI *EFI_SECURITY2_FILE_AUTHENTICATION) (
        const EFI_SECURITY2_PROTOCOL *This,
        const EFI_DEVICE_PATH_PROTOCOL *DevicePath,
        VOID *FileBuffer,
        UINTN FileSize,
        BOOLEAN  BootPolicy
);

struct _EFI_SECURITY2_PROTOCOL {
        EFI_SECURITY2_FILE_AUTHENTICATION FileAuthentication;
};

struct _EFI_SECURITY_PROTOCOL {
        EFI_SECURITY_FILE_AUTHENTICATION_STATE  FileAuthenticationState;
};

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
                                                          VOID *file_buffer, UINTN file_size, BOOLEAN boot_policy) {
        EFI_STATUS status;

        /* Chain original security policy */
        status = uefi_call_wrapper(es2fa, 5, this, device_path, file_buffer, file_size, boot_policy);

        /* if OK, don't bother with MOK check */
        if (status == EFI_SUCCESS)
                return status;

        if (shim_validate(file_buffer, file_size))
                return EFI_SUCCESS;

        return status;
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
static EFIAPI EFI_STATUS security_policy_authentication (const EFI_SECURITY_PROTOCOL *this, UINT32 authentication_status,
                                                         const EFI_DEVICE_PATH_PROTOCOL *device_path_const) {
        EFI_STATUS status;
        _cleanup_freepool_ EFI_DEVICE_PATH *dev_path = NULL;
        _cleanup_freepool_ CHAR16 *dev_path_str = NULL;
        EFI_HANDLE h;
        EFI_FILE *root;
        _cleanup_freepool_ CHAR8 *file_buffer = NULL;
        UINTN file_size;

        if (!device_path_const)
                return EFI_INVALID_PARAMETER;

        dev_path = DuplicateDevicePath((EFI_DEVICE_PATH*) device_path_const);

        status = uefi_call_wrapper(BS->LocateDevicePath, 3, (EFI_GUID*) &simple_fs_guid, &dev_path, &h);
        if (status != EFI_SUCCESS)
                return status;

        /* No need to check return value, this already happened in efi_main() */
        root = LibOpenRoot(h);
        dev_path_str = DevicePathToStr(dev_path);

        status = file_read(root, dev_path_str, 0, 0, &file_buffer, &file_size);
        if (EFI_ERROR(status))
                return status;
        uefi_call_wrapper(root->Close, 1, root);

        if (shim_validate(file_buffer, file_size))
                return EFI_SUCCESS;

        /* Try using the platform's native policy.... */
        return uefi_call_wrapper(esfas, 3, this, authentication_status, device_path_const);
}

EFI_STATUS security_policy_install(void) {
        EFI_SECURITY_PROTOCOL *security_protocol;
        EFI_SECURITY2_PROTOCOL *security2_protocol = NULL;
        EFI_STATUS status;

        /* Already Installed */
        if (esfas)
                return EFI_ALREADY_STARTED;

        /*
         * Don't bother with status here. The call is allowed
         * to fail, since SECURITY2 was introduced in PI 1.2.1.
         * Use security2_protocol == NULL as indicator.
         */
        uefi_call_wrapper(BS->LocateProtocol, 3, (EFI_GUID*) &security2_protocol_guid, NULL, (VOID**) &security2_protocol);

        status = uefi_call_wrapper(BS->LocateProtocol, 3, (EFI_GUID*) &security_protocol_guid, NULL, (VOID**) &security_protocol);
         /* This one is mandatory, so there's a serious problem */
        if (status != EFI_SUCCESS)
                return status;

        esfas = security_protocol->FileAuthenticationState;
        security_protocol->FileAuthenticationState = security_policy_authentication;

        if (security2_protocol) {
                es2fa = security2_protocol->FileAuthentication;
                security2_protocol->FileAuthentication = security2_policy_authentication;
        }

        return EFI_SUCCESS;
}
