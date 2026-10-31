/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Ported from:
 * https://github.com/fwupd/fwupd-efi/blob/1a794fc7ce481176926687f4e88e6e0c8d5e9699/efi/fwupdate.c
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "device-path-util.h"
#include "efi-efivars.h"
#include "efi-log.h"
#include "efi-string.h"
#include "efi.h"
#include "fwupdate.h"
#include "proto/block-io.h"
#include "proto/graphics-output.h"
#include "string-util.h"
#include "util.h"

/* The following types implement the protocol for windows compatible graphical firmware updates. This
 * extended header is inserted right after the capsule header when the indicated GUID is used.
 * https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/boot-screen-components
 */
#define UX_CAPSULE_GUID {0x3b8c8162, 0x188c, 0x46a4, {0xae, 0xc9, 0xbe, 0x43, 0xf1, 0xd6, 0x56, 0x97} }

typedef struct {
        uint8_t version;
        uint8_t checksum;
        uint8_t image_type;
        uint8_t reserved;
        uint32_t mode;
        uint32_t x_offset;
        uint32_t y_offset;
} _packed_ UX_CAPSULE_HEADER;

/* The following types are defined by fwupd:
 * https://github.com/fwupd/fwupd-efi/blob/1a794fc7ce481176926687f4e88e6e0c8d5e9699/efi/fwup-efi.h
 * fwupd uses this struct for the EFI variables it creates in userspace.
 */
#define FWUPDATE_ATTEMPT_UPDATE 0x00000001
#define FWUPDATE_ATTEMPTED      0x00000002

typedef struct {
        uint32_t update_info_version;
        EFI_GUID guid;
        uint32_t capsule_flags;
        uint64_t hw_inst;
        EFI_TIME time_attempted;
        uint32_t status;
        union {
                EFI_DEVICE_PATH dp;
                uint8_t dp_buf[0];
        };
} _packed_ FWUP_UPDATE_INFO;

typedef struct {
        char16_t *name;
        uint32_t attrs;
        size_t size;
        FWUP_UPDATE_INFO *info;
        EFI_HANDLE device_handle;
        const EFI_DEVICE_PATH *file_dp; /* Borrowed from info. */
} FwupUpdateTable;

static FwupUpdateTable *fwup_update_table_free(FwupUpdateTable *update) {
        if (!update)
                return NULL;

        free(update->name);
        free(update->info);

        return mfree(update);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(FwupUpdateTable *, fwup_update_table_free);

static void fwup_update_table_free_many(FwupUpdateTable **a, size_t n) {
        assert(a || n == 0);

        FOREACH_ARRAY(i, a, n)
                fwup_update_table_free(*i);

        free(a);
}

static void capsule_free_many(EFI_CAPSULE_HEADER **a, size_t n) {
        assert(a || n == 0);

        FOREACH_ARRAY(i, a, n)
                free(*i);

        free(a);
}

static EFI_STATUS get_boot_disk_path(EFI_HANDLE boot_device, EFI_DEVICE_PATH **ret_disk_path) {
        EFI_DEVICE_PATH *path = NULL;
        EFI_STATUS err;

        assert(ret_disk_path);

        if (!boot_device)
                return EFI_NOT_FOUND;

        err = BS->HandleProtocol(boot_device, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &path);
        if (err != EFI_SUCCESS)
                return err;
        if (!path)
                return EFI_NOT_FOUND;

        /* Remove the last partition node, as partition discovery does, to identify the whole disk rather
         * than just the ESP. An empty prefix cannot identify a disk. */
        const EFI_DEVICE_PATH *partition = NULL;
        for (const EFI_DEVICE_PATH *node = path; !device_path_is_end(node); node = device_path_next_node(node))
                if (node->Type == MEDIA_DEVICE_PATH && IN_SET(node->SubType, MEDIA_HARDDRIVE_DP, MEDIA_CDROM_DP))
                        partition = node;
        if (!partition || partition == path)
                return EFI_NOT_FOUND;

        _cleanup_free_ EFI_DEVICE_PATH *disk_path = device_path_replace_node(path, partition, /* new_node= */ NULL);
        EFI_DEVICE_PATH *remaining = disk_path;
        EFI_HANDLE disk_handle = NULL;

        err = BS->LocateDevicePath(MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), &remaining, &disk_handle);
        if (err != EFI_SUCCESS)
                return err;
        if (!disk_handle || !remaining || !device_path_is_end(remaining))
                return EFI_NOT_FOUND;

        EFI_BLOCK_IO_PROTOCOL *block_io = NULL;
        err = BS->HandleProtocol(disk_handle, MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), (void **) &block_io);
        if (err != EFI_SUCCESS)
                return err;
        if (!block_io || !block_io->Media || block_io->Media->LogicalPartition || !block_io->Media->MediaPresent)
                return EFI_NOT_FOUND;

        /* Fastboot firmware may not have connected the other partitions on this disk yet. */
        (void) BS->ConnectController(disk_handle, /* DriverImageHandle= */ NULL, /* RemainingDevicePath= */ NULL, /* Recursive= */ true);

        *ret_disk_path = TAKE_PTR(disk_path);
        return EFI_SUCCESS;
}

static EFI_STATUS parse_info_var(const char16_t *name, FwupUpdateTable **ret_update) {
        _cleanup_free_ FWUP_UPDATE_INFO *info = NULL;
        size_t size = 0;
        uint32_t flags = 0;
        EFI_STATUS err;

        assert(name);
        assert(ret_update);

        err = efivar_get_raw_full(MAKE_GUID_PTR(FWUPDATE), name, &flags, (void **) &info, &size);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to get variable '%ls': %m", name);

        if (size < sizeof(FWUP_UPDATE_INFO))
                return log_error_status(EFI_INVALID_PARAMETER, "Variable '%ls' is too small: %zu < %zu", name, size, sizeof(FWUP_UPDATE_INFO));

        EFI_DEVICE_PATH *hdr = &info->dp;
        size_t dp_size = size - offsetof(FWUP_UPDATE_INFO, dp);

        if (!device_path_is_valid(hdr, dp_size) || device_path_size(hdr) != dp_size)
                return log_error_status(EFI_INVALID_PARAMETER, "Variable '%ls' has an invalid EFI device path", name);

        log_debug("Parsed UEFI update variable '%ls': flags=0x%08x, hw_inst=%" PRIu64 ", status=%" PRIu32,
                  name,
                  info->capsule_flags,
                  info->hw_inst,
                  info->status);

        *ret_update = xnew(FwupUpdateTable, 1);
        **ret_update = (FwupUpdateTable) {
                .name = xstrdup16(name),
                .attrs = flags,
                .size = size,
                .info = TAKE_PTR(info),
        };

        return EFI_SUCCESS;
}

/* Locates the capsule's filesystem on the boot disk as provided by fwupd.
 *
 * fwupd's fu_uefi_capsule_device_write_update_info() stores the path built by
 * fu_uefi_capsule_device_build_dp_buf(): an HD node describing the ESP partition, followed by a File node.
 * The ESP mount point is stripped from the filename, which is stored as NUL-terminated UTF-16 with
 * backslashes. fu_efi_device_path_list_write() appends End. No controller/disk hardware prefix is stored.
 *
 * An example, with the capsule's ESP mounted at /efi on partition 1 of the PCI disk
 * (HD(1,...) abbreviates the unchanged ESP partition node, and $F denotes the File node):
 *   filename       = /efi/EFI/fedora/fw/fwupd-697bd920-12cf-4da9-8385-996909bc6559.cap
 *   UEFI file path = File(\EFI\fedora\fw\fwupd-697bd920-12cf-4da9-8385-996909bc6559.cap)
 *   update_dp      = HD(1,...)/File(\EFI\fedora\fw\fwupd-697bd920-12cf-4da9-8385-996909bc6559.cap)/End
 *   boot_disk_path = PciRoot(0)/Pci(0x4,0)/End
 *   lookup_dp      = PciRoot(0)/Pci(0x4,0)/HD(1,...)/End
 *
 * Prepending the boot disk's hardware path scopes the partition lookup to that disk, to stop the firmware
 * from finding the partition on another disk. A full input path must already start with boot_disk_path.
 * Requires the filesystem lookup to consume lookup_dp completely, rather than accepting a partial match.
 *
 * Returns the filesystem handle and, via ret_file_dp, a borrowed pointer to the original file-path nodes
 * in update_dp (File(\EFI\fedora\fw\fwupd-697bd920-12cf-4da9-8385-996909bc6559.cap)/End in the example). */
static EFI_STATUS find_capsule(
                const EFI_DEVICE_PATH *update_dp,
                const EFI_DEVICE_PATH *boot_disk_path,
                EFI_HANDLE *ret_device_handle,
                const EFI_DEVICE_PATH **ret_file_dp) {

        _cleanup_free_ EFI_DEVICE_PATH *device_dp = NULL, *lookup_dp = NULL;
        const EFI_DEVICE_PATH *file_dp;
        EFI_HANDLE device_handle = NULL;
        EFI_STATUS err;

        assert(update_dp);
        assert(boot_disk_path);
        assert(!device_path_is_end(boot_disk_path));
        assert(ret_device_handle);
        assert(ret_file_dp);

        err = device_path_split_file_path(update_dp, &device_dp, &file_dp);
        if (err != EFI_SUCCESS)
                return err;

        if (device_dp->Type == MEDIA_DEVICE_PATH && device_dp->SubType == MEDIA_HARDDRIVE_DP) {
                if (device_dp->Length != sizeof(HARDDRIVE_DEVICE_PATH) ||
                    !device_path_is_end(device_path_next_node(device_dp)))
                        return EFI_NOT_FOUND;

                lookup_dp = device_path_replace_node(boot_disk_path, /* node= */ NULL, device_dp);
        } else {
                if (!device_path_startswith(device_dp, boot_disk_path))
                        return EFI_NOT_FOUND;

                lookup_dp = TAKE_PTR(device_dp);
        }

        EFI_DEVICE_PATH *remaining = lookup_dp;
        err = BS->LocateDevicePath(MAKE_GUID_PTR(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL), &remaining, &device_handle);
        if (err != EFI_SUCCESS)
                return err;
        if (!device_handle || !remaining || !device_path_is_end(remaining))
                return EFI_NOT_FOUND;

        *ret_device_handle = device_handle;
        *ret_file_dp = file_dp;
        return EFI_SUCCESS;
}

static EFI_STATUS parse_update_vars(
                const EFI_DEVICE_PATH *boot_disk_path,
                FwupUpdateTable ***updates,
                size_t *n_updates) {

        size_t name_length = 1024 * sizeof(char16_t);
        _cleanup_free_ char16_t *name = NULL;
        EFI_STATUS err;

        assert(boot_disk_path);
        assert(updates);
        assert(n_updates);

        /* A series of fwupd-* named variables will be prepared by userspace, but there is no fixed name,
         * so we need to iterate over the full table of variables and find them. Unfortunately there are no
         * APIs to search by GUID, so it's really the entire table that has to be walked.
         * As per the protocol, start with a NUL string, and then pass the previous name as input to the
         * next search, as the protocol implementation is stateless. */

        name = xnew0(char16_t, name_length);

        for (;;) {
                EFI_GUID guid;

                err = RT->GetNextVariableName(&name_length, name, &guid);
                if (err == EFI_NOT_FOUND)
                        break;
                if (err == EFI_BUFFER_TOO_SMALL) {
                        if (name_length > SIZE_MAX / 2)
                                return log_error_status(EFI_OUT_OF_RESOURCES, "Variable name too long: %zu", name_length);
                        name_length *= 2;
                        name = xrealloc(name, name_length / 2, name_length);
                        continue;
                }
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to get next variable name: %m");

                if (!efi_guid_equal(&guid, MAKE_GUID_PTR(FWUPDATE)))
                        continue;
                if (!startswith_no_case(name, u"fwupd-"))
                        continue;

                log_debug("Found UEFI update variable '%ls'", name);

                _cleanup_(fwup_update_table_freep) FwupUpdateTable *update = NULL;
                err = parse_info_var(name, &update);
                if (err != EFI_SUCCESS)
                        /* We cannot establish which disk owns a malformed entry, so leave it untouched. */
                        continue;
                if (!FLAGS_SET(update->info->status, FWUPDATE_ATTEMPT_UPDATE)) {
                        log_debug("Skipping UEFI update variable '%ls', lacks FWUPDATE_ATTEMPT_UPDATE flag", name);
                        continue;
                }

                err = find_capsule(&update->info->dp, boot_disk_path, &update->device_handle, &update->file_dp);
                if (err != EFI_SUCCESS) {
                        log_debug_status(err, "Ignoring update '%ls', cannot resolve it on the boot disk: %m", name);
                        continue;
                }

                if (*n_updates == SIZE_MAX)
                        return log_error_status(EFI_OUT_OF_RESOURCES, "Too many UEFI update variables found");

                *updates = xrealloc(*updates,
                                    *n_updates * sizeof(FwupUpdateTable *),
                                    (*n_updates + 1) * sizeof(FwupUpdateTable *));
                (*updates)[(*n_updates)++] = TAKE_PTR(update);
        }

        return EFI_SUCCESS;
}

static EFI_STATUS get_graphics_protocol_mode(EFI_HANDLE image, uint32_t *ret_mode) {
        _cleanup_free_ EFI_HANDLE *handles = NULL;
        size_t n_handles = 0;
        static uint32_t mode = 0;
        static int found = -1;
        EFI_STATUS err;

        assert(ret_mode);

        /* Doesn't depend on the capsule being inspected, cache the result */
        if (found > 0) {
                *ret_mode = mode;
                return EFI_SUCCESS;
        }
        if (found == 0)
                return EFI_UNSUPPORTED;

        err = BS->LocateHandleBuffer(
                        ByProtocol,
                        MAKE_GUID_PTR(EFI_GRAPHICS_OUTPUT_PROTOCOL),
                        /* SearchKey= */ NULL,
                        &n_handles,
                        &handles);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to locate graphics output protocol handles: %m");
        if (n_handles == 0 || !handles)
                return log_error_status(EFI_UNSUPPORTED, "No graphics output protocol handles found for UX capsule");

        FOREACH_ARRAY(h, handles, n_handles) {
                EFI_GRAPHICS_OUTPUT_PROTOCOL *proto;

                err = BS->OpenProtocol(*h,
                                       MAKE_GUID_PTR(EFI_GRAPHICS_OUTPUT_PROTOCOL),
                                       (void **)&proto,
                                       image,
                                       /* ControllerHandler= */ NULL,
                                       EFI_OPEN_PROTOCOL_GET_PROTOCOL);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to get graphics output protocol: %m");

                *ret_mode = mode = proto->Mode->Mode;
                found = 1;
                return EFI_SUCCESS;
        }

        found = 0;
        return EFI_UNSUPPORTED;
}

static uint8_t capsule_checksum(const uint8_t *buffer, size_t size) {
        uint8_t checksum = 0;

        assert(buffer || size == 0);

        FOREACH_ARRAY(c, buffer, size)
                checksum += *c;

        return checksum;
}

static EFI_STATUS prepare_capsules(
                EFI_HANDLE image,
                FwupUpdateTable **updates,
                size_t n_updates,
                EFI_CAPSULE_HEADER ***ret_capsules,
                size_t *ret_n_capsules,
                EFI_CAPSULE_BLOCK_DESCRIPTOR **ret_capsule_blocks) {

        _cleanup_free_ EFI_CAPSULE_BLOCK_DESCRIPTOR *capsule_blocks = NULL;
        EFI_CAPSULE_HEADER **capsules = NULL;
        size_t n_capsules = 0;
        EFI_STATUS err;

        CLEANUP_ARRAY(capsules, n_capsules, capsule_free_many);

        assert(updates || n_updates == 0);
        assert(ret_capsules);
        assert(ret_n_capsules);
        assert(ret_capsule_blocks);

        log_debug("Preparing %zu UEFI capsules...", n_updates);

        FOREACH_ARRAY(u, updates, n_updates) {
                _cleanup_file_close_ EFI_FILE *root = NULL;
                err = open_volume((*u)->device_handle, &root);
                if (err != EFI_SUCCESS) {
                        log_warning_status(err, "Failed to open volume for '%ls': %m, skipping", (*u)->name);
                        continue;
                }

                _cleanup_free_ char16_t *dp_str = NULL;
                err = device_path_to_str((*u)->file_dp, &dp_str);
                if (err != EFI_SUCCESS) {
                        log_warning_status(err, "Failed to convert device path for '%ls' to string: %m, skipping", (*u)->name);
                        continue;
                }

                _cleanup_free_ char *file_buffer = NULL;
                size_t file_size = 0;
                err = file_read(root, dp_str, /* offset= */ 0, /* size= */ 0, &file_buffer, &file_size);
                if (err != EFI_SUCCESS) {
                        log_warning_status(err, "Failed to read file for '%ls': %m, skipping", (*u)->name);
                        continue;
                }

                if (file_size < sizeof(EFI_CAPSULE_HEADER)) {
                        log_warning("File '%ls' is too small for EFI_CAPSULE_HEADER: %zu < %zu, skipping", (*u)->name, file_size, sizeof(EFI_CAPSULE_HEADER));
                        continue;
                }
                EFI_CAPSULE_HEADER *capsule = (EFI_CAPSULE_HEADER *)file_buffer;

                EFI_GUID guid = (*u)->info->guid; /* Avoid unaligned access warning, since info is packed */
                /* Is this a Microsoft UX capsule? Then let's do special processing for it */
                if (efi_guid_equal(&guid, MAKE_GUID_PTR(UX_CAPSULE))) {
                        if (UINT32_MAX - capsule->HeaderSize < (uint32_t) sizeof(UX_CAPSULE_HEADER)) {
                                log_warning("Capsule header too large to parse UX_CAPSULE_HEADER: %" PRIu32 ", skipping",
                                            capsule->HeaderSize);
                                continue;
                        }

                        if (capsule->HeaderSize + sizeof(UX_CAPSULE_HEADER) > file_size) {
                                log_warning("File '%ls' is too small for UX_CAPSULE_HEADER: %zu < %" PRIu32 ", skipping",
                                            (*u)->name, file_size, capsule->HeaderSize);
                                continue;
                        }

                        /* struct is packed, so no alignment check is necessary */
                        UX_CAPSULE_HEADER *hdr = (UX_CAPSULE_HEADER *)((uint8_t *)capsule + capsule->HeaderSize);
                        uint32_t mode = 0;

                        err = get_graphics_protocol_mode(image, &mode);
                        if (err != EFI_SUCCESS)
                                return log_error_status(err, "Failed to get graphics protocol mode for UX capsule: %m");
                        hdr->mode = mode; /* hdr is packed so cannot take a pointer to a field, it would be unaligned */

                        /* Since the mode is updated, need to recalculate the checksum */
                        hdr->checksum = 0;
                        hdr->checksum = capsule_checksum((uint8_t *) hdr, sizeof(UX_CAPSULE_HEADER));
                } else if (capsule->Flags == 0)
                        /* fwupd supplies any required flags; do not impose platform-specific reset behavior. */
                        capsule->Flags = (*u)->info->capsule_flags;

                if (n_capsules == SIZE_MAX)
                        return log_error_status(EFI_OUT_OF_RESOURCES, "Too many UEFI capsules");

                EFI_CAPSULE_BLOCK_DESCRIPTOR block_descriptor = {
                        .Length = file_size,
                        .DataBlock = POINTER_TO_PHYSICAL_ADDRESS(file_buffer),
                };

                capsule_blocks = xrealloc(capsule_blocks,
                                          n_capsules * sizeof(EFI_CAPSULE_BLOCK_DESCRIPTOR),
                                          (n_capsules + 1) * sizeof(EFI_CAPSULE_BLOCK_DESCRIPTOR));
                capsule_blocks[n_capsules] = block_descriptor;

                capsules = xrealloc(capsules,
                                    n_capsules * sizeof(EFI_CAPSULE_HEADER *),
                                    (n_capsules + 1) * sizeof(EFI_CAPSULE_HEADER *));
                capsules[n_capsules++] = TAKE_PTR(capsule);
        }

        /* Need to terminate the lists with NULL/empty elements as per spec */
        capsule_blocks = xrealloc(capsule_blocks,
                                  n_capsules * sizeof(EFI_CAPSULE_BLOCK_DESCRIPTOR),
                                  (n_capsules + 1) * sizeof(EFI_CAPSULE_BLOCK_DESCRIPTOR));
        capsule_blocks[n_capsules] = (EFI_CAPSULE_BLOCK_DESCRIPTOR) { };
        capsules = xrealloc(capsules,
                            n_capsules * sizeof(EFI_CAPSULE_HEADER *),
                            (n_capsules + 1) * sizeof(EFI_CAPSULE_HEADER *));
        capsules[n_capsules] = NULL;

        *ret_capsule_blocks = TAKE_PTR(capsule_blocks);
        *ret_capsules = TAKE_PTR(capsules);
        *ret_n_capsules = n_capsules;
        n_capsules = 0;

        log_debug("Prepared %zu UEFI capsules for update.", *ret_n_capsules);

        return EFI_SUCCESS;
}

static EFI_STATUS apply_updates(
                EFI_CAPSULE_HEADER **capsules,
                size_t n_capsules,
                const EFI_CAPSULE_BLOCK_DESCRIPTOR *capsule_blocks,
                EFI_RESET_TYPE *ret_reset_type) {

        EFI_RESET_TYPE reset_type;
        uint64_t max_capsule_size;
        EFI_STATUS err;

        assert(capsules && n_capsules > 0);
        assert(capsule_blocks);
        assert(ret_reset_type);

        err = RT->QueryCapsuleCapabilities(capsules, n_capsules, &max_capsule_size, &reset_type);
        if (err != EFI_SUCCESS) {
                log_error_status(err, "Failed to query capsule capabilities, assuming EfiResetWarm: %m");
                reset_type = EfiResetWarm;
        }

        err = RT->UpdateCapsule(capsules, n_capsules, POINTER_TO_PHYSICAL_ADDRESS(capsule_blocks));
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to update capsules: %m");

        *ret_reset_type = reset_type;
        return EFI_SUCCESS;
}

static EFI_STATUS mark_capsules_as_attempted(FwupUpdateTable **updates, size_t n_updates) {
        EFI_TIME now;
        EFI_STATUS err;

        if (n_updates == 0)
                return EFI_SUCCESS;

        err = RT->GetTime(&now, NULL);
        if (err != EFI_SUCCESS) /* Should not happen, but sometimes clocks are flaky */
                now = (EFI_TIME) { };

        FOREACH_ARRAY(u, updates, n_updates) {
                log_debug("Marking UEFI update variable '%ls' as attempted", (*u)->name);

                (*u)->info->time_attempted = now;
                (*u)->info->status = FWUPDATE_ATTEMPTED;

                err = efivar_set_raw(MAKE_GUID_PTR(FWUPDATE), (*u)->name, (*u)->info, (*u)->size, (*u)->attrs);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to set variable '%ls': %m", (*u)->name);
        }

        return EFI_SUCCESS;
}

/* Implement the flow defined at https://github.com/fwupd/fwupd-efi/blob/main/SECURITY.md */
void fwupdate_install(EFI_HANDLE image, EFI_HANDLE boot_device) {
        EFI_STATUS err;

        _cleanup_free_ EFI_DEVICE_PATH *boot_disk_path = NULL;
        err = get_boot_disk_path(boot_device, &boot_disk_path);
        if (err != EFI_SUCCESS) {
                log_debug_status(err, "Cannot determine the boot disk, skipping firmware updates: %m");
                return;
        }

        /* Collect only variables whose capsules resolve on the boot disk. Variables for other disks must
         * neither be loaded nor have their status changed. */
        FwupUpdateTable **updates = NULL;
        size_t n_updates = 0;
        CLEANUP_ARRAY(updates, n_updates, fwup_update_table_free_many);
        err = parse_update_vars(boot_disk_path, &updates, &n_updates);
        if (err != EFI_SUCCESS || n_updates == 0)
                return;

        /* Now prepare the capsules by loading them in memory. This is best-effort: if there are multiple
         * capsules queued for installation, but some cannot be loaded for any reason, skip them and install
         * what we can. */
        _cleanup_free_ EFI_CAPSULE_BLOCK_DESCRIPTOR *capsule_blocks = NULL;
        EFI_CAPSULE_HEADER **capsules = NULL;
        size_t n_capsules = 0;
        CLEANUP_ARRAY(capsules, n_capsules, capsule_free_many);
        err = prepare_capsules(image, updates, n_updates, &capsules, &n_capsules, &capsule_blocks);
        if (err != EFI_SUCCESS)
                return;

        /* Mark all capsules from the boot disk as "attempted", including the ones that could not be loaded,
         * otherwise we would just loop forever. */
        err = mark_capsules_as_attempted(updates, n_updates);
        if (err != EFI_SUCCESS)
                return;

        /* If no capsules could be prepared, log and bail out, no need to reset.
         * NB: this check is placed after the efi var update, since not all efi vars might reference
         * existing or valid capsules, but the variables need to be marked as processed anyway in order
         * to avoid getting stuck in a loop. */
        if (n_capsules == 0)
                return (void) log_error("No capsules could be prepared out of %zu updates.", n_updates);

        log_info("Applying %zu updates, and then resetting system.", n_capsules);
        log_wait();

        EFI_RESET_TYPE reset_type = EfiResetWarm;
        err = apply_updates(capsules, n_capsules, capsule_blocks, &reset_type);
        if (err != EFI_SUCCESS)
                return;

        /* The update might already reboot, so might not get to this point. */
        log_info("Applied %zu updates, resetting system.", n_capsules);
        log_wait();

        RT->ResetSystem(reset_type, EFI_SUCCESS, /* DataSize= */ 0, /* ResetData= */ NULL);
        assert_not_reached();
}
