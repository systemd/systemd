/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-path-util.h"
#include "efi.h"
#include "efi-efivars.h"
#include "efi-log.h"
#include "fwupd.h"
#include "string-util-fundamental.h"
#include "util.h"

#define FWUPDATE_ATTEMPT_UPDATE 0x00000001
#define FWUPDATE_ATTEMPTED      0x00000002

#define CAPSULE_FLAGS_PERSIST_ACROSS_RESET    0x00010000
#define CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE   0x00020000
#define CAPSULE_FLAGS_INITIATE_RESET          0x00040000

#define EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID { 0x9042a9de, 0x23dc, 0x4a38, {0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a } }
#define UX_CAPSULE_GUID {0x3b8c8162, 0x188c, 0x46a4, {0xae, 0xc9, 0xbe, 0x43, 0xf1, 0xd6, 0x56, 0x97} }

typedef struct {
        uint32_t max_mode;
        uint32_t mode;
        /*EFI_GRAPHICS_OUTPUT_MODE_INFORMATION*/ void *info;
        uint64_t size_of_info;
        EFI_PHYSICAL_ADDRESS frame_buffer_base;
        uint64_t frame_buffer_size;
} EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE;

typedef struct  {
        void *query_mode;
        void *set_mode;
        void *blt;
        EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *mode;
} EFI_GRAPHICS_OUTPUT_PROTOCOL;

typedef struct {
        uint8_t version;
        uint8_t checksum;
        uint8_t image_type;
        uint8_t reserved;
        uint32_t mode;
        uint32_t x_offset;
        uint32_t y_offset;
} _packed_ UX_CAPSULE_HEADER;

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
} FwupUpdateTable;

static FwupUpdateTable *
fwup_update_table_free(FwupUpdateTable *update) {
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

static EFI_STATUS parse_info_var(const char16_t *name, FwupUpdateTable **ret_update) {
        _cleanup_free_ void *infop = NULL;
        size_t size = 0;
        uint32_t flags = 0;
        EFI_STATUS err;

        assert(name);
        assert(ret_update);

        err = efivar_get_raw_flags(MAKE_GUID_PTR(FWUPDATE), name, &infop, &size, &flags);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to get variable '%ls': %m", name);

        if (size < sizeof(FWUP_UPDATE_INFO)) {
                log_error("Variable '%ls' is too small: %zu < %zu", name, size, sizeof(FWUP_UPDATE_INFO));
                return EFI_INVALID_PARAMETER;
        }

        FWUP_UPDATE_INFO *info = (FWUP_UPDATE_INFO *)infop;
        EFI_DEVICE_PATH *hdr = (EFI_DEVICE_PATH *)&info->dp;

        size_t space_left, dp_size;
        space_left = size - offsetof(FWUP_UPDATE_INFO, dp);
        dp_size = device_path_size_with_limit(hdr, space_left);
        if (space_left != dp_size) {
                log_error("Variable '%ls' is too small for EFI_DEVICE_PATH: %zu != %zu", name, space_left, dp_size);
                return EFI_INVALID_PARAMETER;
        }

        *ret_update = xnew0(FwupUpdateTable, 1);
        (*ret_update)->name = xstrdup16(name);
        (*ret_update)->size = size;
        (*ret_update)->info = info;
        (*ret_update)->attrs = flags;
        TAKE_PTR(infop);

        log_debug("Parsed UEFI update variable '%ls': flags=0x%08x, hw_inst=%" PRIu64 ", status=%" PRIu32,
                  name,
                  info->capsule_flags,
                  info->hw_inst,
                  info->status);

        return EFI_SUCCESS;
}

static EFI_STATUS parse_update_vars(FwupUpdateTable ***updates, size_t *n_updates) {
        size_t name_length = 1024 * sizeof(char16_t);
        _cleanup_free_ char16_t *name = NULL;
        EFI_STATUS err;

        assert(updates);
        assert(n_updates);

        log_debug("Searching for UEFI updates...");

        /* A series of fwupd-* named variables will be prepared by userspace, but there is no fixed name,
         * so we need to iterate over the full table of variables and find them. Unfortunately there are no
         * APIs to search by GUID, so it's really the entire table that has to be walked. */

        name = xnew0(char16_t, name_length);

        for (;;) {
                EFI_GUID guid;

                err = RT->GetNextVariableName(&name_length, name, &guid);
                if (err == EFI_NOT_FOUND)
                        break;
                if (err == EFI_BUFFER_TOO_SMALL) {
                        name = xrealloc(name, name_length, name_length * 2);
                        name_length *= 2;
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
                if (err != EFI_SUCCESS) {
                        efivar_unset(MAKE_GUID_PTR(FWUPDATE), name, 0);
                        return err;
                }
                if (!FLAGS_SET(update->info->status, FWUPDATE_ATTEMPT_UPDATE))
                        continue;

                EFI_TIME now;
                err = RT->GetTime(&now, NULL);
                if (err == EFI_SUCCESS)
                        update->info->time_attempted = now;
                update->info->status = FWUPDATE_ATTEMPTED;
                *updates = xrealloc(*updates,
                                    *n_updates * sizeof(FwupUpdateTable),
                                    (*n_updates + 1) * sizeof(FwupUpdateTable));
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
        if (n_handles == 0 || !handles) {
                log_error("No graphics output protocol handles found for UX capsule");
                return EFI_UNSUPPORTED;
        }

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

                *ret_mode = mode = proto->mode->mode;
                found = 1;
                return EFI_SUCCESS;
        }

        found = 0;
        return EFI_UNSUPPORTED;
}

static EFI_DEVICE_PATH *device_path_instance(EFI_DEVICE_PATH **device_path, size_t *ret_size) {
        EFI_DEVICE_PATH *head, *next, *dp;

        assert(device_path);
        assert(ret_size);

        if (!*device_path) {
                *ret_size = 0;
                return NULL;
        }

        dp = head = *device_path;

        for (;;) {
                next = device_path_next_node(dp);

                if (device_path_is_end(dp))
                        break;

                dp = next;
        }

        if (dp->SubType == END_ENTIRE_DEVICE_PATH_SUBTYPE)
                next = NULL;

        *device_path = next;
        *ret_size = ((uint8_t *) dp) - ((uint8_t *) head);

        return head;
}

static EFI_STATUS find_capsule(const char16_t *name, EFI_DEVICE_PATH **file_dp, EFI_HANDLE *ret_device_handle) {
        EFI_HANDLE device_handle;
        EFI_STATUS err;

        assert(name);
        assert(file_dp);
        assert(ret_device_handle);

        err = BS->LocateDevicePath(MAKE_GUID_PTR(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL), file_dp, &device_handle);
        if (err == EFI_SUCCESS) {
                if ((*file_dp)->Type != MEDIA_DEVICE_PATH || (*file_dp)->SubType != MEDIA_FILEPATH_DP) {
                        log_error("Invalid device path type for '%ls': %m", name);
                        return EFI_INVALID_PARAMETER;
                }

                *ret_device_handle = device_handle;
                return EFI_SUCCESS;
        }

        _cleanup_free_ EFI_HANDLE *handles = NULL;
        size_t n_handles;
        err = BS->LocateHandleBuffer(
                        ByProtocol,
                        MAKE_GUID_PTR(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL),
                        /* SearchKey= */ NULL,
                        &n_handles,
                        &handles);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to locate file system handles: %m");

        _cleanup_free_ EFI_DEVICE_PATH *dp = device_path_dup(*file_dp);
        size_t index = 0;
        EFI_DEVICE_PATH *d = dp;

        for (;;) {
                if (device_path_is_end(d)) {
                        log_error("Device path for '%ls' is empty", name);
                        return EFI_INVALID_PARAMETER;
                }
                if (d->Type == MEDIA_DEVICE_PATH && d->SubType == MEDIA_FILEPATH_DP)
                        break;

                index++;
                d = device_path_next_node(d);
        }
        *d = DEVICE_PATH_END_NODE;

        FOREACH_ARRAY(h, handles, n_handles) {
                EFI_DEVICE_PATH *fs_dp;

                err = BS->HandleProtocol(*h, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &fs_dp);
                if (err != EFI_SUCCESS)
                        continue;

                while (!device_path_is_end(fs_dp)) {
                        EFI_DEVICE_PATH *p, *q = fs_dp;
                        size_t size;

                        while ((p = device_path_instance(&q, &size)))
                                if (memcmp(dp, p, size) == 0) {
                                        device_handle = *h;
                                        for (size_t i = 0; i < index; i++)
                                                *file_dp = device_path_next_node(*file_dp);

                                        if ((*file_dp)->Type != MEDIA_DEVICE_PATH || (*file_dp)->SubType != MEDIA_FILEPATH_DP) {
                                                log_error("Invalid device path for '%ls': %m", name);
                                                return EFI_INVALID_PARAMETER;
                                        }

                                        *ret_device_handle = device_handle;
                                        return EFI_SUCCESS;
                                }

                        fs_dp = device_path_next_node(fs_dp);
                }
        }

        log_error("Failed to find device path '%ls' in any file system", name);
        return EFI_NOT_FOUND;
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
                EFI_DEVICE_PATH *file_dp = (EFI_DEVICE_PATH *)(*u)->info->dp_buf;
                EFI_HANDLE device_handle = NULL;

                err = find_capsule((*u)->name, &file_dp, &device_handle);
                if (err != EFI_SUCCESS) {
                        log_error("Failed to find capsule '%ls': %m", (*u)->name);
                        continue;
                }

                _cleanup_file_close_ EFI_FILE *root = NULL;
                err = open_volume(device_handle, &root);
                if (err != EFI_SUCCESS) {
                        log_error("Failed to open volume for '%ls': %m", (*u)->name);
                        continue;
                }

                _cleanup_free_ char16_t *dp_str = NULL;
                err = device_path_to_str(file_dp, &dp_str);
                if (err != EFI_SUCCESS) {
                        log_error("Failed to convert device path for '%ls' to string: %m", (*u)->name);
                        continue;
                }

                _cleanup_free_ char *file_buffer = NULL;
                size_t file_size = 0;
                err = file_read(root, dp_str, 0, 0, &file_buffer, &file_size);
                if (err != EFI_SUCCESS) {
                        log_error("Failed to read file for '%ls': %m", (*u)->name);
                        continue;
                }

                if (file_size < sizeof(EFI_CAPSULE_HEADER)) {
                        log_error("File '%ls' is too small for EFI_CAPSULE_HEADER: %zu < %zu", (*u)->name, file_size, sizeof(EFI_CAPSULE_HEADER));
                        continue;
                }

                EFI_CAPSULE_BLOCK_DESCRIPTOR block_descriptor = {
                        .Length = file_size,
                        .DataBlock = (EFI_PHYSICAL_ADDRESS)(uintptr_t)file_buffer,
                };
                EFI_CAPSULE_HEADER *capsule = (EFI_CAPSULE_HEADER *)file_buffer;

                EFI_GUID guid = (*u)->info->guid; /* Avoid unaligned access warning */
                if (efi_guid_equal(&guid, MAKE_GUID_PTR(UX_CAPSULE))) {
                        UX_CAPSULE_HEADER *hdr = (UX_CAPSULE_HEADER *)(((uint8_t *)capsule) + capsule->HeaderSize);
                        uint32_t mode = 0;

                        err = get_graphics_protocol_mode(image, &mode);
                        if (err != EFI_SUCCESS)
                                return log_error_status(err, "Failed to get graphics protocol mode for UX capsule: %m");
                        hdr->mode = mode; /* Avoid unaligned access warning */

                        /* Since the mode is updated, need to recalculate the checksum */
                        uint8_t checksum = 0, *p = (uint8_t *) hdr;
                        hdr->checksum = 0;
                        FOREACH_ARRAY(c, p, sizeof(UX_CAPSULE_HEADER))
                                checksum += *c;
                        hdr->checksum = checksum;
                }

                if (capsule->Flags == 0 && !efi_guid_equal(&guid, MAKE_GUID_PTR(UX_CAPSULE))) {
#if defined(__aarch64__) || (defined(__riscv) && __riscv_xlen == 64)
                        capsule->Flags |= (*u)->info->capsule_flags;
#else
                        capsule->Flags |= (*u)->info->capsule_flags |
                                          CAPSULE_FLAGS_PERSIST_ACROSS_RESET |
                                          CAPSULE_FLAGS_INITIATE_RESET;
#endif
                }

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
        capsule_blocks[n_capsules] = (EFI_CAPSULE_BLOCK_DESCRIPTOR) {
                .Length = 0,
                .ContinuationPointer = 0,
        };
        capsules = xrealloc(capsules,
                            n_capsules * sizeof(EFI_CAPSULE_HEADER *),
                            (n_capsules + 1) * sizeof(EFI_CAPSULE_HEADER *));
        capsules[n_capsules] = NULL;

        *ret_capsule_blocks = TAKE_PTR(capsule_blocks);
        *ret_capsules = TAKE_PTR(capsules);
        *ret_n_capsules = n_capsules;
        n_capsules = 0;

        log_debug("Prepared %zu UEFI capsules for updates.", *ret_n_capsules);

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

        err = RT->UpdateCapsule(capsules, n_capsules, (EFI_PHYSICAL_ADDRESS)(uintptr_t)capsule_blocks);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to update capsule: %m");

        *ret_reset_type = reset_type;
        return EFI_SUCCESS;
}

/* Implement the flow defined at https://github.com/fwupd/fwupd-efi/blob/main/SECURITY.md */
void fwupd_install_updates(EFI_HANDLE image) {
        EFI_STATUS err;

        /* Userspace prepares a set of 'fwupd-*' variables pointing to the capsules to install, parse them
         * and store them in a table. */
        FwupUpdateTable **updates = NULL;
        size_t n_updates = 0;
        CLEANUP_ARRAY(updates, n_updates, fwup_update_table_free_many);
        err = parse_update_vars(&updates, &n_updates);
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

        /* Mark all parsed capsules as "attempted" to be updated. This also includes the ones that could not
         * be loaded, otherwise we would just loop forever. */
        FOREACH_ARRAY(u, updates, n_updates) {
                log_debug("Marking UEFI update variable '%ls' as attempted", (*u)->name);
                err = efivar_set_raw(MAKE_GUID_PTR(FWUPDATE), (*u)->name, (*u)->info, (*u)->size, (*u)->attrs);
                if (err != EFI_SUCCESS)
                        return (void) log_error_status(err, "Failed to set variable '%ls': %m", (*u)->name);
        }

        /* If no capsules could be prepared, log and bail out, no need to reset. */
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

        RT->ResetSystem(reset_type, EFI_SUCCESS, 0, NULL);
        assert_not_reached();
}
