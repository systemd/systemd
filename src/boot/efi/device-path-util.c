/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-path-util.h"
#include "util.h"

EFI_STATUS make_multiple_file_device_path(EFI_HANDLE device, const char16_t **files, EFI_DEVICE_PATH
                                          ***ret_dp)
{
        EFI_STATUS err;
        EFI_DEVICE_PATH *cur_dp = NULL, **iterator_dp = NULL;
        EFI_DEVICE_PATH *original_device_path = NULL;
        size_t n_files = 0;

        assert(files);
        assert(ret_dp);

        err = BS->HandleProtocol(device, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **)
                                 &original_device_path);
        if (err != EFI_SUCCESS)
                return err;

        EFI_DEVICE_PATH *end_node = original_device_path;
        while (!device_path_is_end(end_node))
                end_node = device_path_next_node(end_node);


        size_t o_dp_size = (uint8_t *) end_node - (uint8_t *) original_device_path;
        STRV_FOREACH(file, files) {
                n_files += 1;
        }

        *ret_dp = xnew(EFI_DEVICE_PATH*, n_files);

        if (n_files == 0)
                return EFI_SUCCESS;

        iterator_dp = ret_dp[0];

        STRV_FOREACH(file, files) {
                size_t file_size = strsize16(*file);

                // 1st element: FILEPATH_DEVICE_PATH + path name payload
                // 2nd element: DEVICE_PATH_END_NODE
                *iterator_dp = xnew(EFI_DEVICE_PATH, o_dp_size +
                                    sizeof(FILEPATH_DEVICE_PATH)
                                    + file_size
                                    + sizeof(EFI_DEVICE_PATH));
                cur_dp = *iterator_dp;

                /* Prepend the original device path */
                cur_dp = mempcpy(cur_dp, original_device_path, o_dp_size);

                FILEPATH_DEVICE_PATH *file_dp = (FILEPATH_DEVICE_PATH *) cur_dp;
                file_dp->Header = (EFI_DEVICE_PATH) {
                        .Type = MEDIA_DEVICE_PATH,
                        .SubType = MEDIA_FILEPATH_DP,
                        .Length = sizeof(FILEPATH_DEVICE_PATH) + file_size,
                };
                memcpy(file_dp->PathName, *file, file_size);

                cur_dp = device_path_next_node(cur_dp);
                *cur_dp = DEVICE_PATH_END_NODE;

                iterator_dp++;
        }

        return EFI_SUCCESS;
}

EFI_STATUS make_file_device_path(EFI_HANDLE device, const char16_t *file, EFI_DEVICE_PATH **ret_dp) {
        EFI_STATUS err;
        EFI_DEVICE_PATH *dp;

        assert(file);
        assert(ret_dp);

        err = BS->HandleProtocol(device, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &dp);
        if (err != EFI_SUCCESS)
                return err;

        EFI_DEVICE_PATH *end_node = dp;
        while (!device_path_is_end(end_node))
                end_node = device_path_next_node(end_node);

        size_t file_size = strsize16(file);
        size_t dp_size = (uint8_t *) end_node - (uint8_t *) dp;

        /* Make a copy that can also hold a file media device path. */
        *ret_dp = xmalloc(dp_size + file_size + sizeof(FILEPATH_DEVICE_PATH) + sizeof(EFI_DEVICE_PATH));
        dp = mempcpy(*ret_dp, dp, dp_size);

        FILEPATH_DEVICE_PATH *file_dp = (FILEPATH_DEVICE_PATH *) dp;
        file_dp->Header = (EFI_DEVICE_PATH) {
                .Type = MEDIA_DEVICE_PATH,
                .SubType = MEDIA_FILEPATH_DP,
                .Length = sizeof(FILEPATH_DEVICE_PATH) + file_size,
        };
        memcpy(file_dp->PathName, file, file_size);

        dp = device_path_next_node(dp);
        *dp = DEVICE_PATH_END_NODE;
        return EFI_SUCCESS;
}

EFI_STATUS device_path_to_str(const EFI_DEVICE_PATH *dp, char16_t **ret) {
        EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *dp_to_text;
        EFI_STATUS err;
        _cleanup_free_ char16_t *str = NULL;

        assert(dp);
        assert(ret);

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_DEVICE_PATH_TO_TEXT_PROTOCOL), NULL, (void **) &dp_to_text);
        if (err != EFI_SUCCESS) {
                /* If the device path to text protocol is not available we can still do a best-effort attempt
                 * to convert it ourselves if we are given filepath-only device path. */

                size_t size = 0;
                for (const EFI_DEVICE_PATH *node = dp; !device_path_is_end(node);
                     node = device_path_next_node(node)) {
                        log_internal(EFI_SUCCESS, "%hu %hu %hu", node->Type, node->SubType, node->Length);
                        if (node->Type != MEDIA_DEVICE_PATH || node->SubType != MEDIA_FILEPATH_DP)
                                return err;

                        size_t path_size = node->Length;
                        if (path_size <= offsetof(FILEPATH_DEVICE_PATH, PathName) || path_size % sizeof(char16_t))
                                return EFI_INVALID_PARAMETER;
                        path_size -= offsetof(FILEPATH_DEVICE_PATH, PathName);

                        _cleanup_free_ char16_t *old = str;
                        str = xmalloc(size + path_size);
                        if (old) {
                                memcpy(str, old, size);
                                str[size / sizeof(char16_t) - 1] = '\\';
                        }

                        memcpy(str + (size / sizeof(char16_t)),
                               ((uint8_t *) node) + offsetof(FILEPATH_DEVICE_PATH, PathName),
                               path_size);
                        size += path_size;
                }

                *ret = TAKE_PTR(str);
                return EFI_SUCCESS;
        }

        str = dp_to_text->ConvertDevicePathToText(dp, false, false);
        if (!str)
                return EFI_OUT_OF_RESOURCES;

        *ret = TAKE_PTR(str);
        return EFI_SUCCESS;
}

bool device_path_startswith(const EFI_DEVICE_PATH *dp, const EFI_DEVICE_PATH *start) {
        if (!start)
                return true;
        if (!dp)
                return false;
        for (;;) {
                if (device_path_is_end(start))
                        return true;
                if (device_path_is_end(dp))
                        return false;
                if (start->Length != dp->Length)
                        return false;
                if (memcmp(dp, start, start->Length) != 0)
                        return false;
                start = device_path_next_node(start);
                dp = device_path_next_node(dp);
        }
}

EFI_DEVICE_PATH *device_path_replace_node(
                const EFI_DEVICE_PATH *path, const EFI_DEVICE_PATH *node, const EFI_DEVICE_PATH *new_node) {

        /* Create a new device path as a copy of path, while chopping off the remainder starting at the given
         * node. If new_node is provided, it is appended at the end of the new path. */

        assert(path);
        assert(node);

        size_t len = (uint8_t *) node - (uint8_t *) path;
        EFI_DEVICE_PATH *ret = xmalloc(len + (new_node ? new_node->Length : 0) + sizeof(EFI_DEVICE_PATH));
        EFI_DEVICE_PATH *end = mempcpy(ret, path, len);

        if (new_node)
                end = mempcpy(end, new_node, new_node->Length);

        *end = DEVICE_PATH_END_NODE;
        return ret;
}

const EFI_DEVICE_PATH **split_multiple_file_device_path(const EFI_DEVICE_PATH *dp) {
        /* Split a multi-instance device path
        * into an array of single-instance device path
        * */

        /* To achieve this, we need to:
         * (1) determine how many instances is there in this multi-instance device path
         * (2) we will copy the entire multi instance device
         * (3) arrange an array of size n_instances of type EFI_DEVICE_PATH*
         *      containing for each index the start pointer of an instance
         * (4) each time, we will encounter an END INSTANCE, we will replace it
         *      by an END NODE
         * (5) return an array of EFI_DEVICE_PATH*, i.e. EFI_DEVICE_PATH**
         * */
        const EFI_DEVICE_PATH *end = dp;
        const EFI_DEVICE_PATH **instances = NULL;
        EFI_DEVICE_PATH *next = NULL;
        EFI_DEVICE_PATH *ret_dp = NULL;
        size_t n_dps = 0;
        size_t n_instances = 0;
        size_t total_dp_size = 0;

        assert(dp);

        /* We determine (1) */
        while (!device_path_is_end(end)) {
                n_instances++;
                while (!device_path_is_end_instance(end)) {
                        n_dps++;
                        end = device_path_next_node(end);
                        if (device_path_is_end(end))
                                break;
                }
                if (device_path_is_end(end))
                        break;
                end = device_path_next_node(end);
        }
        total_dp_size = (uint8_t *)end - (uint8_t *)dp;

        /* We count the final device path this way */
        n_dps += 1;
        total_dp_size += sizeof(EFI_DEVICE_PATH);

        log_internal(EFI_SUCCESS, "total dp size: %lu, n_dps: %lu, n_instances: %lu", total_dp_size, n_dps,
                     n_instances);

        /* We perform the copy mentioned in (2) */
        ret_dp = xmalloc(total_dp_size);
        mempcpy(ret_dp, dp, total_dp_size);

        log_internal(EFI_SUCCESS, "copied dp (%p) into ret_dp (%p)", dp, ret_dp);

        /* We arrange the array mentioned in (3) */
        log_internal(EFI_SUCCESS, "allocating %lu instances", n_instances);
        instances = xmalloc(sizeof(EFI_DEVICE_PATH*) * (n_instances + 1));
        end = ret_dp;
        for (size_t instance_index = 0 ;; instance_index++) {
                assert(instance_index < n_instances);

                instances[instance_index] = end;
                log_internal(EFI_SUCCESS, "wrote %lu-instance, now at %p", instance_index, end);

                while (!device_path_is_end_instance(end)) {
                        log_internal(EFI_SUCCESS, "chasing %p -> %p, type: %hu, subtype: %hu", end, device_path_next_node(end), end->Type, end->SubType);
                        end = device_path_next_node(end);
                        if (device_path_is_end(end))
                                break;
                }

                if (device_path_is_end(end))
                        break;
                else
                        end = device_path_next_node(end);
        }

        instances[n_instances] = NULL;

        log_internal(EFI_SUCCESS, "allocated %lu instances", n_instances);

        /* We replace all END_INSTANCE by END_NODE as mentioned in (4) */
        next = ret_dp;
        while (!device_path_is_end(next)) {
                if (device_path_is_end_instance(next)) {
                        *next = DEVICE_PATH_END_NODE;
                        log_internal(EFI_SUCCESS, "wrote END NODE instead of END INSTANCE");
                }
                next = device_path_next_node(next);
        }

        return instances;
}
