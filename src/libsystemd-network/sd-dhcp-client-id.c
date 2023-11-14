/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dhcp-client-id-internal.h"
#include "unaligned.h"
#include "utf8.h"

int sd_dhcp_client_id_new(sd_dhcp_client_id **ret) {
        sd_dhcp_client_id *client_id;

        assert_return(ret, -EINVAL);

        client_id = new0(sd_dhcp_client_id, 1);
        if (!client_id)
                return -ENOMEM;

        *ret = client_id;
        return 0;
}

sd_dhcp_client_id* sd_dhcp_client_id_free(sd_dhcp_client_id *client_id) {
        return mfree(client_id);
}

int sd_dhcp_client_id_clear(sd_dhcp_client_id *client_id) {
        assert_return(client_id, -EINVAL);

        *client_id = (sd_dhcp_client_id) {};
        return 0;
}

int sd_dhcp_client_id_is_set(sd_dhcp_client_id *client_id) {
        if (!client_id)
                return false;

        return client_id->size >= MIN_CLIENT_ID_LEN && client_id->size <= MAX_CLIENT_ID_LEN;
}

int sd_dhcp_client_id_get(sd_dhcp_client_id *client_id, uint8_t *ret_type, const void **ret_data, size_t *ret_size) {
        assert_return(sd_dhcp_client_id_is_set(client_id), -EINVAL);
        assert_return(ret_type, -EINVAL);
        assert_return(ret_data, -EINVAL);
        assert_return(ret_size, -EINVAL);

        *ret_type = client_id->id.type;
        *ret_data = client_id->id.data;
        *ret_size = client_id->size - offsetof(typeof(client_id->id), data);
        return 0;
}

int sd_dhcp_client_id_get_raw(sd_dhcp_client_id *client_id, const void **ret_data, size_t *ret_size) {
        assert_return(sd_dhcp_client_id_is_set(client_id), -EINVAL);
        assert_return(ret_data, -EINVAL);
        assert_return(ret_size, -EINVAL);

        /* Unlike sd_dhcp_client_id_get(), this returns whole client ID including its type. */

        *ret_data = client_id->raw;
        *ret_size = client_id->size;
        return 0;
}

int sd_dhcp_client_id_set(
                sd_dhcp_client_id *client_id,
                uint8_t type,
                const void *data,
                size_t data_size) {

        assert_return(client_id, -EINVAL);
        assert_return(data, -EINVAL);
        assert_return(data_size >= MIN_CLIENT_ID_DATA_LEN && data_size <= MAX_CLIENT_ID_DATA_LEN, -EINVAL);

        client_id->id.type = type;
        memcpy(client_id->id.data, data, data_size);

        client_id->size = offsetof(typeof(client_id->id), data) + data_size;
        return 0;
}

int sd_dhcp_client_id_set_raw(
                sd_dhcp_client_id *client_id,
                const void *data,
                size_t data_size) {

        assert_return(client_id, -EINVAL);
        assert_return(data, -EINVAL);
        assert_return(data_size >= MIN_CLIENT_ID_LEN && data_size <= MAX_CLIENT_ID_LEN, -EINVAL);

        /* Unlike sd_dhcp_client_id_set(), this takes whole client ID including its type. */

        memcpy(client_id->raw, data, data_size);

        client_id->size = data_size;
        return 0;
}

int sd_dhcp_client_id_set_iaid_duid(
                sd_dhcp_client_id *client_id,
                uint32_t iaid,
                sd_dhcp_duid *duid) {

        assert_return(client_id, -EINVAL);
        assert_return(duid, -EINVAL);
        assert_return(sd_dhcp_duid_is_set(duid), -ESTALE);

        client_id->id.type = 255;
        unaligned_write_be32(&client_id->id.ns.iaid, iaid);
        memcpy(&client_id->id.ns.duid, &duid->duid, duid->size);

        client_id->size = offsetof(typeof(client_id->id), ns.duid) + duid->size;
        return 0;
}
