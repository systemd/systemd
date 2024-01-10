/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dhcp-client-id-internal.h"
#include "unaligned.h"
#include "utf8.h"

int sd_dhcp_client_id_clear(sd_dhcp_client_id *client_id) {
        assert_return(client_id, -EINVAL);

        *client_id = (sd_dhcp_client_id) {};
        return 0;
}

int sd_dhcp_client_id_is_set(const sd_dhcp_client_id *client_id) {
        if (!client_id)
                return false;

        return client_id_size_is_valid(client_id->size);
}

int sd_dhcp_client_id_get(const sd_dhcp_client_id *client_id, uint8_t *ret_type, const void **ret_data, size_t *ret_size) {
        assert_return(sd_dhcp_client_id_is_set(client_id), -EINVAL);
        assert_return(ret_type, -EINVAL);
        assert_return(ret_data, -EINVAL);
        assert_return(ret_size, -EINVAL);

        *ret_type = client_id->id.type;
        *ret_data = client_id->id.data;
        *ret_size = client_id->size - offsetof(typeof(client_id->id), data);
        return 0;
}

int sd_dhcp_client_id_get_raw(const sd_dhcp_client_id *client_id, const void **ret_data, size_t *ret_size) {
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
        assert_return(client_id_data_size_is_valid(data_size), -EINVAL);

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
        assert_return(client_id_size_is_valid(data_size), -EINVAL);

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

int sd_dhcp_client_id_to_string(const sd_dhcp_client_id *client_id, char **ret) {
        _cleanup_free_ char *t = NULL;
        size_t len;
        int r;

        assert_return(sd_dhcp_client_id_is_set(client_id), -EINVAL);
        assert_return(ret, -EINVAL);

        len = client_id->size - offsetof(typeof(client_id->id), data);

        switch (client_id->id.type) {
        case 0:
                if (utf8_is_printable((char *) client_id->id.gen.data, len))
                        r = asprintf(&t, "%.*s", (int) len, client_id->id.gen.data);
                else
                        r = asprintf(&t, "DATA");
                break;
        case 1:
                if (len == sizeof_field(sd_dhcp_client_id, id.eth))
                        r = asprintf(&t, "%02x:%02x:%02x:%02x:%02x:%02x",
                                     client_id->id.eth.haddr[0],
                                     client_id->id.eth.haddr[1],
                                     client_id->id.eth.haddr[2],
                                     client_id->id.eth.haddr[3],
                                     client_id->id.eth.haddr[4],
                                     client_id->id.eth.haddr[5]);
                else
                        r = asprintf(&t, "ETHER");
                break;
        case 2 ... 254:
                r = asprintf(&t, "ARP/LL");
                break;
        case 255:
                if (len < sizeof(uint32_t))
                        r = asprintf(&t, "IAID/DUID");
                else {
                        uint32_t iaid = be32toh(client_id->id.ns.iaid);
                        /* TODO: check and stringify DUID */
                        r = asprintf(&t, "IAID:0x%x/DUID", iaid);
                }
                break;
        default:
                assert_not_reached();
        }
        if (r < 0)
                return -ENOMEM;

        *ret = TAKE_PTR(t);
        return 0;
}

int sd_dhcp_client_id_to_string_from_raw(const void *data, size_t data_size, char **ret) {
        sd_dhcp_client_id client_id;
        int r;

        assert_return(data, -EINVAL);
        assert_return(client_id_size_is_valid(data_size), -EINVAL);
        assert_return(ret, -EINVAL);

        r = sd_dhcp_client_id_set_raw(&client_id, data, data_size);
        if (r < 0)
                return r;

        return sd_dhcp_client_id_to_string(&client_id, ret);
}

void client_id_hash_func(const sd_dhcp_client_id *client_id, struct siphash *state) {
        assert(sd_dhcp_client_id_is_set(client_id));
        assert(state);

        siphash24_compress_typesafe(client_id->size, state);
        siphash24_compress(client_id->raw, client_id->size, state);
}

int client_id_compare_func(const sd_dhcp_client_id *a, const sd_dhcp_client_id *b) {
        assert(sd_dhcp_client_id_is_set(a));
        assert(sd_dhcp_client_id_is_set(b));

        return memcmp_nn(a->raw, a->size, b->raw, b->size);
}
