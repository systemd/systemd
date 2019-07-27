#include <linux/genetlink.h>

#include "sd-netlink.h"
#include "netlink-internal.h"
#include "alloc-util.h"

typedef struct {
        const char* name;
        uint8_t version;
} genl_family;

static const genl_family genl_families[] = {
        [SD_GENL_ID_CTRL]   = { .name = "",          .version = 1 },
        [SD_GENL_WIREGUARD] = { .name = "wireguard", .version = 1 },
        [SD_GENL_FOU]       = { .name = "fou",       .version = 1 },
        [SD_GENL_L2TP]      = { .name = "l2tp",      .version = 1 },
        [SD_GENL_MACSEC]    = { .name = "macsec",    .version = 1 },
};

int sd_genl_socket_open(sd_netlink **ret) {
        return netlink_open_family(ret, NETLINK_GENERIC);
}
static int lookup_id(sd_netlink *nl, sd_genl_family family, uint16_t *id);

static int genl_message_new(sd_netlink *nl, sd_genl_family family, uint16_t nlmsg_type, uint8_t cmd, sd_netlink_message **ret) {
        int r;
        struct genlmsghdr *genl;
        const NLType *genl_cmd_type, *nl_type;
        const NLTypeSystem *type_system;
        size_t size;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;

        assert_return(nl->protocol == NETLINK_GENERIC, -EINVAL);

        r = type_system_get_type(&genl_family_type_system_root, &genl_cmd_type, family);
        if (r < 0)
                return r;

        r = message_new_empty(nl, &m);
        if (r < 0)
                return r;

        size = NLMSG_SPACE(sizeof(struct genlmsghdr));
        m->hdr = malloc0(size);
        if (!m->hdr)
                return -ENOMEM;

        m->hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

        type_get_type_system(genl_cmd_type, &type_system);

        r = type_system_get_type(type_system, &nl_type, cmd);
        if (r < 0)
                return r;

        m->hdr->nlmsg_len = size;
        m->hdr->nlmsg_type = nlmsg_type;

        type_get_type_system(nl_type, &m->containers[0].type_system);
        genl = NLMSG_DATA(m->hdr);
        genl->cmd = cmd;
        genl->version = genl_families[family].version;

        *ret = TAKE_PTR(m);

        return 0;
}

int sd_genl_message_new(sd_netlink *nl, sd_genl_family family, uint8_t cmd, sd_netlink_message **ret) {
        int r;
        uint16_t id = GENL_ID_CTRL;

        if (family != SD_GENL_ID_CTRL) {
                r = lookup_id(nl, family, &id);
                if (r < 0)
                        return r;
        }

        return genl_message_new(nl, family, id, cmd, ret);
}

static int lookup_id(sd_netlink *nl, sd_genl_family family, uint16_t *id) {
        int r;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;

        r = sd_genl_message_new(nl, SD_GENL_ID_CTRL, CTRL_CMD_GETFAMILY, &req);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(req, CTRL_ATTR_FAMILY_NAME, genl_families[family].name);
        if (r < 0)
                return r;

        r = sd_netlink_call(nl, req, 0, &reply);
        if (r < 0)
                return r;

        return sd_netlink_message_read_u16(reply, CTRL_ATTR_FAMILY_ID, id);
}
