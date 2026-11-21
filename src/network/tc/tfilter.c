/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_ether.h>
#include <linux/pkt_sched.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "conf-parser.h"
#include "fw.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "ordered-set.h"
#include "parse-util.h"
#include "qdisc.h"
#include "set.h"
#include "siphash24.h"
#include "string-util.h"
#include "tc-util.h"
#include "tfilter.h"

const TFilterVTable * const tfilter_vtable[_TFILTER_KIND_MAX] = {
        [TFILTER_KIND_FW] = &fw_tfilter_vtable,
};

static TFilter* tfilter_detach_impl(TFilter *tfilter) {
        assert(tfilter);
        assert(!tfilter->link || !tfilter->network);

        if (tfilter->network) {
                assert(tfilter->section);
                hashmap_remove(tfilter->network->tfilters_by_section, tfilter->section);

                tfilter->network = NULL;
                return tfilter;
        }

        if (tfilter->link) {
                set_remove(tfilter->link->tfilters, tfilter);

                tfilter->link = NULL;
                return tfilter;
        }

        return NULL;
}

static void tfilter_detach(TFilter *tfilter) {
        assert(tfilter);

        tfilter_unref(tfilter_detach_impl(tfilter));
}

static void tfilter_hash_func(const TFilter *tfilter, struct siphash *state);
static int tfilter_compare_func(const TFilter *a, const TFilter *b);

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        tfilter_hash_ops,
        TFilter,
        tfilter_hash_func,
        tfilter_compare_func,
        tfilter_detach);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        tfilter_section_hash_ops,
        ConfigSection,
        config_section_hash_func,
        config_section_compare_func,
        TFilter,
        tfilter_detach);

static int tfilter_new(TFilterKind kind, TFilter **ret) {
        _cleanup_(tfilter_unrefp) TFilter *tfilter = NULL;
        int r;

        if (kind == _TFILTER_KIND_INVALID) {
                tfilter = new(TFilter, 1);
                if (!tfilter)
                        return -ENOMEM;

                *tfilter = (TFilter) {
                        .n_ref = 1,
                        .parent = TC_H_ROOT,
                        .kind = kind,
                };
        } else {
                assert(kind >= 0 && kind < _TFILTER_KIND_MAX);
                tfilter = malloc0(tfilter_vtable[kind]->object_size);
                if (!tfilter)
                        return -ENOMEM;

                tfilter->n_ref = 1;
                tfilter->parent = TC_H_ROOT;
                tfilter->kind = kind;

                if (TFILTER_VTABLE(tfilter)->init) {
                        r = TFILTER_VTABLE(tfilter)->init(tfilter);
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(tfilter);

        return 0;
}

int tfilter_new_static(TFilterKind kind, Network *network, const char *filename, unsigned section_line, TFilter **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(tfilter_unrefp) TFilter *tfilter = NULL;
        TFilter *existing;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        existing = hashmap_get(network->tfilters_by_section, n);
        if (existing) {
                if (existing->kind != kind)
                        return -EINVAL;

                *ret = existing;
                return 0;
        }

        r = tfilter_new(kind, &tfilter);
        if (r < 0)
                return r;

        tfilter->network = network;
        tfilter->section = TAKE_PTR(n);
        tfilter->source = NETWORK_CONFIG_SOURCE_STATIC;

        r = hashmap_ensure_put(&network->tfilters_by_section, &tfilter_section_hash_ops, tfilter->section, tfilter);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(tfilter);
        return 0;
}

static TFilter* tfilter_free(TFilter *tfilter) {
        if (!tfilter)
                return NULL;

        tfilter_detach_impl(tfilter);

        config_section_free(tfilter->section);

        free(tfilter->tca_kind);
        return mfree(tfilter);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(TFilter, tfilter, tfilter_free);

static const char *tfilter_get_tca_kind(const TFilter *tfilter) {
        assert(tfilter);

        return (TFILTER_VTABLE(tfilter) && TFILTER_VTABLE(tfilter)->tca_kind) ?
                TFILTER_VTABLE(tfilter)->tca_kind : tfilter->tca_kind;
}

static void tfilter_hash_func(const TFilter *tfilter, struct siphash *state) {
        assert(tfilter);
        assert(state);

        siphash24_compress_typesafe(tfilter->handle, state);
        siphash24_compress_typesafe(tfilter->parent, state);
        siphash24_compress_typesafe(tfilter->protocol, state);
        siphash24_compress_typesafe(tfilter->priority, state);
        siphash24_compress_string(tfilter_get_tca_kind(tfilter), state);
}

static int tfilter_compare_func(const TFilter *a, const TFilter *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->handle, b->handle);
        if (r != 0)
                return r;

        r = CMP(a->parent, b->parent);
        if (r != 0)
                return r;

        r = CMP(a->protocol, b->protocol);
        if (r != 0)
                return r;

        r = CMP(a->priority, b->priority);
        if (r != 0)
                return r;

        return strcmp_ptr(tfilter_get_tca_kind(a), tfilter_get_tca_kind(b));
}

static int tfilter_get(Link *link, const TFilter *in, TFilter **ret) {
        TFilter *existing;

        assert(link);
        assert(in);

        existing = set_get(link->tfilters, in);
        if (!existing)
                return -ENOENT;

        if (ret)
                *ret = existing;
        return 0;
}

static int tfilter_get_request(Link *link, const TFilter *tfilter, Request **ret) {
        Request *req;

        assert(link);
        assert(link->manager);
        assert(tfilter);

        req = ordered_set_get(
                        link->manager->request_queue,
                        &(Request) {
                                .link = link,
                                .type = REQUEST_TYPE_TC_FILTER,
                                .userdata = (void*) tfilter,
                                .hash_func = (hash_func_t) tfilter_hash_func,
                                .compare_func = (compare_func_t) tfilter_compare_func,
                        });
        if (!req)
                return -ENOENT;

        if (ret)
                *ret = req;
        return 0;
}

static int tfilter_attach(Link *link, TFilter *tfilter) {
        int r;

        assert(link);
        assert(tfilter);
        assert(!tfilter->link);
        assert(!tfilter->network);

        r = set_ensure_put(&link->tfilters, &tfilter_hash_ops, tfilter);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        tfilter->link = link;
        tfilter_ref(tfilter);
        return 0;
}

static int tfilter_dup(const TFilter *src, TFilter **ret) {
        _cleanup_(tfilter_unrefp) TFilter *dst = NULL;

        assert(src);
        assert(ret);

        if (TFILTER_VTABLE(src))
                dst = memdup(src, TFILTER_VTABLE(src)->object_size);
        else
                dst = newdup(TFilter, src, 1);
        if (!dst)
                return -ENOMEM;

        /* clear the reference counter and all pointers */
        dst->n_ref = 1;
        dst->network = NULL;
        dst->section = NULL;
        dst->link = NULL;
        dst->tca_kind = NULL;

        if (src->tca_kind) {
                dst->tca_kind = strdup(src->tca_kind);
                if (!dst->tca_kind)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(dst);
        return 0;
}

static void log_tfilter_debug(TFilter *tfilter, Link *link, const char *str) {
        _cleanup_free_ char *state = NULL;

        assert(tfilter);
        assert(str);

        if (!DEBUG_LOGGING)
                return;

        (void) network_config_state_to_string_alloc(tfilter->state, &state);

        log_link_debug(link, "%s %s TFilter (%s): handle=%"PRIx32":%"PRIx32", parent=%"PRIx32":%"PRIx32", protocol=%"PRIu16", priority=%"PRIu16", kind=%s",
                       str, strna(network_config_source_to_string(tfilter->source)), strna(state),
                       TC_H_MAJ(tfilter->handle) >> 16, TC_H_MIN(tfilter->handle),
                       TC_H_MAJ(tfilter->parent) >> 16, TC_H_MIN(tfilter->parent),
                       tfilter->protocol, tfilter->priority,
                       strna(tfilter_get_tca_kind(tfilter)));
}

void link_tfilter_drop_marked(Link *link) {
        TFilter *tfilter;

        assert(link);

        SET_FOREACH(tfilter, link->tfilters) {
                Request *req;

                if (!tfilter_is_marked(tfilter))
                        continue;

                tfilter_unmark(tfilter);
                tfilter_enter_removed(tfilter);
                if (tfilter_get_request(link, tfilter, &req) >= 0)
                        tfilter_enter_removed(req->userdata);

                if (tfilter->state == 0) {
                        log_tfilter_debug(tfilter, link, "Forgetting");
                        tfilter_detach(tfilter);
                } else
                        log_tfilter_debug(tfilter, link, "Removed");
        }
}

static void tfilter_drop(TFilter *tfilter) {
        assert(tfilter);

        tfilter_mark(tfilter);
        link_tfilter_drop_marked(tfilter->link);
}

static int tfilter_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, TFilter *tfilter) {
        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_error_errno(link, m, r, "Could not set TFilter");
                link_enter_failed(link);
                return 1;
        }

        if (link->tc_messages == 0) {
                log_link_debug(link, "Traffic control configured");
                link->tc_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int tfilter_configure(TFilter *tfilter, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(tfilter);
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(req);

        log_tfilter_debug(tfilter, link, "Configuring");

        r = sd_rtnl_message_new_traffic_control(link->manager->rtnl, &m, RTM_NEWTFILTER,
                                                link->ifindex, tfilter->handle, tfilter->parent);
        if (r < 0)
                return r;

        r = sd_rtnl_message_traffic_control_set_info(m, tfilter->protocol, tfilter->priority);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, TCA_KIND, tfilter_get_tca_kind(tfilter));
        if (r < 0)
                return r;

        if (TFILTER_VTABLE(tfilter) && TFILTER_VTABLE(tfilter)->fill_message) {
                r = TFILTER_VTABLE(tfilter)->fill_message(link, tfilter, m);
                if (r < 0)
                        return r;
        }

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static bool tfilter_is_ready_to_configure(TFilter *tfilter, Link *link) {
        assert(tfilter);
        assert(link);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        if (tfilter->parent == TC_H_ROOT)
                return true;

        return link_find_qdisc(link, TC_H_MAJ(tfilter->parent), NULL, NULL) >= 0;
}

static int tfilter_process_request(Request *req, Link *link, TFilter *tfilter) {
        TFilter *existing;
        int r;

        assert(req);
        assert(link);
        assert(tfilter);

        if (!tfilter_is_ready_to_configure(tfilter, link))
                return 0;

        r = tfilter_configure(tfilter, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure TFilter: %m");

        tfilter_enter_configuring(tfilter);
        if (tfilter_get(link, tfilter, &existing) >= 0)
                tfilter_enter_configuring(existing);

        return 1;
}

int link_request_tfilter(Link *link, const TFilter *tfilter) {
        _cleanup_(tfilter_unrefp) TFilter *tmp = NULL;
        TFilter *existing = NULL;
        int r;

        assert(link);
        assert(tfilter);
        assert(tfilter->source != NETWORK_CONFIG_SOURCE_FOREIGN);

        if (tfilter_get_request(link, tfilter, NULL) >= 0)
                return 0; /* already requested, skipping. */

        r = tfilter_dup(tfilter, &tmp);
        if (r < 0)
                return r;

        if (tfilter_get(link, tfilter, &existing) >= 0)
                /* Copy state for logging below. */
                tmp->state = existing->state;

        log_tfilter_debug(tmp, link, "Requesting");
        r = link_queue_request_safe(link, REQUEST_TYPE_TC_FILTER,
                                    tmp,
                                    tfilter_unref,
                                    tfilter_hash_func,
                                    tfilter_compare_func,
                                    tfilter_process_request,
                                    &link->tc_messages,
                                    tfilter_handler,
                                    NULL);
        if (r <= 0)
                return r;

        tfilter_enter_requesting(tmp);
        if (existing)
                tfilter_enter_requesting(existing);

        TAKE_PTR(tmp);
        return 1;
}

int manager_rtnl_process_tfilter(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(tfilter_unrefp) TFilter *tmp = NULL;
        Request *req = NULL;
        TFilter *tfilter = NULL;
        Link *link;
        uint16_t type;
        int ifindex, r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "rtnl: failed to receive TFilter message, ignoring");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWTFILTER, RTM_DELTFILTER)) {
                log_warning("rtnl: received unexpected message type %u when processing TFilter, ignoring.", type);
                return 0;
        }

        r = sd_rtnl_message_traffic_control_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get ifindex from message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received TFilter message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        if (link_get_by_index(m, ifindex, &link) < 0) {
                if (!m->enumerating)
                        log_warning("rtnl: received TFilter for link '%d' we don't know about, ignoring.", ifindex);
                return 0;
        }

        r = tfilter_new(_TFILTER_KIND_INVALID, &tmp);
        if (r < 0)
                return log_oom();

        r = sd_rtnl_message_traffic_control_get_handle(message, &tmp->handle);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received TFilter message without handle, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_traffic_control_get_parent(message, &tmp->parent);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received TFilter message without parent, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_string_strdup(message, TCA_KIND, &tmp->tca_kind);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received TFilter message without kind, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_traffic_control_get_info(message, &tmp->protocol, &tmp->priority);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received TFilter message without info, ignoring: %m");
                return 0;
        }

        (void) tfilter_get(link, tmp, &tfilter);
        (void) tfilter_get_request(link, tmp, &req);

        if (type == RTM_DELTFILTER) {
                if (tfilter)
                        tfilter_drop(tfilter);
                else
                        log_tfilter_debug(tmp, link, "Kernel removed unknown");

                return 0;
        }

        bool is_new = false;
        if (!tfilter) {
                /* If we did not know the tfilter, then save it. */
                r = tfilter_attach(link, tmp);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to remember TFilter, ignoring: %m");
                        return 0;
                }

                tfilter = tmp;
                is_new = true;
        }

        /* Also update information that cannot be obtained through netlink notification. */
        if (req && req->waiting_reply) {
                TFilter *t = ASSERT_PTR(req->userdata);

                tfilter->source = t->source;
        }

        tfilter_enter_configured(tfilter);
        if (req)
                tfilter_enter_configured(req->userdata);

        log_tfilter_debug(tfilter, link, is_new ? "Remembering" : "Received remembered");
        return 1;
}

int link_enumerate_tfilter(Link *link, uint32_t parent) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        r = sd_rtnl_message_new_traffic_control(link->manager->rtnl, &req, RTM_GETTFILTER, link->ifindex, 0, parent);
        if (r < 0)
                return r;

        return manager_enumerate_internal(link->manager, link->manager->rtnl, req, manager_rtnl_process_tfilter);
}

static int tfilter_section_verify(TFilter *tfilter) {
        int r;

        assert(tfilter);

        if (section_is_invalid(tfilter->section))
                return -EINVAL;

        if (TFILTER_VTABLE(tfilter)->verify) {
                r = TFILTER_VTABLE(tfilter)->verify(tfilter);
                if (r < 0)
                        return r;
        }

        return 0;
}

void network_drop_invalid_tfilter(Network *network) {
        TFilter *tfilter;

        assert(network);

        HASHMAP_FOREACH(tfilter, network->tfilters_by_section)
                if (tfilter_section_verify(tfilter) < 0)
                        tfilter_detach(tfilter);
}

int config_parse_tfilter_parent(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(tfilter_unref_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tfilter_new_static(ltype, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        if (streq(rvalue, "root"))
                tfilter->parent = TC_H_ROOT;
        else if (streq(rvalue, "clsact"))
                tfilter->parent = TC_H_MAKE(TC_H_CLSACT, 0);
        else if (streq(rvalue, "ingress"))
                tfilter->parent = TC_H_MAKE(TC_H_INGRESS, 0);
        else {
                r = parse_handle(rvalue, &tfilter->parent);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse 'Parent=', ignoring assignment: %s",
                                   rvalue);
                        return 0;
                }
        }

        TAKE_PTR(tfilter);

        return 0;
}

int config_parse_tfilter_handle(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(tfilter_unref_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = ASSERT_PTR(data);
        uint32_t handle;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tfilter_new_static(ltype, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tfilter->handle = TC_H_UNSPEC;
                TAKE_PTR(tfilter);
                return 0;
        }

        r = safe_atou32_full(rvalue, 0, &handle);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse 'Handle=', ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        tfilter->handle = handle;
        TAKE_PTR(tfilter);

        return 0;
}

int config_parse_tfilter_protocol(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(tfilter_unref_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tfilter_new_static(ltype, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tfilter->protocol = 0;
                TAKE_PTR(tfilter);
                return 0;
        }

        if (streq(rvalue, "ip"))
                tfilter->protocol = ETH_P_IP;
        else if (streq(rvalue, "ipv6"))
                tfilter->protocol = ETH_P_IPV6;
        else if (streq(rvalue, "all"))
                tfilter->protocol = ETH_P_ALL;
        else {
                uint16_t proto;

                r = safe_atou16_full(rvalue, 0, &proto);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse 'Protocol=', ignoring assignment: %s",
                                   rvalue);
                        return 0;
                }

                tfilter->protocol = proto;
        }

        TAKE_PTR(tfilter);

        return 0;
}

int config_parse_tfilter_priority(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(tfilter_unref_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = ASSERT_PTR(data);
        uint16_t prio;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tfilter_new_static(ltype, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tfilter->priority = 0;
                TAKE_PTR(tfilter);
                return 0;
        }

        r = safe_atou16(rvalue, &prio);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse 'Priority=', ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        tfilter->priority = prio;
        TAKE_PTR(tfilter);

        return 0;
}

int config_parse_tfilter_classid(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(tfilter_unref_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tfilter_new_static(ltype, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tfilter->classid = TC_H_UNSPEC;
                TAKE_PTR(tfilter);
                return 0;
        }

        r = parse_handle(rvalue, &tfilter->classid);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse 'FlowId=', ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        TAKE_PTR(tfilter);

        return 0;
}
