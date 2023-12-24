/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */

#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "in-addr-util.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "parse-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "tc-util.h"
#include "tclass.h"

const TClassVTable * const tclass_vtable[_TCLASS_KIND_MAX] = {
        [TCLASS_KIND_DRR] = &drr_tclass_vtable,
        [TCLASS_KIND_HTB] = &htb_tclass_vtable,
        [TCLASS_KIND_QFQ] = &qfq_tclass_vtable,
};

static int tclass_new(TClassKind kind, TClass **ret) {
        _cleanup_(tclass_freep) TClass *tclass = NULL;
        int r;

        if (kind == _TCLASS_KIND_INVALID) {
                tclass = new(TClass, 1);
                if (!tclass)
                        return -ENOMEM;

                *tclass = (TClass) {
                        .parent = TC_H_ROOT,
                        .kind = kind,
                };
        } else {
                assert(kind >= 0 && kind < _TCLASS_KIND_MAX);
                tclass = malloc0(tclass_vtable[kind]->object_size);
                if (!tclass)
                        return -ENOMEM;

                tclass->parent = TC_H_ROOT;
                tclass->kind = kind;

                if (TCLASS_VTABLE(tclass)->init) {
                        r = TCLASS_VTABLE(tclass)->init(tclass);
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(tclass);

        return 0;
}

int tclass_new_static(TClassKind kind, Network *network, const char *filename, unsigned section_line, TClass **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(tclass_freep) TClass *tclass = NULL;
        TClass *existing;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        existing = hashmap_get(network->tclasses_by_section, n);
        if (existing) {
                if (existing->kind != kind)
                        return -EINVAL;

                *ret = existing;
                return 0;
        }

        r = tclass_new(kind, &tclass);
        if (r < 0)
                return r;

        tclass->network = network;
        tclass->section = TAKE_PTR(n);
        tclass->source = NETWORK_CONFIG_SOURCE_STATIC;

        r = hashmap_ensure_put(&network->tclasses_by_section, &config_section_hash_ops, tclass->section, tclass);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(tclass);
        return 0;
}

TClass* tclass_free(TClass *tclass) {
        if (!tclass)
                return NULL;

        if (tclass->network && tclass->section)
                hashmap_remove(tclass->network->tclasses_by_section, tclass->section);

        config_section_free(tclass->section);

        if (tclass->link)
                set_remove(tclass->link->tclasses, tclass);

        free(tclass->tca_kind);
        return mfree(tclass);
}

static const char *tclass_get_tca_kind(const TClass *tclass) {
        assert(tclass);

        return (TCLASS_VTABLE(tclass) && TCLASS_VTABLE(tclass)->tca_kind) ?
                TCLASS_VTABLE(tclass)->tca_kind : tclass->tca_kind;
}

static void tclass_hash_func(const TClass *tclass, struct siphash *state) {
        assert(tclass);
        assert(state);

        siphash24_compress_typesafe(tclass->classid, state);
        siphash24_compress_typesafe(tclass->parent, state);
        siphash24_compress_string(tclass_get_tca_kind(tclass), state);
}

static int tclass_compare_func(const TClass *a, const TClass *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->classid, b->classid);
        if (r != 0)
                return r;

        r = CMP(a->parent, b->parent);
        if (r != 0)
                return r;

        return strcmp_ptr(tclass_get_tca_kind(a), tclass_get_tca_kind(b));
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        tclass_hash_ops,
        TClass,
        tclass_hash_func,
        tclass_compare_func,
        tclass_free);

static int tclass_get(Link *link, const TClass *in, TClass **ret) {
        TClass *existing;

        assert(link);
        assert(in);

        existing = set_get(link->tclasses, in);
        if (!existing)
                return -ENOENT;

        if (ret)
                *ret = existing;
        return 0;
}

static int tclass_add(Link *link, TClass *tclass) {
        int r;

        assert(link);
        assert(tclass);

        r = set_ensure_put(&link->tclasses, &tclass_hash_ops, tclass);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        tclass->link = link;
        return 0;
}

static int tclass_dup(const TClass *src, TClass **ret) {
        _cleanup_(tclass_freep) TClass *dst = NULL;

        assert(src);
        assert(ret);

        if (TCLASS_VTABLE(src))
                dst = memdup(src, TCLASS_VTABLE(src)->object_size);
        else
                dst = newdup(TClass, src, 1);
        if (!dst)
                return -ENOMEM;

        /* clear all pointers */
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

int link_find_tclass(Link *link, uint32_t classid, TClass **ret) {
        TClass *tclass;

        assert(link);

        SET_FOREACH(tclass, link->tclasses) {
                if (tclass->classid != classid)
                        continue;

                if (!tclass_exists(tclass))
                        continue;

                if (ret)
                        *ret = tclass;
                return 0;
        }

        return -ENOENT;
}

static void log_tclass_debug(TClass *tclass, Link *link, const char *str) {
        _cleanup_free_ char *state = NULL;

        assert(tclass);
        assert(str);

        if (!DEBUG_LOGGING)
                return;

        (void) network_config_state_to_string_alloc(tclass->state, &state);

        log_link_debug(link, "%s %s TClass (%s): classid=%"PRIx32":%"PRIx32", parent=%"PRIx32":%"PRIx32", kind=%s",
                       str, strna(network_config_source_to_string(tclass->source)), strna(state),
                       TC_H_MAJ(tclass->classid) >> 16, TC_H_MIN(tclass->classid),
                       TC_H_MAJ(tclass->parent) >> 16, TC_H_MIN(tclass->parent),
                       strna(tclass_get_tca_kind(tclass)));
}

TClass* tclass_drop(TClass *tclass) {
        QDisc *qdisc;
        Link *link;

        assert(tclass);

        link = ASSERT_PTR(tclass->link);

        /* Also drop all child qdiscs assigned to the class. */
        SET_FOREACH(qdisc, link->qdiscs) {
                if (qdisc->parent != tclass->classid)
                        continue;

                qdisc_drop(qdisc);
        }

        tclass_enter_removed(tclass);

        if (tclass->state == 0) {
                log_tclass_debug(tclass, link, "Forgetting");
                tclass = tclass_free(tclass);
        } else
                log_tclass_debug(tclass, link, "Removed");

        return tclass;
}

static int tclass_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, TClass *tclass) {
        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_error_errno(link, m, r, "Could not set TClass");
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

static int tclass_configure(TClass *tclass, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(tclass);
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(req);

        log_tclass_debug(tclass, link, "Configuring");

        r = sd_rtnl_message_new_traffic_control(link->manager->rtnl, &m, RTM_NEWTCLASS,
                                                link->ifindex, tclass->classid, tclass->parent);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, TCA_KIND, TCLASS_VTABLE(tclass)->tca_kind);
        if (r < 0)
                return r;

        if (TCLASS_VTABLE(tclass)->fill_message) {
                r = TCLASS_VTABLE(tclass)->fill_message(link, tclass, m);
                if (r < 0)
                        return r;
        }

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static bool tclass_is_ready_to_configure(TClass *tclass, Link *link) {
        assert(tclass);
        assert(link);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        return link_find_qdisc(link, TC_H_MAJ(tclass->classid), tclass_get_tca_kind(tclass), NULL) >= 0;
}

static int tclass_process_request(Request *req, Link *link, TClass *tclass) {
        int r;

        assert(req);
        assert(link);
        assert(tclass);

        if (!tclass_is_ready_to_configure(tclass, link))
                return 0;

        r = tclass_configure(tclass, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure TClass: %m");

        tclass_enter_configuring(tclass);
        return 1;
}

int link_request_tclass(Link *link, TClass *tclass) {
        TClass *existing;
        int r;

        assert(link);
        assert(tclass);

        if (tclass_get(link, tclass, &existing) < 0) {
                _cleanup_(tclass_freep) TClass *tmp = NULL;

                r = tclass_dup(tclass, &tmp);
                if (r < 0)
                        return log_oom();

                r = tclass_add(link, tmp);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to store TClass: %m");

                existing = TAKE_PTR(tmp);
        } else
                existing->source = tclass->source;

        log_tclass_debug(existing, link, "Requesting");
        r = link_queue_request_safe(link, REQUEST_TYPE_TC_CLASS,
                                    existing, NULL,
                                    tclass_hash_func,
                                    tclass_compare_func,
                                    tclass_process_request,
                                    &link->tc_messages,
                                    tclass_handler,
                                    NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request TClass: %m");
        if (r == 0)
                return 0;

        tclass_enter_requesting(existing);
        return 1;
}

int manager_rtnl_process_tclass(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(tclass_freep) TClass *tmp = NULL;
        TClass *tclass = NULL;
        Link *link;
        uint16_t type;
        int ifindex, r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "rtnl: failed to receive TClass message, ignoring");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWTCLASS, RTM_DELTCLASS)) {
                log_warning("rtnl: received unexpected message type %u when processing TClass, ignoring.", type);
                return 0;
        }

        r = sd_rtnl_message_traffic_control_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get ifindex from message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received TClass message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        if (link_get_by_index(m, ifindex, &link) < 0) {
                if (!m->enumerating)
                        log_warning("rtnl: received TClass for link '%d' we don't know about, ignoring.", ifindex);
                return 0;
        }

        r = tclass_new(_TCLASS_KIND_INVALID, &tmp);
        if (r < 0)
                return log_oom();

        r = sd_rtnl_message_traffic_control_get_handle(message, &tmp->classid);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received TClass message without handle, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_traffic_control_get_parent(message, &tmp->parent);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received TClass message without parent, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_string_strdup(message, TCA_KIND, &tmp->tca_kind);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received TClass message without kind, ignoring: %m");
                return 0;
        }

        (void) tclass_get(link, tmp, &tclass);

        switch (type) {
        case RTM_NEWTCLASS:
                if (tclass) {
                        tclass_enter_configured(tclass);
                        log_tclass_debug(tclass, link, "Received remembered");
                } else {
                        tclass_enter_configured(tmp);
                        log_tclass_debug(tmp, link, "Received new");

                        r = tclass_add(link, tmp);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to remember TClass, ignoring: %m");
                                return 0;
                        }

                        tclass = TAKE_PTR(tmp);
                }

                break;

        case RTM_DELTCLASS:
                if (tclass)
                        (void) tclass_drop(tclass);
                else
                        log_tclass_debug(tmp, link, "Kernel removed unknown");

                break;

        default:
                assert_not_reached();
        }

        return 1;
}

int link_enumerate_tclass(Link *link, uint32_t parent) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        r = sd_rtnl_message_new_traffic_control(link->manager->rtnl, &req, RTM_GETTCLASS, link->ifindex, 0, parent);
        if (r < 0)
                return r;

        return manager_enumerate_internal(link->manager, link->manager->rtnl, req, manager_rtnl_process_tclass);
}

static int tclass_section_verify(TClass *tclass) {
        int r;

        assert(tclass);

        if (section_is_invalid(tclass->section))
                return -EINVAL;

        if (TCLASS_VTABLE(tclass)->verify) {
                r = TCLASS_VTABLE(tclass)->verify(tclass);
                if (r < 0)
                        return r;
        }

        return 0;
}

void network_drop_invalid_tclass(Network *network) {
        TClass *tclass;

        assert(network);

        HASHMAP_FOREACH(tclass, network->tclasses_by_section)
                if (tclass_section_verify(tclass) < 0)
                        tclass_free(tclass);
}

int config_parse_tclass_parent(
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

        _cleanup_(tclass_free_or_set_invalidp) TClass *tclass = NULL;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tclass_new_static(ltype, network, filename, section_line, &tclass);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control class, ignoring assignment: %m");
                return 0;
        }

        if (streq(rvalue, "root"))
                tclass->parent = TC_H_ROOT;
        else {
                r = parse_handle(rvalue, &tclass->parent);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse 'Parent=', ignoring assignment: %s",
                                   rvalue);
                        return 0;
                }
        }

        TAKE_PTR(tclass);

        return 0;
}

int config_parse_tclass_classid(
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

        _cleanup_(tclass_free_or_set_invalidp) TClass *tclass = NULL;
        Network *network = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = tclass_new_static(ltype, network, filename, section_line, &tclass);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control class, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tclass->classid = TC_H_UNSPEC;
                TAKE_PTR(tclass);
                return 0;
        }

        r = parse_handle(rvalue, &tclass->classid);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse 'ClassId=', ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        TAKE_PTR(tclass);

        return 0;
}
