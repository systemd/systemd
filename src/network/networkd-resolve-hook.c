/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-dhcp-server.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "argv-util.h"
#include "dns-answer.h"
#include "dns-domain.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "errno-util.h"
#include "fd-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-resolve-hook.h"
#include "resolve-hook-util.h"
#include "set.h"
#include "varlink-io.systemd.Resolve.Hook.h"
#include "varlink-util.h"

static int manager_make_domain_array(Manager *m, sd_json_variant **ret) {
        int r;

        assert(m);
        assert(ret);

        _cleanup_(set_freep) Set *domains = NULL;
        Link *link;
        HASHMAP_FOREACH(link, m->links_by_index) {
                if (!link_has_local_lease_domain(link))
                        continue;

                r = set_put_strdup_full(&domains, &dns_name_hash_ops_free, link->network->dhcp_server_local_lease_domain);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        char *s;
        SET_FOREACH(s, domains) {
                r = sd_json_variant_append_arrayb(&array, SD_JSON_BUILD_STRING(s));
                if (r < 0)
                        return r;
        }

        if (!array)
                return sd_json_variant_new_array(ret, /* array= */ NULL, /* n= */ 0);

        *ret = TAKE_PTR(array);
        return 0;
}

int manager_notify_hook_filters(Manager *m) {
        int r;

        assert(m);

        /* Called whenever a machine is added or dropped from the list */

        if (set_isempty(m->query_filter_subscriptions))
                return 0;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        r = manager_make_domain_array(m, &array);
        if (r < 0)
                return log_error_errno(r, "Failed to generate JSON array with machine names: %m");

        r = varlink_many_notifybo(m->query_filter_subscriptions, SD_JSON_BUILD_PAIR_VARIANT("filterDomains", array));
        if (r < 0)
                return log_error_errno(r, "Failed to notify filter subscribers: %m");

        return 0;
}

static int vl_method_query_filter(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        r = manager_make_domain_array(m, &array);
        if (r < 0)
                return r;

        if (flags & SD_VARLINK_METHOD_MORE) {
                /* If 'more' is set, this is a subscription request, keep track of the link */

                r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_VARIANT("filterDomains", array));
                if (r < 0)
                        return log_error_errno(r, "Failed to notify filter subscribers: %m");

                r = set_ensure_put(&m->query_filter_subscriptions, &varlink_hash_ops, link);
                if (r < 0)
                        return r;

                sd_varlink_ref(link);
        } else {
                r = sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("filterDomains", array));
                if (r < 0)
                        return log_error_errno(r, "Failed to notify filter subscribers: %m");
        }

        return 0;
}

static int vl_method_resolve_record(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        _cleanup_(resolve_record_parameters_done) ResolveRecordParameters p = {};
        r = sd_varlink_dispatch(link, parameters, resolve_record_parameters_dispatch_table, &p);
        if (r != 0)
                return r;

        if (dns_question_isempty(p.question))
                return sd_varlink_error_invalid_parameter_name(link, "question");

        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        bool found_address = false, found_domain = false;
        DnsResourceKey *key;
        DNS_QUESTION_FOREACH(key, p.question) {
                const char *name = dns_resource_key_name(key);

                Link *l;
                HASHMAP_FOREACH(l, m->links_by_index) {

                        if (!link_has_local_lease_domain(l))
                                continue;

                        /* Try to strip the local lease domain suffix from name, so that we have the short hostname left. */
                        _cleanup_free_ char *prefix = NULL;
                        r = dns_name_change_suffix(name, l->network->dhcp_server_local_lease_domain, /* new_suffix= */ NULL, &prefix);
                        if (r <= 0) /* no match? */
                                continue;

                        found_domain = true;

                        struct in_addr address;
                        r = sd_dhcp_server_get_lease_address_by_name(l->dhcp_server, prefix, &address);
                        if (r <= 0)
                                continue;

                        /* The domain exists, so we can give a positive reply. But only for A lookups we have addresses to return. */
                        if (key->type != DNS_TYPE_A)
                                continue;

                        found_address = true;

                        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
                        r = dns_resource_record_new_address(&rr, AF_INET, (union in_addr_union*) &address, name);
                        if (r < 0)
                                return r;

                        r = dns_answer_add_extend(
                                        &answer,
                                        rr,
                                        l->ifindex,
                                        DNS_ANSWER_AUTHENTICATED,
                                        /* rrsig= */ NULL);
                        if (r < 0)
                                return r;
                }
        }

        if (!found_address) {
                /* If this was a lookup in one of our domains, return NXDOMAIN, we are authoritative on that */
                if (found_domain)
                        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_INTEGER("rcode", DNS_RCODE_NXDOMAIN));

                /* Otherwise we return an empty response, which means: continue with the usual lookup */
                return sd_varlink_reply(link, /* parameters= */ NULL);
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ja = NULL;
        r = dns_answer_to_json(answer, &ja);
        if (r < 0)
                return r;

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_INTEGER("rcode", DNS_RCODE_SUCCESS),
                        SD_JSON_BUILD_PAIR_VARIANT("answer", ja));
}

static void on_resolve_hook_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        if (set_remove(m->query_filter_subscriptions, link))
                sd_varlink_unref(link);
}

int manager_varlink_init_resolve_hook(Manager *m, int fd) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        _unused_ _cleanup_close_ int fd_close = fd; /* take possession */
        int r;

        assert(m);

        if (m->varlink_resolve_hook_server)
                return 0;

        if (fd < 0 && invoked_by_systemd()) {
                log_debug("systemd-networkd-resolve-hook.socket seems to be disabled, not installing varlink server.");
                return 0;
        }

        r = varlink_server_new(&s, SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server: %m");

        (void) sd_varlink_server_set_description(s, "varlink-resolve-hook");

        r = sd_varlink_server_add_interface(s, &vl_interface_io_systemd_Resolve_Hook);
        if (r < 0)
                return log_error_errno(r, "Failed to add Resolve.Hook interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        s,
                        "io.systemd.Resolve.Hook.QueryFilter",   vl_method_query_filter,
                        "io.systemd.Resolve.Hook.ResolveRecord", vl_method_resolve_record);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        r = sd_varlink_server_bind_disconnect(s, on_resolve_hook_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to bind on resolve hook disconnection events: %m");

        if (fd < 0) {
                r = sd_varlink_server_listen_address(s, "/run/systemd/resolve.hook/io.systemd.Network",
                                                     0666 | SD_VARLINK_SERVER_MODE_MKDIR_0755);
                if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                        log_warning_errno(r, "Failed to bind to systemd-resolved hook varlink socket, ignoring: %m");
                        return 0;
                }
        } else
                r = sd_varlink_server_listen_fd(s, fd);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to systemd-resolved hook varlink socket: %m");

        TAKE_FD(fd_close);

        r = sd_varlink_server_attach_event(s, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        m->varlink_resolve_hook_server = TAKE_PTR(s);
        return 0;
}
