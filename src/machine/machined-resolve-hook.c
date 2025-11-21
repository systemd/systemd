/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "dns-answer.h"
#include "dns-domain.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "hashmap.h"
#include "local-addresses.h"
#include "log.h"
#include "machine.h"
#include "machined.h"
#include "machined-resolve-hook.h"
#include "resolve-hook-util.h"
#include "set.h"
#include "varlink-util.h"

static int manager_make_machine_array(Manager *m, sd_json_variant **ret) {
        int r;

        assert(m);
        assert(ret);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        Machine *machine;
        HASHMAP_FOREACH(machine, m->machines) {
                if (machine->class == MACHINE_HOST)
                        continue;
                if (!machine->started)
                        continue;

                r = sd_json_variant_append_arrayb(&array, SD_JSON_BUILD_STRING(machine->name));
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
        r = manager_make_machine_array(m, &array);
        if (r < 0)
                return log_error_errno(r, "Failed to generate JSON array with machine names: %m");

        r = varlink_many_notifybo(m->query_filter_subscriptions, SD_JSON_BUILD_PAIR_VARIANT("filterDomains", array));
        if (r < 0)
                return log_error_errno(r, "Failed to notify filter subscribers: %m");

        return 0;
}

int vl_method_query_filter(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        r = manager_make_machine_array(m, &array);
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

int vl_method_resolve_record(
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

        _cleanup_free_ struct local_address *addresses = NULL;
        bool found = false, nxdomain = false;
        int n_addresses = -1;

        DnsResourceKey *key;
        DNS_QUESTION_FOREACH(key, p.question) {
                Machine *machine = hashmap_get(m->machines, dns_resource_key_name(key));
                if (machine) {
                        /* We found a perfect match, yay! */
                        found = true;

                        if (!dns_resource_key_is_address(key))
                                continue;

                        if (n_addresses < 0) {
                                n_addresses = machine_get_addresses(machine, &addresses);
                                if (n_addresses < 0)
                                        return n_addresses;
                        }

                        int family = dns_type_to_af(key->type);
                        FOREACH_ARRAY(address, addresses, n_addresses) {
                                if (address->family != family)
                                        continue;

                                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
                                r = dns_resource_record_new_address(&rr, address->family, &address->address, machine->name);
                                if (r < 0)
                                        return r;

                                r = dns_answer_add_extend(
                                                &answer,
                                                rr,
                                                machine->n_netif == 1 ? machine->netif[0] : -1,
                                                DNS_ANSWER_AUTHENTICATED,
                                                /* rrsig= */ NULL);
                                if (r < 0)
                                        return r;
                        }
                }

                /* So this is not a direct match? Then check if we find a prefix match */
                const char *q = dns_resource_key_name(key);
                while (!nxdomain) {
                        r = dns_name_parent(&q);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        nxdomain = !!hashmap_get(m->machines, q);
                }
        }

        if (!found) {
                /* If we found a prefix match we own the subtree, and thus return NXDOMAIN because we know
                 * that we only expose the machine A/AAAA records on the primary name, but nothing below. */
                if (nxdomain)
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
