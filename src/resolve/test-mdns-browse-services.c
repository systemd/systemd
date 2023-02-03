/* SPDX-License-Identifier: LGPL-2.1-or-later */


/* Browse for and resolve mDNS services.
 * Subscribes to updates from systemd-resolved over varlink for the specified service type.
 * Discovered services are resolved if --resolve flag supplied. */

#include <assert.h>
#include <build.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "af-list.h"
#include "main-func.h"
#include "random-util.h"
#include "resolved-def.h"
#include "static-destruct.h"
#include "strv.h"
#include "varlink.h"

#define VL_SERVICE_RESOLVE_RETRY 2

static uint64_t m_token;
static bool resolve_flag = false;
static int n_columns = 80;

static char *in_domain = NULL;
static char *in_name = NULL;
static char *in_type = NULL;
static char *in_ifname = NULL;

STATIC_DESTRUCTOR_REGISTER(in_domain, freep);
STATIC_DESTRUCTOR_REGISTER(in_name, freep);
STATIC_DESTRUCTOR_REGISTER(in_type, freep);
STATIC_DESTRUCTOR_REGISTER(in_ifname, freep);

static int json_dispatch_ifindex(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        int *ifi = userdata;
        int64_t t;

        assert(variant);
        assert(ifi);

        if (!json_variant_is_integer(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an integer.", strna(name));

        t = json_variant_integer(variant);
        if (t > INT_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is out of bounds for an interface index.", strna(name));

        *ifi = (int) t;
        return 0;
}

static int json_dispatch_family(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        int *family = userdata;
        int64_t t;

        assert(variant);
        assert(family);

        if (!json_variant_is_integer(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an integer.", strna(name));

        t = json_variant_integer(variant);
        if (t < 0 || t > INT_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid family.", strna(name));

        *family = (int) t;
        return 0;
}

typedef struct AddressParameters {
        int ifindex;
        int family;
        union in_addr_union address;
        size_t address_size;
} AddressParameters;

static int json_dispatch_address(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        AddressParameters *p = userdata;
        union in_addr_union buf = {};
        JsonVariant *i;
        size_t n, k = 0;

        assert(variant);
        assert(p);

        if (!json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        n = json_variant_elements(variant);
        if (!IN_SET(n, 4, 16))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is array of unexpected size.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(i, variant) {
                int64_t b;

                if (!json_variant_is_integer(i))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Element %zu of JSON field '%s' is not an integer.", k, strna(name));

                b = json_variant_integer(i);
                if (b < 0 || b > 0xff)
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Element %zu of JSON field '%s' is out of range 0…255.", k, strna(name));

                buf.bytes[k++] = (uint8_t) b;
        }

        p->address = buf;
        p->address_size = k;

        return 0;
}

static const JsonDispatch address_parameters_dispatch_table[] = {
        { "ifindex", JSON_VARIANT_INTEGER,  json_dispatch_ifindex, offsetof(AddressParameters, ifindex), 0              },
        { "family",  JSON_VARIANT_INTEGER,  json_dispatch_family,  offsetof(AddressParameters, family),  JSON_MANDATORY },
        { "address", JSON_VARIANT_ARRAY,    json_dispatch_address, 0,                                    JSON_MANDATORY },
        {}
};

static char *format_txt(JsonVariant *txt_array) {
        size_t c = 1;
        char *p, *s;
        JsonVariant *i;

        if (!json_variant_is_array(txt_array))
                return NULL;
        JSON_VARIANT_ARRAY_FOREACH(i, txt_array) {
                c += json_variant_elements(i) * 4 + 3;
        }

        p = s = new(char, c);
        if (!s)
                return NULL;

        JSON_VARIANT_ARRAY_FOREACH(i, txt_array) {
                JsonVariant *j;

                if (i != json_variant_by_index(txt_array, 0))
                        *(p++) = ' ';

                *(p++) = '"';

                JSON_VARIANT_ARRAY_FOREACH(j, i) {
                        int64_t b;

                        if (!json_variant_is_integer(j))
                                continue;

                        b = json_variant_integer(j);

                        if (b < ' ' || b == '"' || b >= 127) {
                                *(p++) = '\\';
                                *(p++) = '0' + (b / 100);
                                *(p++) = '0' + ((b / 10) % 10);
                                *(p++) = '0' + (b % 10);
                        } else
                                *(p++) = b;
                }
                *(p++) = '"';
        }

        *p = 0;
        return s;
}

static int resolve_service_query_reply(JsonVariant *parameters, const char *error_id) {
        int r;

        if (!parameters)
                return 0;

        if (error_id) {
                printf("   error_id = %s\n\n", error_id);
                fflush(stdout);
                return 0;
        }

        JsonVariant *srv_data = json_variant_by_key(parameters, "srv");
        if (srv_data) {
                printf("   hostname = [%s]\n", json_variant_string(json_variant_by_key(srv_data, "hostname"))? : "");
                printf("   port = [%lu]\n", json_variant_unsigned(json_variant_by_key(srv_data, "port")));
        }

        JsonVariant *addr_data = json_variant_by_key(parameters, "addr");
        _cleanup_free_ char *ret_str = NULL;
        if (addr_data) {
                JsonVariant *addressElement = json_variant_by_index(addr_data, 0);
                AddressParameters q = {};
                r = json_dispatch(addressElement, address_parameters_dispatch_table, NULL, 0, &q);
                if (r < 0)
                        printf("Json_dispatch fail\n");

                if (q.address_size != FAMILY_ADDRESS_SIZE(q.family)) {
                        r = -EINVAL;
                        printf("q.address_size != FAMILY_ADDRESS_SIZE\n");
                }

                if (q.family == AF_INET)
                        in_addr_to_string(AF_INET, &(const union in_addr_union) {.in = {q.address.in.s_addr}}, &ret_str);
                else if (q.family == AF_INET6)
                        in_addr_to_string(AF_INET6, &(const union in_addr_union) {.in6 = {q.address.in6.__in6_u}}, &ret_str);

                printf("   address = [%s]\n", ret_str? : "");
        }

        JsonVariant *txt_data = json_variant_by_key(parameters, "txt");
        if (txt_data) {
                _cleanup_free_ char *txt_str = NULL;
                txt_str = format_txt(txt_data);
                printf("   txt = [%s]\n\n", txt_str? : "");
        }

        fflush(stdout);
        return 0;
}

static int service_query_reply(
                        Varlink *link,
                        JsonVariant *parameters,
                        const char *error_id,
                        VarlinkReplyFlags flags,
                        void *userdata) {
        JsonVariant *recv_data = NULL, *ret_params = NULL;
        int r;

        if (error_id) {
                printf("error_id = %s\n", error_id);
                if (parameters) {
                        if (json_variant_is_string(json_variant_by_key(parameters, "parameter")))
                                printf("Invalid parameter \"%s\"\n",
                                                        json_variant_string(
                                                                json_variant_by_key(parameters, "parameter")));
                        else {
                                int err_code = json_variant_integer(json_variant_by_key(parameters, "errno"));
                                log_error_errno(err_code, "Reply error. %m");
                        }
                }

                return sd_event_exit(varlink_get_event(link), 0);
        }

        recv_data = json_variant_by_key(parameters, "browser_service_data");
        if (!json_variant_is_array(recv_data))
                return 0;

        if (m_token != json_variant_unsigned(json_variant_by_key(parameters, "token")))
                return 0;

        _cleanup_(varlink_unrefp) Varlink *resolve_link = NULL;

        r = varlink_connect_address(&resolve_link, "/run/systemd/resolve/io.systemd.Resolve");
        if (r < 0)
                return 0;

        r = varlink_set_description(resolve_link, "Resolve client");
        if (r < 0)
                return 0;

        varlink_set_relative_timeout(resolve_link, 120 * USEC_PER_SEC);

        JsonVariant *in;
        JSON_VARIANT_ARRAY_FOREACH(in, recv_data) {
                _cleanup_(json_variant_unrefp) JsonVariant *in_params = NULL;
                int retry = 0;
                const char *ret_err_str = NULL;
                const char *name, *type, *domain;
                char ifname_buf[IF_NAMESIZE];
                name = json_variant_string(json_variant_by_key(in, "name"));
                type = json_variant_string(json_variant_by_key(in, "type"));
                domain = json_variant_string(json_variant_by_key(in, "domain"));
                bool add_flag = json_variant_boolean(json_variant_by_key(in, "add_flag"));
                int family = json_variant_integer(json_variant_by_key(in, "family"));
                int ifindex = json_variant_integer(json_variant_by_key(in, "interface"));

                printf("%c %6s %4s %-*s %-20s %s\n",
                                (add_flag) ? '+' : '-',
                                if_indextoname(json_variant_integer(json_variant_by_key(in, "interface")), ifname_buf),
                                af_to_name(family),
                                n_columns-35, name?: "", type?: "", domain?: "");
                fflush(stdout);

                if (resolve_flag && add_flag) {
                        r = json_build(&in_params,
                                JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR("domain", JSON_BUILD_STRING(domain)),
                                                JSON_BUILD_PAIR("name", JSON_BUILD_STRING(name)),
                                                JSON_BUILD_PAIR("type", JSON_BUILD_STRING(type)),
                                                JSON_BUILD_PAIR("ifindex", JSON_BUILD_INTEGER(ifindex)),
                                                JSON_BUILD_PAIR("family", JSON_BUILD_INTEGER(family)),
                                                JSON_BUILD_PAIR("flags", JSON_BUILD_UNSIGNED(SD_RESOLVED_MDNS))));

                        if (r < 0) {
                                printf("   Resolve failed for service.\n\n");
                                continue;
                        }

                        /* Higher success rate of resolving with retry */
                        while (retry++ < VL_SERVICE_RESOLVE_RETRY) {
                                r = varlink_call(resolve_link, "io.systemd.Resolve.ResolveService", in_params, &ret_params, &ret_err_str, NULL);
                                if (!ret_err_str)
                                        break;
                        }

                        if (r < 0) {
                                printf("   Resolve failed for service.\n\n");
                                continue;
                        }

                        resolve_service_query_reply(ret_params, ret_err_str);
                        fflush(stdout);
                }
        }

        return 0;
}
static int stop_signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Varlink *start_link = NULL;
        _cleanup_(varlink_unrefp) Varlink *stop_link = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *call_params = NULL;
        int r;

        if (si->ssi_signo != SIGINT)
                return 0;

        if (userdata == NULL)
                return 0;

        start_link = (Varlink*)userdata;

        r = json_build(&call_params,
                        JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR("token", JSON_BUILD_UNSIGNED(m_token))));
        if (r < 0)
                goto finish;

        r = varlink_connect_address(&stop_link, "/run/systemd/resolve/io.systemd.Resolve");
        if (r < 0)
                goto finish;

        r = varlink_call(stop_link, "io.systemd.Resolve.StopBrowse", call_params, NULL, NULL, NULL);
        if (r < 0)
                goto finish;

        r = sd_event_exit(varlink_get_event(start_link), 0);
finish:
        if (r < 0)
                printf("Stop The Browse failed %d \n",r);
        return 0;
}

static int help(void) {
        printf("%s [OPTIONS...]\n"
               "\n"
               "Browse for and resolve mDNS services.\n"
               "\nOptions:\n"
               "  -h --help                    Show this help\n"
               "  -v --version                 Show package version\n"
               "  -n --name=NAME               Service instance name\n"
               "  -t --type=TYPE               Service type\n"
               "  -d --domain=DOMAIN           Service domain. Mandatory\n"
               "  -i --interface=INTERFACE     Look on interface\n"
               "  -r --resolve                 Resolve discovered services\n",
               program_invocation_short_name);

        return 0;
}

static int native_parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h' },
                { "version",   no_argument,       NULL, 'v' },
                { "name",      required_argument, NULL, 'n' },
                { "type",      required_argument, NULL, 't' },
                { "domain",    required_argument, NULL, 'd' },
                { "interface", required_argument, NULL, 'i' },
                { "resolve",   no_argument,       NULL, 'r' },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hvrn:t:d:i:", options, NULL)) >= 0) {
                switch(c) {

                case 'h':
                        return help();

                case 'v':
                        return version();

                case 'n':
                        in_name = strdup(optarg);
                        break;

                case 't':
                        in_type = strdup(optarg);
                        break;

                case 'd':
                        in_domain = strdup(optarg);
                        break;

                case 'i':
                        in_ifname = strdup(optarg);
                        break;

                case 'r':
                        resolve_flag = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
                fflush(stdout);
        }

        return 1;
}

static int run(int argc, char **argv) {
        _cleanup_(varlink_unrefp) Varlink *start_link = NULL;
        _cleanup_(json_variant_unrefp)JsonVariant *in_params = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        sigset_t ss;
        char *ec;
        int r;

        if ((ec = getenv("COLUMNS")))
                n_columns = atoi(ec);

        if (native_parse_argv(argc, argv) <= 0)
                return 0;

        r = varlink_connect_address(&start_link, "/run/systemd/resolve/io.systemd.Resolve");
        if (r < 0)
                goto finish;

        r = varlink_set_description(start_link, "client");
        if (r < 0)
                goto finish;

        varlink_set_userdata(start_link, NULL);

        r = varlink_set_relative_timeout(start_link, USEC_INFINITY);
        if (r < 0)
                goto finish;

        r = sd_event_default(&event);
        if (r < 0)
                goto finish;

        r = sigemptyset(&ss);
        if (r < 0)
                goto finish;

        r = sigaddset(&ss, SIGINT);
        if (r < 0)
                goto finish;

        r = sigprocmask(SIG_BLOCK, &ss, NULL);
        if (r < 0)
                goto finish;

        r = varlink_attach_event(start_link, event, 0);
        if (r < 0)
                goto finish;

        r = sd_event_add_signal(event, NULL, SIGINT, stop_signal_handler, start_link);
        if (r < 0)
                goto finish;

        r = varlink_bind_reply(start_link, service_query_reply);
        if (r < 0)
                goto finish;

        random_bytes(&m_token, sizeof(uint64_t));

        r = json_build(&in_params,
                        JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR("domain_name", JSON_BUILD_STRING(in_domain? : "")),
                                        JSON_BUILD_PAIR("name", JSON_BUILD_STRING(in_name? : "")),
                                        JSON_BUILD_PAIR("type", JSON_BUILD_STRING(in_type? : "")),
                                        JSON_BUILD_PAIR("ifname", JSON_BUILD_STRING(in_ifname? : "")),
                                        JSON_BUILD_PAIR("token", JSON_BUILD_UNSIGNED(m_token))));
        if (r < 0)
                goto finish;

        r = varlink_observe(start_link, "io.systemd.Resolve.StartBrowse", in_params);
        if (r < 0)
                goto finish;

        r = sd_event_loop(varlink_get_event(start_link));

finish:
        if (r < 0)
                log_error_errno(r, "Init failed. %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
