/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "extract-word.h"
#include "string-table.h"
#include "timesyncd-server.h"

static const char * const server_type_table[_SERVER_TYPE_MAX] = {
        [SERVER_SYSTEM]   = "system",
        [SERVER_FALLBACK] = "fallback",
        [SERVER_LINK]     = "link",
        [SERVER_RUNTIME]  = "runtime",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(server_type, ServerType);

int server_address_new(
                ServerName *n,
                ServerAddress **ret,
                const union sockaddr_union *sockaddr,
                socklen_t socklen) {

        ServerAddress *a, *tail;

        assert(n);
        assert(sockaddr);
        assert(socklen >= offsetof(struct sockaddr, sa_data));
        assert(socklen <= sizeof(union sockaddr_union));

        a = new(ServerAddress, 1);
        if (!a)
                return -ENOMEM;

        *a = (ServerAddress) {
                .name = n,
                .socklen = socklen,
        };

        memcpy(&a->sockaddr, sockaddr, socklen);

        tail = LIST_FIND_TAIL(addresses, n->addresses);
        LIST_INSERT_AFTER(addresses, n->addresses, tail, a);

        if (ret)
                *ret = a;

        return 0;
}

ServerAddress* server_address_free(ServerAddress *a) {
        if (!a)
                return NULL;

        if (a->name) {
                LIST_REMOVE(addresses, a->name->addresses, a);

                if (a->name->manager && a->name->manager->current_server_address == a)
                        manager_set_server_address(a->name->manager, NULL);
        }

        return mfree(a);
}

static int enable_ntp_server_defer_event(Manager *m, ServerType type) {
        int r;

        assert(m);
        assert((type >= 0) && (type < _SERVER_TYPE_MAX));

        m->ntp_server_change_mask |= 1U << type;

        r = bus_manager_emit_ntp_server_changed(m);
        if (r < 0)
                return r;

        return 1;
}

int server_name_new(
                Manager *m,
                ServerName **ret,
                ServerType type,
                const char *string) {
        int r;
        ServerName *n;

        assert(m);
        assert(string);

        n = new(ServerName, 1);
        if (!n)
                return -ENOMEM;

        *n = (ServerName) {
                .manager = m,
                .type = type,
                .string = strdup(string),
        };

        if (!n->string) {
                free(n);
                return -ENOMEM;
        }

        (void) server_name_parse_port(n); // side effect processes port detail from string if present

        switch (type) {
        case SERVER_SYSTEM:
                LIST_APPEND(names, m->system_servers, n);
                break;
        case SERVER_LINK:
                LIST_APPEND(names, m->link_servers, n);
                break;
        case SERVER_FALLBACK:
                LIST_APPEND(names, m->fallback_servers, n);
                break;
        case SERVER_RUNTIME:
                LIST_APPEND(names, m->runtime_servers, n);
                break;
        default:
                assert_not_reached();
        }

        r = enable_ntp_server_defer_event(m, type);
        if (r < 0)
                log_debug_errno(r, "Failed to enable ntp server defer event, ignoring: %m");

        if (type != SERVER_FALLBACK &&
            m->current_server_name &&
            m->current_server_name->type == SERVER_FALLBACK)
                manager_set_server_name(m, NULL);

        log_debug("Added new %s server %s.", server_type_to_string(type), n->string);

        if (ret)
                *ret = n;

        return 0;
}

ServerName *server_name_free(ServerName *n) {
        int r;

        if (!n)
                return NULL;

        server_name_flush_addresses(n);

        if (n->manager) {
                if (n->type == SERVER_SYSTEM)
                        LIST_REMOVE(names, n->manager->system_servers, n);
                else if (n->type == SERVER_LINK)
                        LIST_REMOVE(names, n->manager->link_servers, n);
                else if (n->type == SERVER_FALLBACK)
                        LIST_REMOVE(names, n->manager->fallback_servers, n);
                else if (n->type == SERVER_RUNTIME)
                        LIST_REMOVE(names, n->manager->runtime_servers, n);
                else
                        assert_not_reached();

                r = enable_ntp_server_defer_event(n->manager, n->type);
                if (r < 0)
                        log_debug_errno(r, "Failed to enable ntp server defer event, ignoring: %m");

                if (n->manager->current_server_name == n)
                        manager_set_server_name(n->manager, NULL);
        }

        log_debug("Removed server %s.", n->string);

        free(n->string);
        return mfree(n);
}

void server_name_flush_addresses(ServerName *n) {
        assert(n);

        while (n->addresses)
                server_address_free(n->addresses);
}

int server_name_parse_port(ServerName *n) {
        const char *sqr = "]", *col = ":";
        char *ret_sqr, *ret_col, *last_col;

        ret_sqr = strrchr(n->string, *sqr);
        ret_col = strchr(n->string, *col);
        last_col = strrchr(n->string, *col);

        if (ret_sqr == NULL && ret_col == NULL) { // server.domain or I.P.v.4
                return 0;
        } else if (ret_sqr == NULL && strlen(ret_col) == strlen(last_col)) { // has no ']' and exactly one ":"
                const char *word = strdupa_safe(n->string);
                (void) extract_first_word(&word, &n->string, col, 0);
                (void) extract_first_word(&word, &n->overridden_port, col, 0);
                log_debug("Matched single port: %s / %s", n->string, n->overridden_port);
                return 1;
        } else if (ret_sqr == NULL && ret_col != NULL && last_col != NULL && strlen(ret_col) != strlen(last_col)) {
                // naked IP::v:6, no ']' and more than one ':'
                return 0;
        } else if (ret_sqr != NULL && strlen(ret_sqr) == strlen(last_col)+1) { // [IP::v:6]:port with "]:" substring
                const char *word = strdupa_safe(n->string);
                (void) extract_first_word(&word, &ret_col, sqr, 0);
                n->string = strncat(ret_col, sqr, strlen(sqr)+1);
                word = last_col;
                (void) extract_first_word(&word, &n->overridden_port, col, 0);
                log_debug("Matched [IP::v:6]:port, output  %s / %s", n->string, n->overridden_port);
                return 2;
        } else if (ret_sqr != NULL && last_col != NULL && strlen(ret_sqr) != strlen(last_col)+1) {
                // [IP::v:6] without port -- no "]:" substring
                return 0;
        } else {
                assert_not_reached();
                return -1;
        }
}
