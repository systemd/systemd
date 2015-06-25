/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "xml.h"
#include "fileio.h"
#include "strv.h"
#include "set.h"
#include "conf-files.h"
#include "bus-internal.h"
#include "bus-xml-policy.h"
#include "sd-login.h"
#include "formats-util.h"

static void policy_item_free(PolicyItem *i) {
        assert(i);

        free(i->interface);
        free(i->member);
        free(i->error);
        free(i->name);
        free(i->path);
        free(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(PolicyItem*, policy_item_free);

static void item_append(PolicyItem *i, PolicyItem **list) {

        PolicyItem *tail;

        LIST_FIND_TAIL(items, *list, tail);
        LIST_INSERT_AFTER(items, *list, tail, i);
}

static int file_load(Policy *p, const char *path) {

        _cleanup_free_ char *c = NULL, *policy_user = NULL, *policy_group = NULL;
        _cleanup_(policy_item_freep) PolicyItem *i = NULL;
        void *xml_state = NULL;
        unsigned n_other = 0;
        const char *q;
        int r;

        enum {
                STATE_OUTSIDE,
                STATE_BUSCONFIG,
                STATE_POLICY,
                STATE_POLICY_CONTEXT,
                STATE_POLICY_CONSOLE,
                STATE_POLICY_USER,
                STATE_POLICY_GROUP,
                STATE_POLICY_OTHER_ATTRIBUTE,
                STATE_ALLOW_DENY,
                STATE_ALLOW_DENY_INTERFACE,
                STATE_ALLOW_DENY_MEMBER,
                STATE_ALLOW_DENY_ERROR,
                STATE_ALLOW_DENY_PATH,
                STATE_ALLOW_DENY_MESSAGE_TYPE,
                STATE_ALLOW_DENY_NAME,
                STATE_ALLOW_DENY_OTHER_ATTRIBUTE,
                STATE_OTHER,
        } state = STATE_OUTSIDE;

        enum {
                POLICY_CATEGORY_NONE,
                POLICY_CATEGORY_DEFAULT,
                POLICY_CATEGORY_MANDATORY,
                POLICY_CATEGORY_ON_CONSOLE,
                POLICY_CATEGORY_NO_CONSOLE,
                POLICY_CATEGORY_USER,
                POLICY_CATEGORY_GROUP
        } policy_category = POLICY_CATEGORY_NONE;

        unsigned line = 0;

        assert(p);

        r = read_full_file(path, &c, NULL);
        if (r < 0) {
                if (r == -ENOENT)
                        return 0;
                if (r == -EISDIR)
                        return r;

                return log_error_errno(r, "Failed to load %s: %m", path);
        }

        q = c;
        for (;;) {
                _cleanup_free_ char *name = NULL;
                int t;

                t = xml_tokenize(&q, &name, &xml_state, &line);
                if (t < 0)
                        return log_error_errno(t, "XML parse failure in %s: %m", path);

                switch (state) {

                case STATE_OUTSIDE:

                        if (t == XML_TAG_OPEN) {
                                if (streq(name, "busconfig"))
                                        state = STATE_BUSCONFIG;
                                else {
                                        log_error("Unexpected tag %s at %s:%u.", name, path, line);
                                        return -EINVAL;
                                }

                        } else if (t == XML_END)
                                return 0;
                        else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token (1) at %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_BUSCONFIG:

                        if (t == XML_TAG_OPEN) {
                                if (streq(name, "policy")) {
                                        state = STATE_POLICY;
                                        policy_category = POLICY_CATEGORY_NONE;
                                        free(policy_user);
                                        free(policy_group);
                                        policy_user = policy_group = NULL;
                                } else {
                                        state = STATE_OTHER;
                                        n_other = 0;
                                }
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq(name, "busconfig")))
                                state = STATE_OUTSIDE;
                        else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token (2) at %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_POLICY:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq(name, "context"))
                                        state = STATE_POLICY_CONTEXT;
                                else if (streq(name, "at_console"))
                                        state = STATE_POLICY_CONSOLE;
                                else if (streq(name, "user"))
                                        state = STATE_POLICY_USER;
                                else if (streq(name, "group"))
                                        state = STATE_POLICY_GROUP;
                                else {
                                        log_warning("Attribute %s of <policy> tag unknown at %s:%u, ignoring.", name, path, line);
                                        state = STATE_POLICY_OTHER_ATTRIBUTE;
                                }
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq(name, "policy")))
                                state = STATE_BUSCONFIG;
                        else if (t == XML_TAG_OPEN) {
                                PolicyItemType it;

                                if (streq(name, "allow"))
                                        it = POLICY_ITEM_ALLOW;
                                else if (streq(name, "deny"))
                                        it = POLICY_ITEM_DENY;
                                else {
                                        log_warning("Unknown tag %s in <policy> %s:%u.", name, path, line);
                                        return -EINVAL;
                                }

                                assert(!i);
                                i = new0(PolicyItem, 1);
                                if (!i)
                                        return log_oom();

                                i->type = it;
                                state = STATE_ALLOW_DENY;

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token (3) at %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_POLICY_CONTEXT:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                if (streq(name, "default")) {
                                        policy_category = POLICY_CATEGORY_DEFAULT;
                                        state = STATE_POLICY;
                                } else if (streq(name, "mandatory")) {
                                        policy_category = POLICY_CATEGORY_MANDATORY;
                                        state = STATE_POLICY;
                                } else {
                                        log_error("context= parameter %s unknown for <policy> at %s:%u.", name, path, line);
                                        return -EINVAL;
                                }
                        } else {
                                log_error("Unexpected token (4) at %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_POLICY_CONSOLE:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                if (streq(name, "true")) {
                                        policy_category = POLICY_CATEGORY_ON_CONSOLE;
                                        state = STATE_POLICY;
                                } else if (streq(name, "false")) {
                                        policy_category = POLICY_CATEGORY_NO_CONSOLE;
                                        state = STATE_POLICY;
                                } else {
                                        log_error("at_console= parameter %s unknown for <policy> at %s:%u.", name, path, line);
                                        return -EINVAL;
                                }
                        } else {
                                log_error("Unexpected token (4.1) at %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_POLICY_USER:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                free(policy_user);
                                policy_user = name;
                                name = NULL;
                                policy_category = POLICY_CATEGORY_USER;
                                state = STATE_POLICY;
                        } else {
                                log_error("Unexpected token (5) in %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_POLICY_GROUP:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                free(policy_group);
                                policy_group = name;
                                name = NULL;
                                policy_category = POLICY_CATEGORY_GROUP;
                                state = STATE_POLICY;
                        } else {
                                log_error("Unexpected token (6) at %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_POLICY_OTHER_ATTRIBUTE:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_POLICY;
                        else {
                                log_error("Unexpected token (7) in %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_ALLOW_DENY:

                        assert(i);

                        if (t == XML_ATTRIBUTE_NAME) {
                                PolicyItemClass ic;

                                if (startswith(name, "send_"))
                                        ic = POLICY_ITEM_SEND;
                                else if (startswith(name, "receive_"))
                                        ic = POLICY_ITEM_RECV;
                                else if (streq(name, "own"))
                                        ic = POLICY_ITEM_OWN;
                                else if (streq(name, "own_prefix"))
                                        ic = POLICY_ITEM_OWN_PREFIX;
                                else if (streq(name, "user"))
                                        ic = POLICY_ITEM_USER;
                                else if (streq(name, "group"))
                                        ic = POLICY_ITEM_GROUP;
                                else if (STR_IN_SET(name, "eavesdrop", "log")) {
                                        log_debug("Unsupported attribute %s= at %s:%u, ignoring.", name, path, line);
                                        state = STATE_ALLOW_DENY_OTHER_ATTRIBUTE;
                                        break;
                                } else {
                                        log_error("Unknown attribute %s= at %s:%u, ignoring.", name, path, line);
                                        state = STATE_ALLOW_DENY_OTHER_ATTRIBUTE;
                                        break;
                                }

                                if (i->class != _POLICY_ITEM_CLASS_UNSET && ic != i->class) {
                                        log_error("send_, receive_/eavesdrop fields mixed on same tag at %s:%u.", path, line);
                                        return -EINVAL;
                                }

                                i->class = ic;

                                if (ic == POLICY_ITEM_SEND || ic == POLICY_ITEM_RECV) {
                                        const char *u;

                                        u = strchr(name, '_');
                                        assert(u);

                                        u++;

                                        if (streq(u, "interface"))
                                                state = STATE_ALLOW_DENY_INTERFACE;
                                        else if (streq(u, "member"))
                                                state = STATE_ALLOW_DENY_MEMBER;
                                        else if (streq(u, "error"))
                                                state = STATE_ALLOW_DENY_ERROR;
                                        else if (streq(u, "path"))
                                                state = STATE_ALLOW_DENY_PATH;
                                        else if (streq(u, "type"))
                                                state = STATE_ALLOW_DENY_MESSAGE_TYPE;
                                        else if ((streq(u, "destination") && ic == POLICY_ITEM_SEND) ||
                                                 (streq(u, "sender") && ic == POLICY_ITEM_RECV))
                                                state = STATE_ALLOW_DENY_NAME;
                                        else {
                                                if (streq(u, "requested_reply"))
                                                        log_debug("Unsupported attribute %s= at %s:%u, ignoring.", name, path, line);
                                                else
                                                        log_error("Unknown attribute %s= at %s:%u, ignoring.", name, path, line);
                                                state = STATE_ALLOW_DENY_OTHER_ATTRIBUTE;
                                                break;
                                        }
                                } else
                                        state = STATE_ALLOW_DENY_NAME;

                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq(name, i->type == POLICY_ITEM_ALLOW ? "allow" : "deny"))) {

                                /* If the tag is fully empty so far, we consider it a recv */
                                if (i->class == _POLICY_ITEM_CLASS_UNSET)
                                        i->class = POLICY_ITEM_RECV;

                                if (policy_category == POLICY_CATEGORY_DEFAULT)
                                        item_append(i, &p->default_items);
                                else if (policy_category == POLICY_CATEGORY_MANDATORY)
                                        item_append(i, &p->mandatory_items);
                                else if (policy_category == POLICY_CATEGORY_ON_CONSOLE)
                                        item_append(i, &p->on_console_items);
                                else if (policy_category == POLICY_CATEGORY_NO_CONSOLE)
                                        item_append(i, &p->no_console_items);
                                else if (policy_category == POLICY_CATEGORY_USER) {
                                        const char *u = policy_user;

                                        assert_cc(sizeof(uid_t) == sizeof(uint32_t));

                                        r = hashmap_ensure_allocated(&p->user_items, NULL);
                                        if (r < 0)
                                                return log_oom();

                                        if (!u) {
                                                log_error("User policy without name");
                                                return -EINVAL;
                                        }

                                        r = get_user_creds(&u, &i->uid, NULL, NULL, NULL);
                                        if (r < 0) {
                                                log_error_errno(r, "Failed to resolve user %s, ignoring policy: %m", u);
                                                free(i);
                                        } else {
                                                PolicyItem *first;

                                                first = hashmap_get(p->user_items, UINT32_TO_PTR(i->uid));
                                                item_append(i, &first);
                                                i->uid_valid = true;

                                                r = hashmap_replace(p->user_items, UINT32_TO_PTR(i->uid), first);
                                                if (r < 0) {
                                                        LIST_REMOVE(items, first, i);
                                                        return log_oom();
                                                }
                                        }

                                } else if (policy_category == POLICY_CATEGORY_GROUP) {
                                        const char *g = policy_group;

                                        assert_cc(sizeof(gid_t) == sizeof(uint32_t));

                                        r = hashmap_ensure_allocated(&p->group_items, NULL);
                                        if (r < 0)
                                                return log_oom();

                                        if (!g) {
                                                log_error("Group policy without name");
                                                return -EINVAL;
                                        }

                                        r = get_group_creds(&g, &i->gid);
                                        if (r < 0) {
                                                log_error_errno(r, "Failed to resolve group %s, ignoring policy: %m", g);
                                                free(i);
                                        } else {
                                                PolicyItem *first;

                                                first = hashmap_get(p->group_items, UINT32_TO_PTR(i->gid));
                                                item_append(i, &first);
                                                i->gid_valid = true;

                                                r = hashmap_replace(p->group_items, UINT32_TO_PTR(i->gid), first);
                                                if (r < 0) {
                                                        LIST_REMOVE(items, first, i);
                                                        return log_oom();
                                                }
                                        }
                                }

                                state = STATE_POLICY;
                                i = NULL;

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token (8) at %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_ALLOW_DENY_INTERFACE:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                assert(i);
                                if (i->interface) {
                                        log_error("Duplicate interface at %s:%u.", path, line);
                                        return -EINVAL;
                                }

                                if (!streq(name, "*")) {
                                        i->interface = name;
                                        name = NULL;
                                }
                                state = STATE_ALLOW_DENY;
                        } else {
                                log_error("Unexpected token (9) at %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_ALLOW_DENY_MEMBER:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                assert(i);
                                if (i->member) {
                                        log_error("Duplicate member in %s:%u.", path, line);
                                        return -EINVAL;
                                }

                                if (!streq(name, "*")) {
                                        i->member = name;
                                        name = NULL;
                                }
                                state = STATE_ALLOW_DENY;
                        } else {
                                log_error("Unexpected token (10) in %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_ALLOW_DENY_ERROR:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                assert(i);
                                if (i->error) {
                                        log_error("Duplicate error in %s:%u.", path, line);
                                        return -EINVAL;
                                }

                                if (!streq(name, "*")) {
                                        i->error = name;
                                        name = NULL;
                                }
                                state = STATE_ALLOW_DENY;
                        } else {
                                log_error("Unexpected token (11) in %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_ALLOW_DENY_PATH:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                assert(i);
                                if (i->path) {
                                        log_error("Duplicate path in %s:%u.", path, line);
                                        return -EINVAL;
                                }

                                if (!streq(name, "*")) {
                                        i->path = name;
                                        name = NULL;
                                }
                                state = STATE_ALLOW_DENY;
                        } else {
                                log_error("Unexpected token (12) in %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_ALLOW_DENY_MESSAGE_TYPE:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                assert(i);

                                if (i->message_type != 0) {
                                        log_error("Duplicate message type in %s:%u.", path, line);
                                        return -EINVAL;
                                }

                                if (!streq(name, "*")) {
                                        r = bus_message_type_from_string(name, &i->message_type);
                                        if (r < 0) {
                                                log_error("Invalid message type in %s:%u.", path, line);
                                                return -EINVAL;
                                        }
                                }

                                state = STATE_ALLOW_DENY;
                        } else {
                                log_error("Unexpected token (13) in %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_ALLOW_DENY_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                assert(i);
                                if (i->name) {
                                        log_error("Duplicate name in %s:%u.", path, line);
                                        return -EINVAL;
                                }

                                switch (i->class) {
                                case POLICY_ITEM_USER:
                                        if (!streq(name, "*")) {
                                                const char *u = name;

                                                r = get_user_creds(&u, &i->uid, NULL, NULL, NULL);
                                                if (r < 0)
                                                        log_error_errno(r, "Failed to resolve user %s: %m", name);
                                                else
                                                        i->uid_valid = true;
                                        }
                                        break;
                                case POLICY_ITEM_GROUP:
                                        if (!streq(name, "*")) {
                                                const char *g = name;

                                                r = get_group_creds(&g, &i->gid);
                                                if (r < 0)
                                                        log_error_errno(r, "Failed to resolve group %s: %m", name);
                                                else
                                                        i->gid_valid = true;
                                        }
                                        break;

                                case POLICY_ITEM_SEND:
                                case POLICY_ITEM_RECV:

                                        if (streq(name, "*")) {
                                                free(name);
                                                name = NULL;
                                        }
                                        break;


                                default:
                                        break;
                                }

                                i->name = name;
                                name = NULL;

                                state = STATE_ALLOW_DENY;
                        } else {
                                log_error("Unexpected token (14) in %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_ALLOW_DENY_OTHER_ATTRIBUTE:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_ALLOW_DENY;
                        else {
                                log_error("Unexpected token (15) in %s:%u.", path, line);
                                return -EINVAL;
                        }

                        break;

                case STATE_OTHER:

                        if (t == XML_TAG_OPEN)
                                n_other++;
                        else if (t == XML_TAG_CLOSE || t == XML_TAG_CLOSE_EMPTY) {

                                if (n_other == 0)
                                        state = STATE_BUSCONFIG;
                                else
                                        n_other--;
                        }

                        break;
                }
        }
}

enum {
        DENY,
        ALLOW,
        DUNNO,
};

static const char *verdict_to_string(int v) {
        switch (v) {

        case DENY:
                return "DENY";
        case ALLOW:
                return "ALLOW";
        case DUNNO:
                return "DUNNO";
        }

        return NULL;
}

struct policy_check_filter {
        PolicyItemClass class;
        uid_t uid;
        gid_t gid;
        int message_type;
        const char *name;
        const char *interface;
        const char *path;
        const char *member;
};

static int is_permissive(PolicyItem *i) {

        assert(i);

        return (i->type == POLICY_ITEM_ALLOW) ? ALLOW : DENY;
}

static int check_policy_item(PolicyItem *i, const struct policy_check_filter *filter) {

        assert(i);
        assert(filter);

        switch (i->class) {
        case POLICY_ITEM_SEND:
        case POLICY_ITEM_RECV:

                if (i->name && !streq_ptr(i->name, filter->name))
                        break;

                if ((i->message_type != 0) && (i->message_type != filter->message_type))
                        break;

                if (i->path && !streq_ptr(i->path, filter->path))
                        break;

                if (i->member && !streq_ptr(i->member, filter->member))
                        break;

                if (i->interface && !streq_ptr(i->interface, filter->interface))
                        break;

                return is_permissive(i);

        case POLICY_ITEM_OWN:
                assert(filter->name);

                if (streq(i->name, "*") || streq(i->name, filter->name))
                        return is_permissive(i);
                break;

        case POLICY_ITEM_OWN_PREFIX:
                assert(filter->name);

                if (streq(i->name, "*") || service_name_startswith(filter->name, i->name))
                        return is_permissive(i);
                break;

        case POLICY_ITEM_USER:
                if (filter->uid != UID_INVALID)
                        if ((streq_ptr(i->name, "*") || (i->uid_valid && i->uid == filter->uid)))
                                return is_permissive(i);
                break;

        case POLICY_ITEM_GROUP:
                if (filter->gid != GID_INVALID)
                        if ((streq_ptr(i->name, "*") || (i->gid_valid && i->gid == filter->gid)))
                                return is_permissive(i);
                break;

        case POLICY_ITEM_IGNORE:
        default:
                break;
        }

        return DUNNO;
}

static int check_policy_items(PolicyItem *items, const struct policy_check_filter *filter) {

        PolicyItem *i;
        int verdict = DUNNO;

        assert(filter);

        /* Check all policies in a set - a broader one might be followed by a more specific one,
         * and the order of rules in policy definitions matters */
        LIST_FOREACH(items, i, items) {
                int v;

                if (i->class != filter->class &&
                    !(i->class == POLICY_ITEM_OWN_PREFIX && filter->class == POLICY_ITEM_OWN))
                        continue;

                v = check_policy_item(i, filter);
                if (v != DUNNO)
                        verdict = v;
        }

        return verdict;
}

static int policy_check(Policy *p, const struct policy_check_filter *filter) {

        PolicyItem *items;
        int verdict, v;

        assert(p);
        assert(filter);

        assert(IN_SET(filter->class, POLICY_ITEM_SEND, POLICY_ITEM_RECV, POLICY_ITEM_OWN, POLICY_ITEM_USER, POLICY_ITEM_GROUP));

        /*
         * The policy check is implemented by the following logic:
         *
         *  1. Check default items
         *  2. Check group items
         *  3. Check user items
         *  4. Check on/no_console items
         *  5. Check mandatory items
         *
         *  Later rules override earlier rules.
         */

        verdict = check_policy_items(p->default_items, filter);

        if (filter->gid != GID_INVALID) {
                items = hashmap_get(p->group_items, UINT32_TO_PTR(filter->gid));
                if (items) {
                        v = check_policy_items(items, filter);
                        if (v != DUNNO)
                                verdict = v;
                }
        }

        if (filter->uid != UID_INVALID) {
                items = hashmap_get(p->user_items, UINT32_TO_PTR(filter->uid));
                if (items) {
                        v = check_policy_items(items, filter);
                        if (v != DUNNO)
                                verdict = v;
                }
        }

        if (filter->uid != UID_INVALID && sd_uid_get_seats(filter->uid, -1, NULL) > 0)
                v = check_policy_items(p->on_console_items, filter);
        else
                v = check_policy_items(p->no_console_items, filter);
        if (v != DUNNO)
                verdict = v;

        v = check_policy_items(p->mandatory_items, filter);
        if (v != DUNNO)
                verdict = v;

        return verdict;
}

bool policy_check_own(Policy *p, uid_t uid, gid_t gid, const char *name) {

        struct policy_check_filter filter = {
                .class = POLICY_ITEM_OWN,
                .uid   = uid,
                .gid   = gid,
                .name  = name,
        };

        int verdict;

        assert(p);
        assert(name);

        verdict = policy_check(p, &filter);

        log_full(LOG_AUTH | (verdict != ALLOW ? LOG_WARNING : LOG_DEBUG),
                 "Ownership permission check for uid=" UID_FMT " gid=" GID_FMT" name=%s: %s",
                 uid, gid, strna(name), strna(verdict_to_string(verdict)));

        return verdict == ALLOW;
}

bool policy_check_hello(Policy *p, uid_t uid, gid_t gid) {

        struct policy_check_filter filter = {
                .uid = uid,
                .gid = gid,
        };
        int verdict;

        assert(p);

        filter.class = POLICY_ITEM_USER;
        verdict = policy_check(p, &filter);

        if (verdict != DENY) {
                int v;

                filter.class = POLICY_ITEM_GROUP;
                v = policy_check(p, &filter);
                if (v != DUNNO)
                        verdict = v;
        }

        log_full(LOG_AUTH | (verdict != ALLOW ? LOG_WARNING : LOG_DEBUG),
                 "Hello permission check for uid=" UID_FMT " gid=" GID_FMT": %s",
                 uid, gid, strna(verdict_to_string(verdict)));

        return verdict == ALLOW;
}

bool policy_check_one_recv(Policy *p,
                           uid_t uid,
                           gid_t gid,
                           int message_type,
                           const char *name,
                           const char *path,
                           const char *interface,
                           const char *member) {

        struct policy_check_filter filter = {
                .class        = POLICY_ITEM_RECV,
                .uid          = uid,
                .gid          = gid,
                .message_type = message_type,
                .name         = name,
                .interface    = interface,
                .path         = path,
                .member       = member,
        };

        assert(p);

        return policy_check(p, &filter) == ALLOW;
}

bool policy_check_recv(Policy *p,
                       uid_t uid,
                       gid_t gid,
                       int message_type,
                       Set *names,
                       char **namesv,
                       const char *path,
                       const char *interface,
                       const char *member,
                       bool dbus_to_kernel) {

        char *n, **nv, *last = NULL;
        bool allow = false;
        Iterator i;

        assert(p);

        if (set_isempty(names) && strv_isempty(namesv)) {
                allow = policy_check_one_recv(p, uid, gid, message_type, NULL, path, interface, member);
        } else {
                SET_FOREACH(n, names, i) {
                        last = n;
                        allow = policy_check_one_recv(p, uid, gid, message_type, n, path, interface, member);
                        if (allow)
                                break;
                }
                if (!allow) {
                        STRV_FOREACH(nv, namesv) {
                                last = *nv;
                                allow = policy_check_one_recv(p, uid, gid, message_type, *nv, path, interface, member);
                                if (allow)
                                        break;
                        }
                }
        }

        log_full(LOG_AUTH | (!allow ? LOG_WARNING : LOG_DEBUG),
                 "Receive permission check %s for uid=" UID_FMT " gid=" GID_FMT" message=%s name=%s path=%s interface=%s member=%s: %s",
                 dbus_to_kernel ? "dbus-1 to kernel" : "kernel to dbus-1", uid, gid, bus_message_type_to_string(message_type), strna(last),
                 strna(path), strna(interface), strna(member), allow ? "ALLOW" : "DENY");

        return allow;
}

bool policy_check_one_send(Policy *p,
                           uid_t uid,
                           gid_t gid,
                           int message_type,
                           const char *name,
                           const char *path,
                           const char *interface,
                           const char *member) {

        struct policy_check_filter filter = {
                .class        = POLICY_ITEM_SEND,
                .uid          = uid,
                .gid          = gid,
                .message_type = message_type,
                .name         = name,
                .interface    = interface,
                .path         = path,
                .member       = member,
        };

        assert(p);

        return policy_check(p, &filter) == ALLOW;
}

bool policy_check_send(Policy *p,
                       uid_t uid,
                       gid_t gid,
                       int message_type,
                       Set *names,
                       char **namesv,
                       const char *path,
                       const char *interface,
                       const char *member,
                       bool dbus_to_kernel,
                       char **out_used_name) {

        char *n, **nv, *last = NULL;
        bool allow = false;
        Iterator i;

        assert(p);

        if (set_isempty(names) && strv_isempty(namesv)) {
                allow = policy_check_one_send(p, uid, gid, message_type, NULL, path, interface, member);
        } else {
                SET_FOREACH(n, names, i) {
                        last = n;
                        allow = policy_check_one_send(p, uid, gid, message_type, n, path, interface, member);
                        if (allow)
                                break;
                }
                if (!allow) {
                        STRV_FOREACH(nv, namesv) {
                                last = *nv;
                                allow = policy_check_one_send(p, uid, gid, message_type, *nv, path, interface, member);
                                if (allow)
                                        break;
                        }
                }
        }

        if (out_used_name)
                *out_used_name = last;

        log_full(LOG_AUTH | (!allow ? LOG_WARNING : LOG_DEBUG),
                 "Send permission check %s for uid=" UID_FMT " gid=" GID_FMT" message=%s name=%s path=%s interface=%s member=%s: %s",
                 dbus_to_kernel ? "dbus-1 to kernel" : "kernel to dbus-1", uid, gid, bus_message_type_to_string(message_type), strna(last),
                 strna(path), strna(interface), strna(member), allow ? "ALLOW" : "DENY");

        return allow;
}

int policy_load(Policy *p, char **files) {
        char **i;
        int r;

        assert(p);

        STRV_FOREACH(i, files) {

                r = file_load(p, *i);
                if (r == -EISDIR) {
                        _cleanup_strv_free_ char **l = NULL;
                        char **j;

                        r = conf_files_list(&l, ".conf", NULL, *i, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get configuration file list: %m");

                        STRV_FOREACH(j, l)
                                file_load(p, *j);
                }

                /* We ignore all errors but EISDIR, and just proceed. */
        }

        return 0;
}

void policy_free(Policy *p) {
        PolicyItem *i, *first;

        if (!p)
                return;

        while ((i = p->default_items)) {
                LIST_REMOVE(items, p->default_items, i);
                policy_item_free(i);
        }

        while ((i = p->mandatory_items)) {
                LIST_REMOVE(items, p->mandatory_items, i);
                policy_item_free(i);
        }

        while ((i = p->on_console_items)) {
                LIST_REMOVE(items, p->on_console_items, i);
                policy_item_free(i);
        }

        while ((i = p->no_console_items)) {
                LIST_REMOVE(items, p->no_console_items, i);
                policy_item_free(i);
        }

        while ((first = hashmap_steal_first(p->user_items))) {

                while ((i = first)) {
                        LIST_REMOVE(items, first, i);
                        policy_item_free(i);
                }
        }

        while ((first = hashmap_steal_first(p->group_items))) {

                while ((i = first)) {
                        LIST_REMOVE(items, first, i);
                        policy_item_free(i);
                }
        }

        hashmap_free(p->user_items);
        hashmap_free(p->group_items);

        p->user_items = p->group_items = NULL;
}

static void dump_items(PolicyItem *items, const char *prefix) {

        PolicyItem *i;

        if (!items)
                return;

        if (!prefix)
                prefix = "";

        LIST_FOREACH(items, i, items) {

                printf("%sType: %s\n"
                       "%sClass: %s\n",
                       prefix, policy_item_type_to_string(i->type),
                       prefix, policy_item_class_to_string(i->class));

                if (i->interface)
                        printf("%sInterface: %s\n",
                               prefix, i->interface);

                if (i->member)
                        printf("%sMember: %s\n",
                               prefix, i->member);

                if (i->error)
                        printf("%sError: %s\n",
                               prefix, i->error);

                if (i->path)
                        printf("%sPath: %s\n",
                               prefix, i->path);

                if (i->name)
                        printf("%sName: %s\n",
                               prefix, i->name);

                if (i->message_type != 0)
                        printf("%sMessage Type: %s\n",
                               prefix, bus_message_type_to_string(i->message_type));

                if (i->uid_valid) {
                        _cleanup_free_ char *user;

                        user = uid_to_name(i->uid);

                        printf("%sUser: %s ("UID_FMT")\n",
                               prefix, strna(user), i->uid);
                }

                if (i->gid_valid) {
                        _cleanup_free_ char *group;

                        group = gid_to_name(i->gid);

                        printf("%sGroup: %s ("GID_FMT")\n",
                               prefix, strna(group), i->gid);
                }
                printf("%s-\n", prefix);
        }
}

static void dump_hashmap_items(Hashmap *h) {
        PolicyItem *i;
        Iterator j;
        void *k;

        HASHMAP_FOREACH_KEY(i, k, h, j) {
                printf("\t%s Item for %u:\n", draw_special_char(DRAW_ARROW), PTR_TO_UINT(k));
                dump_items(i, "\t\t");
        }
}

void policy_dump(Policy *p) {

        printf("%s Default Items:\n", draw_special_char(DRAW_ARROW));
        dump_items(p->default_items, "\t");

        printf("%s Group Items:\n", draw_special_char(DRAW_ARROW));
        dump_hashmap_items(p->group_items);

        printf("%s User Items:\n", draw_special_char(DRAW_ARROW));
        dump_hashmap_items(p->user_items);

        printf("%s On-Console Items:\n", draw_special_char(DRAW_ARROW));
        dump_items(p->on_console_items, "\t");

        printf("%s No-Console Items:\n", draw_special_char(DRAW_ARROW));
        dump_items(p->no_console_items, "\t");

        printf("%s Mandatory Items:\n", draw_special_char(DRAW_ARROW));
        dump_items(p->mandatory_items, "\t");

        fflush(stdout);
}

int shared_policy_new(SharedPolicy **out) {
        SharedPolicy *sp;
        int r;

        sp = new0(SharedPolicy, 1);
        if (!sp)
                return log_oom();

        r = pthread_mutex_init(&sp->lock, NULL);
        if (r < 0) {
                log_error_errno(r, "Cannot initialize shared policy mutex: %m");
                goto exit_free;
        }

        r = pthread_rwlock_init(&sp->rwlock, NULL);
        if (r < 0) {
                log_error_errno(r, "Cannot initialize shared policy rwlock: %m");
                goto exit_mutex;
        }

        *out = sp;
        sp = NULL;
        return 0;

        /* pthread lock destruction is not fail-safe... meh! */
exit_mutex:
        pthread_mutex_destroy(&sp->lock);
exit_free:
        free(sp);
        return r;
}

SharedPolicy *shared_policy_free(SharedPolicy *sp) {
        if (!sp)
                return NULL;

        policy_free(sp->policy);
        pthread_rwlock_destroy(&sp->rwlock);
        pthread_mutex_destroy(&sp->lock);
        strv_free(sp->configuration);
        free(sp);

        return NULL;
}

static int shared_policy_reload_unlocked(SharedPolicy *sp, char **configuration) {
        Policy old, buffer = {};
        bool free_old;
        int r;

        assert(sp);

        r = policy_load(&buffer, configuration);
        if (r < 0)
                return log_error_errno(r, "Failed to load policy: %m");

        log_debug("Reloading configuration");
        /* policy_dump(&buffer); */

        pthread_rwlock_wrlock(&sp->rwlock);
        memcpy(&old, &sp->buffer, sizeof(old));
        memcpy(&sp->buffer, &buffer, sizeof(buffer));
        free_old = !!sp->policy;
        sp->policy = &sp->buffer;
        pthread_rwlock_unlock(&sp->rwlock);

        if (free_old)
                policy_free(&old);

        return 0;
}

int shared_policy_reload(SharedPolicy *sp) {
        int r;

        assert(sp);

        pthread_mutex_lock(&sp->lock);
        r = shared_policy_reload_unlocked(sp, sp->configuration);
        pthread_mutex_unlock(&sp->lock);

        return r;
}

int shared_policy_preload(SharedPolicy *sp, char **configuration) {
        _cleanup_strv_free_ char **conf = NULL;
        int r = 0;

        assert(sp);

        conf = strv_copy(configuration);
        if (!conf)
                return log_oom();

        pthread_mutex_lock(&sp->lock);
        if (!sp->policy) {
                r = shared_policy_reload_unlocked(sp, conf);
                if (r >= 0) {
                        sp->configuration = conf;
                        conf = NULL;
                }
        }
        pthread_mutex_unlock(&sp->lock);

        return r;
}

Policy *shared_policy_acquire(SharedPolicy *sp) {
        assert(sp);

        pthread_rwlock_rdlock(&sp->rwlock);
        if (sp->policy)
                return sp->policy;
        pthread_rwlock_unlock(&sp->rwlock);

        return NULL;
}

void shared_policy_release(SharedPolicy *sp, Policy *p) {
        assert(sp);
        assert(!p || sp->policy == p);

        if (p)
                pthread_rwlock_unlock(&sp->rwlock);
}

static const char* const policy_item_type_table[_POLICY_ITEM_TYPE_MAX] = {
        [_POLICY_ITEM_TYPE_UNSET] = "unset",
        [POLICY_ITEM_ALLOW] = "allow",
        [POLICY_ITEM_DENY] = "deny",
};
DEFINE_STRING_TABLE_LOOKUP(policy_item_type, PolicyItemType);

static const char* const policy_item_class_table[_POLICY_ITEM_CLASS_MAX] = {
        [_POLICY_ITEM_CLASS_UNSET] = "unset",
        [POLICY_ITEM_SEND] = "send",
        [POLICY_ITEM_RECV] = "recv",
        [POLICY_ITEM_OWN] = "own",
        [POLICY_ITEM_OWN_PREFIX] = "own-prefix",
        [POLICY_ITEM_USER] = "user",
        [POLICY_ITEM_GROUP] = "group",
        [POLICY_ITEM_IGNORE] = "ignore",
};
DEFINE_STRING_TABLE_LOOKUP(policy_item_class, PolicyItemClass);
