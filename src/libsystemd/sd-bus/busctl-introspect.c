/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "sd-bus.h"

#include "alloc-util.h"
#include "busctl-introspect.h"
#include "string-util.h"
#include "util.h"
#include "xml.h"

#define NODE_DEPTH_MAX 16

typedef struct Context {
        const XMLIntrospectOps *ops;
        void *userdata;

        char *interface_name;
        uint64_t interface_flags;

        char *member_name;
        char *member_signature;
        char *member_result;
        uint64_t member_flags;
        bool member_writable;

        const char *current;
        void *xml_state;
} Context;

static void context_reset_member(Context *c) {
        free(c->member_name);
        free(c->member_signature);
        free(c->member_result);

        c->member_name = c->member_signature = c->member_result = NULL;
        c->member_flags = 0;
        c->member_writable = false;
}

static void context_reset_interface(Context *c) {
        c->interface_name = mfree(c->interface_name);
        c->interface_flags = 0;

        context_reset_member(c);
}

static int parse_xml_annotation(Context *context, uint64_t *flags) {

        enum {
                STATE_ANNOTATION,
                STATE_NAME,
                STATE_VALUE
        } state = STATE_ANNOTATION;

        _cleanup_free_ char *field = NULL, *value = NULL;

        assert(context);

        for (;;) {
                _cleanup_free_ char *name = NULL;

                int t;

                t = xml_tokenize(&context->current, &name, &context->xml_state, NULL);
                if (t < 0) {
                        log_error("XML parse error.");
                        return t;
                }

                if (t == XML_END) {
                        log_error("Premature end of XML data.");
                        return -EBADMSG;
                }

                switch (state) {

                case STATE_ANNOTATION:

                        if (t == XML_ATTRIBUTE_NAME) {

                                if (streq_ptr(name, "name"))
                                        state = STATE_NAME;

                                else if (streq_ptr(name, "value"))
                                        state = STATE_VALUE;

                                else {
                                        log_error("Unexpected <annotation> attribute %s.", name);
                                        return -EBADMSG;
                                }

                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "annotation"))) {

                                if (flags) {
                                        if (streq_ptr(field, "org.freedesktop.DBus.Deprecated")) {

                                                if (streq_ptr(value, "true"))
                                                        *flags |= SD_BUS_VTABLE_DEPRECATED;

                                        } else if (streq_ptr(field, "org.freedesktop.DBus.Method.NoReply")) {

                                                if (streq_ptr(value, "true"))
                                                        *flags |= SD_BUS_VTABLE_METHOD_NO_REPLY;

                                        } else if (streq_ptr(field, "org.freedesktop.DBus.Property.EmitsChangedSignal")) {

                                                if (streq_ptr(value, "const"))
                                                        *flags = (*flags & ~(SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION|SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE)) | SD_BUS_VTABLE_PROPERTY_CONST;
                                                else if (streq_ptr(value, "invalidates"))
                                                        *flags = (*flags & ~(SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE|SD_BUS_VTABLE_PROPERTY_CONST)) | SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION;
                                                else if (streq_ptr(value, "false"))
                                                        *flags = *flags & ~(SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE|SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION);
                                        }
                                }

                                return 0;

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in <annotation>. (1)");
                                return -EINVAL;
                        }

                        break;

                case STATE_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                free(field);
                                field = name;
                                name = NULL;

                                state = STATE_ANNOTATION;
                        } else {
                                log_error("Unexpected token in <annotation>. (2)");
                                return -EINVAL;
                        }

                        break;

                case STATE_VALUE:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                free(value);
                                value = name;
                                name = NULL;

                                state = STATE_ANNOTATION;
                        } else {
                                log_error("Unexpected token in <annotation>. (3)");
                                return -EINVAL;
                        }

                        break;

                default:
                        assert_not_reached("Bad state");
                }
        }
}

static int parse_xml_node(Context *context, const char *prefix, unsigned n_depth) {

        enum {
                STATE_NODE,
                STATE_NODE_NAME,
                STATE_INTERFACE,
                STATE_INTERFACE_NAME,
                STATE_METHOD,
                STATE_METHOD_NAME,
                STATE_METHOD_ARG,
                STATE_METHOD_ARG_NAME,
                STATE_METHOD_ARG_TYPE,
                STATE_METHOD_ARG_DIRECTION,
                STATE_SIGNAL,
                STATE_SIGNAL_NAME,
                STATE_SIGNAL_ARG,
                STATE_SIGNAL_ARG_NAME,
                STATE_SIGNAL_ARG_TYPE,
                STATE_PROPERTY,
                STATE_PROPERTY_NAME,
                STATE_PROPERTY_TYPE,
                STATE_PROPERTY_ACCESS,
        } state = STATE_NODE;

        _cleanup_free_ char *node_path = NULL, *argument_type = NULL, *argument_direction = NULL;
        const char *np = prefix;
        int r;

        assert(context);
        assert(prefix);

        if (n_depth > NODE_DEPTH_MAX) {
                log_error("<node> depth too high.");
                return -EINVAL;
        }

        for (;;) {
                _cleanup_free_ char *name = NULL;
                int t;

                t = xml_tokenize(&context->current, &name, &context->xml_state, NULL);
                if (t < 0) {
                        log_error("XML parse error.");
                        return t;
                }

                if (t == XML_END) {
                        log_error("Premature end of XML data.");
                        return -EBADMSG;
                }

                switch (state) {

                case STATE_NODE:
                        if (t == XML_ATTRIBUTE_NAME) {

                                if (streq_ptr(name, "name"))
                                        state = STATE_NODE_NAME;
                                else {
                                        log_error("Unexpected <node> attribute %s.", name);
                                        return -EBADMSG;
                                }

                        } else if (t == XML_TAG_OPEN) {

                                if (streq_ptr(name, "interface"))
                                        state = STATE_INTERFACE;
                                else if (streq_ptr(name, "node")) {

                                        r = parse_xml_node(context, np, n_depth+1);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected <node> tag %s.", name);
                                        return -EBADMSG;
                                }

                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "node"))) {

                                if (context->ops->on_path) {
                                        r = context->ops->on_path(node_path ? node_path : np, context->userdata);
                                        if (r < 0)
                                                return r;
                                }

                                return 0;

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in <node>. (1)");
                                return -EINVAL;
                        }

                        break;

                case STATE_NODE_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {

                                free(node_path);

                                if (name[0] == '/') {
                                        node_path = name;
                                        name = NULL;
                                } else {

                                        if (endswith(prefix, "/"))
                                                node_path = strappend(prefix, name);
                                        else
                                                node_path = strjoin(prefix, "/", name, NULL);
                                        if (!node_path)
                                                return log_oom();
                                }

                                np = node_path;
                                state = STATE_NODE;
                        } else {
                                log_error("Unexpected token in <node>. (2)");
                                return -EINVAL;
                        }

                        break;

                case STATE_INTERFACE:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_INTERFACE_NAME;
                                else {
                                        log_error("Unexpected <interface> attribute %s.", name);
                                        return -EBADMSG;
                                }

                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "method"))
                                        state = STATE_METHOD;
                                else if (streq_ptr(name, "signal"))
                                        state = STATE_SIGNAL;
                                else if (streq_ptr(name, "property")) {
                                        context->member_flags |= SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE;
                                        state = STATE_PROPERTY;
                                } else if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(context, &context->interface_flags);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected <interface> tag %s.", name);
                                        return -EINVAL;
                                }
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "interface"))) {

                                if (n_depth == 0) {
                                        if (context->ops->on_interface) {
                                                r = context->ops->on_interface(context->interface_name, context->interface_flags, context->userdata);
                                                if (r < 0)
                                                        return r;
                                        }

                                        context_reset_interface(context);
                                }

                                state = STATE_NODE;

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in <interface>. (1)");
                                return -EINVAL;
                        }

                        break;

                case STATE_INTERFACE_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                if (n_depth == 0) {
                                        free(context->interface_name);
                                        context->interface_name = name;
                                        name = NULL;
                                }

                                state = STATE_INTERFACE;
                        } else {
                                log_error("Unexpected token in <interface>. (2)");
                                return -EINVAL;
                        }

                        break;

                case STATE_METHOD:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_METHOD_NAME;
                                else {
                                        log_error("Unexpected <method> attribute %s", name);
                                        return -EBADMSG;
                                }
                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "arg"))
                                        state = STATE_METHOD_ARG;
                                else if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(context, &context->member_flags);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected <method> tag %s.", name);
                                        return -EINVAL;
                                }
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "method"))) {

                                if (n_depth == 0) {
                                        if (context->ops->on_method) {
                                                r = context->ops->on_method(context->interface_name, context->member_name, context->member_signature, context->member_result, context->member_flags, context->userdata);
                                                if (r < 0)
                                                        return r;
                                        }

                                        context_reset_member(context);
                                }

                                state = STATE_INTERFACE;

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in <method> (1).");
                                return -EINVAL;
                        }

                        break;

                case STATE_METHOD_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {

                                if (n_depth == 0) {
                                        free(context->member_name);
                                        context->member_name = name;
                                        name = NULL;
                                }

                                state = STATE_METHOD;
                        } else {
                                log_error("Unexpected token in <method> (2).");
                                return -EINVAL;
                        }

                        break;

                case STATE_METHOD_ARG:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_METHOD_ARG_NAME;
                                else if (streq_ptr(name, "type"))
                                        state = STATE_METHOD_ARG_TYPE;
                                else if (streq_ptr(name, "direction"))
                                         state = STATE_METHOD_ARG_DIRECTION;
                                else {
                                        log_error("Unexpected method <arg> attribute %s.", name);
                                        return -EBADMSG;
                                }
                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(context, NULL);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected method <arg> tag %s.", name);
                                        return -EINVAL;
                                }
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "arg"))) {

                                if (n_depth == 0) {

                                        if (argument_type) {
                                                if (!argument_direction || streq(argument_direction, "in")) {
                                                        if (!strextend(&context->member_signature, argument_type, NULL))
                                                                return log_oom();
                                                } else if (streq(argument_direction, "out")) {
                                                        if (!strextend(&context->member_result, argument_type, NULL))
                                                                return log_oom();
                                                }
                                        }

                                        argument_type = mfree(argument_type);
                                        argument_direction = mfree(argument_direction);
                                }

                                state = STATE_METHOD;
                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in method <arg>. (1)");
                                return -EINVAL;
                        }

                        break;

                case STATE_METHOD_ARG_NAME:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_METHOD_ARG;
                        else {
                                log_error("Unexpected token in method <arg>. (2)");
                                return -EINVAL;
                        }

                        break;

                case STATE_METHOD_ARG_TYPE:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                free(argument_type);
                                argument_type = name;
                                name = NULL;

                                state = STATE_METHOD_ARG;
                        } else {
                                log_error("Unexpected token in method <arg>. (3)");
                                return -EINVAL;
                        }

                        break;

                case STATE_METHOD_ARG_DIRECTION:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                free(argument_direction);
                                argument_direction = name;
                                name = NULL;

                                state = STATE_METHOD_ARG;
                        } else {
                                log_error("Unexpected token in method <arg>. (4)");
                                return -EINVAL;
                        }

                        break;

                case STATE_SIGNAL:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_SIGNAL_NAME;
                                else {
                                        log_error("Unexpected <signal> attribute %s.", name);
                                        return -EBADMSG;
                                }
                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "arg"))
                                        state = STATE_SIGNAL_ARG;
                                else if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(context, &context->member_flags);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected <signal> tag %s.", name);
                                        return -EINVAL;
                                }
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "signal"))) {

                                if (n_depth == 0) {
                                        if (context->ops->on_signal) {
                                                r = context->ops->on_signal(context->interface_name, context->member_name, context->member_signature, context->member_flags, context->userdata);
                                                if (r < 0)
                                                        return r;
                                        }

                                        context_reset_member(context);
                                }

                                state = STATE_INTERFACE;

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in <signal>. (1)");
                                return -EINVAL;
                        }

                        break;

                case STATE_SIGNAL_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {

                                if (n_depth == 0) {
                                        free(context->member_name);
                                        context->member_name = name;
                                        name = NULL;
                                }

                                state = STATE_SIGNAL;
                        } else {
                                log_error("Unexpected token in <signal>. (2)");
                                return -EINVAL;
                        }

                        break;


                case STATE_SIGNAL_ARG:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_SIGNAL_ARG_NAME;
                                else if (streq_ptr(name, "type"))
                                        state = STATE_SIGNAL_ARG_TYPE;
                                else {
                                        log_error("Unexpected signal <arg> attribute %s.", name);
                                        return -EBADMSG;
                                }
                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(context, NULL);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected signal <arg> tag %s.", name);
                                        return -EINVAL;
                                }
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "arg"))) {

                                if (argument_type) {
                                        if (!strextend(&context->member_signature, argument_type, NULL))
                                                return log_oom();

                                        argument_type = mfree(argument_type);
                                }

                                state = STATE_SIGNAL;
                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in signal <arg> (1).");
                                return -EINVAL;
                        }

                        break;

                case STATE_SIGNAL_ARG_NAME:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_SIGNAL_ARG;
                        else {
                                log_error("Unexpected token in signal <arg> (2).");
                                return -EINVAL;
                        }

                        break;

                case STATE_SIGNAL_ARG_TYPE:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                free(argument_type);
                                argument_type = name;
                                name = NULL;

                                state = STATE_SIGNAL_ARG;
                        } else {
                                log_error("Unexpected token in signal <arg> (3).");
                                return -EINVAL;
                        }

                        break;

                case STATE_PROPERTY:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_PROPERTY_NAME;
                                else if (streq_ptr(name, "type"))
                                        state  = STATE_PROPERTY_TYPE;
                                else if (streq_ptr(name, "access"))
                                        state  = STATE_PROPERTY_ACCESS;
                                else {
                                        log_error("Unexpected <property> attribute %s.", name);
                                        return -EBADMSG;
                                }
                        } else if (t == XML_TAG_OPEN) {

                                if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(context, &context->member_flags);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected <property> tag %s.", name);
                                        return -EINVAL;
                                }

                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "property"))) {

                                if (n_depth == 0) {
                                        if (context->ops->on_property) {
                                                r = context->ops->on_property(context->interface_name, context->member_name, context->member_signature, context->member_writable, context->member_flags, context->userdata);
                                                if (r < 0)
                                                        return r;
                                        }

                                        context_reset_member(context);
                                }

                                state = STATE_INTERFACE;

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in <property>. (1)");
                                return -EINVAL;
                        }

                        break;

                case STATE_PROPERTY_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {

                                if (n_depth == 0) {
                                        free(context->member_name);
                                        context->member_name = name;
                                        name = NULL;
                                }
                                state = STATE_PROPERTY;
                        } else {
                                log_error("Unexpected token in <property>. (2)");
                                return -EINVAL;
                        }

                        break;

                case STATE_PROPERTY_TYPE:

                        if (t == XML_ATTRIBUTE_VALUE) {

                                if (n_depth == 0) {
                                        free(context->member_signature);
                                        context->member_signature = name;
                                        name = NULL;
                                }

                                state = STATE_PROPERTY;
                        } else {
                                log_error("Unexpected token in <property>. (3)");
                                return -EINVAL;
                        }

                        break;

                case STATE_PROPERTY_ACCESS:

                        if (t == XML_ATTRIBUTE_VALUE) {

                                if (streq(name, "readwrite") || streq(name, "write"))
                                        context->member_writable = true;

                                state = STATE_PROPERTY;
                        } else {
                                log_error("Unexpected token in <property>. (4)");
                                return -EINVAL;
                        }

                        break;
                }
        }
}

int parse_xml_introspect(const char *prefix, const char *xml, const XMLIntrospectOps *ops, void *userdata) {
        Context context = {
                .ops = ops,
                .userdata = userdata,
                .current = xml,
        };

        int r;

        assert(prefix);
        assert(xml);
        assert(ops);

        for (;;) {
                _cleanup_free_ char *name = NULL;

                r = xml_tokenize(&context.current, &name, &context.xml_state, NULL);
                if (r < 0) {
                        log_error("XML parse error");
                        goto finish;
                }

                if (r == XML_END) {
                        r = 0;
                        break;
                }

                if (r == XML_TAG_OPEN) {

                        if (streq(name, "node")) {
                                r = parse_xml_node(&context, prefix, 0);
                                if (r < 0)
                                        goto finish;
                        } else {
                                log_error("Unexpected tag '%s' in introspection data.", name);
                                r = -EBADMSG;
                                goto finish;
                        }
                } else if (r != XML_TEXT || !in_charset(name, WHITESPACE)) {
                        log_error("Unexpected token.");
                        r = -EBADMSG;
                        goto finish;
                }
        }

finish:
        context_reset_interface(&context);

        return r;
}
