/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus-vtable.h"

#include "alloc-util.h"
#include "busctl-introspect.h"
#include "log.h"
#include "path-util.h"
#include "string-util.h"
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

                if (t == XML_END)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Premature end of XML data.");

                switch (state) {

                case STATE_ANNOTATION:

                        if (t == XML_ATTRIBUTE_NAME) {

                                if (streq_ptr(name, "name"))
                                        state = STATE_NAME;

                                else if (streq_ptr(name, "value"))
                                        state = STATE_VALUE;

                                else
                                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                               "Unexpected <annotation> attribute %s.",
                                                               name);

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

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <annotation>. (1)");

                        break;

                case STATE_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                free_and_replace(field, name);

                                state = STATE_ANNOTATION;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <annotation>. (2)");

                        break;

                case STATE_VALUE:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                free_and_replace(value, name);

                                state = STATE_ANNOTATION;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <annotation>. (3)");

                        break;

                default:
                        assert_not_reached();
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
                STATE_SIGNAL_ARG_DIRECTION,
                STATE_PROPERTY,
                STATE_PROPERTY_NAME,
                STATE_PROPERTY_TYPE,
                STATE_PROPERTY_ACCESS,
        } state = STATE_NODE;

        _cleanup_free_ char *node_path = NULL, *argument_type = NULL, *argument_direction = NULL;
        const char *np = ASSERT_PTR(prefix);
        int r;

        assert(context);

        if (n_depth > NODE_DEPTH_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "<node> depth too high.");

        for (;;) {
                _cleanup_free_ char *name = NULL;
                int t;

                t = xml_tokenize(&context->current, &name, &context->xml_state, NULL);
                if (t < 0) {
                        log_error("XML parse error.");
                        return t;
                }

                if (t == XML_END)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Premature end of XML data.");

                switch (state) {

                case STATE_NODE:
                        if (t == XML_ATTRIBUTE_NAME) {

                                if (streq_ptr(name, "name"))
                                        state = STATE_NODE_NAME;
                                else
                                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                               "Unexpected <node> attribute %s.", name);

                        } else if (t == XML_TAG_OPEN) {

                                if (streq_ptr(name, "interface"))
                                        state = STATE_INTERFACE;
                                else if (streq_ptr(name, "node")) {

                                        r = parse_xml_node(context, np, n_depth+1);
                                        if (r < 0)
                                                return r;
                                } else
                                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                               "Unexpected <node> tag %s.", name);

                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "node"))) {

                                if (context->ops->on_path) {
                                        r = context->ops->on_path(node_path ?: np, context->userdata);
                                        if (r < 0)
                                                return r;
                                }

                                return 0;

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <node>. (1)");

                        break;

                case STATE_NODE_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {

                                free(node_path);

                                if (name[0] == '/')
                                        node_path = TAKE_PTR(name);
                                else {
                                        node_path = path_join(prefix, name);
                                        if (!node_path)
                                                return log_oom();
                                }

                                np = node_path;
                                state = STATE_NODE;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <node>. (2)");

                        break;

                case STATE_INTERFACE:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_INTERFACE_NAME;
                                else
                                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                               "Unexpected <interface> attribute %s.",
                                                               name);

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
                                } else
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Unexpected <interface> tag %s.", name);
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

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <interface>. (1)");

                        break;

                case STATE_INTERFACE_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                if (n_depth == 0)
                                        free_and_replace(context->interface_name, name);

                                state = STATE_INTERFACE;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <interface>. (2)");

                        break;

                case STATE_METHOD:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_METHOD_NAME;
                                else
                                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                               "Unexpected <method> attribute %s",
                                                               name);
                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "arg"))
                                        state = STATE_METHOD_ARG;
                                else if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(context, &context->member_flags);
                                        if (r < 0)
                                                return r;
                                } else
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Unexpected <method> tag %s.",
                                                               name);
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

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <method> (1).");

                        break;

                case STATE_METHOD_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                if (n_depth == 0)
                                        free_and_replace(context->member_name, name);

                                state = STATE_METHOD;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <method> (2).");

                        break;

                case STATE_METHOD_ARG:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_METHOD_ARG_NAME;
                                else if (streq_ptr(name, "type"))
                                        state = STATE_METHOD_ARG_TYPE;
                                else if (streq_ptr(name, "direction"))
                                        state = STATE_METHOD_ARG_DIRECTION;
                                else
                                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                               "Unexpected method <arg> attribute %s.",
                                                               name);
                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(context, NULL);
                                        if (r < 0)
                                                return r;
                                } else
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Unexpected method <arg> tag %s.",
                                                               name);
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "arg"))) {

                                if (n_depth == 0) {

                                        if (argument_type) {
                                                if (!argument_direction || streq(argument_direction, "in")) {
                                                        if (!strextend(&context->member_signature, argument_type))
                                                                return log_oom();
                                                } else if (streq(argument_direction, "out")) {
                                                        if (!strextend(&context->member_result, argument_type))
                                                                return log_oom();
                                                } else
                                                        log_error("Unexpected method <arg> direction value '%s'.", argument_direction);
                                        }

                                        argument_type = mfree(argument_type);
                                        argument_direction = mfree(argument_direction);
                                }

                                state = STATE_METHOD;
                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in method <arg>. (1)");

                        break;

                case STATE_METHOD_ARG_NAME:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_METHOD_ARG;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in method <arg>. (2)");

                        break;

                case STATE_METHOD_ARG_TYPE:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                free_and_replace(argument_type, name);

                                state = STATE_METHOD_ARG;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in method <arg>. (3)");

                        break;

                case STATE_METHOD_ARG_DIRECTION:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                free_and_replace(argument_direction, name);

                                state = STATE_METHOD_ARG;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in method <arg>. (4)");

                        break;

                case STATE_SIGNAL:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_SIGNAL_NAME;
                                else
                                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                               "Unexpected <signal> attribute %s.",
                                                               name);
                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "arg"))
                                        state = STATE_SIGNAL_ARG;
                                else if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(context, &context->member_flags);
                                        if (r < 0)
                                                return r;
                                } else
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Unexpected <signal> tag %s.",
                                                               name);
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

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <signal>. (1)");

                        break;

                case STATE_SIGNAL_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                if (n_depth == 0)
                                        free_and_replace(context->member_name, name);

                                state = STATE_SIGNAL;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <signal>. (2)");

                        break;

                case STATE_SIGNAL_ARG:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_SIGNAL_ARG_NAME;
                                else if (streq_ptr(name, "type"))
                                        state = STATE_SIGNAL_ARG_TYPE;
                                else if (streq_ptr(name, "direction"))
                                        state = STATE_SIGNAL_ARG_DIRECTION;
                                else
                                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                               "Unexpected signal <arg> attribute %s.",
                                                               name);
                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(context, NULL);
                                        if (r < 0)
                                                return r;
                                } else
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Unexpected signal <arg> tag %s.",
                                                               name);
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "arg"))) {

                                if (argument_type) {
                                        if (!argument_direction || streq(argument_direction, "out")) {
                                                if (!strextend(&context->member_signature, argument_type))
                                                        return log_oom();
                                        } else
                                                log_error("Unexpected signal <arg> direction value '%s'.", argument_direction);

                                        argument_type = mfree(argument_type);
                                }

                                state = STATE_SIGNAL;
                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in signal <arg> (1).");

                        break;

                case STATE_SIGNAL_ARG_NAME:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_SIGNAL_ARG;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in signal <arg> (2).");

                        break;

                case STATE_SIGNAL_ARG_TYPE:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                free_and_replace(argument_type, name);

                                state = STATE_SIGNAL_ARG;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in signal <arg> (3).");

                        break;

                case STATE_SIGNAL_ARG_DIRECTION:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                free_and_replace(argument_direction, name);

                                state = STATE_SIGNAL_ARG;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in signal <arg>. (4)");

                        break;

                case STATE_PROPERTY:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_PROPERTY_NAME;
                                else if (streq_ptr(name, "type"))
                                        state  = STATE_PROPERTY_TYPE;
                                else if (streq_ptr(name, "access"))
                                        state  = STATE_PROPERTY_ACCESS;
                                else
                                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                               "Unexpected <property> attribute %s.",
                                                               name);
                        } else if (t == XML_TAG_OPEN) {

                                if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(context, &context->member_flags);
                                        if (r < 0)
                                                return r;
                                } else
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Unexpected <property> tag %s.",
                                                               name);

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

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <property>. (1)");

                        break;

                case STATE_PROPERTY_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                if (n_depth == 0)
                                        free_and_replace(context->member_name, name);

                                state = STATE_PROPERTY;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <property>. (2)");

                        break;

                case STATE_PROPERTY_TYPE:

                        if (t == XML_ATTRIBUTE_VALUE) {
                                if (n_depth == 0)
                                        free_and_replace(context->member_signature, name);

                                state = STATE_PROPERTY;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <property>. (3)");

                        break;

                case STATE_PROPERTY_ACCESS:

                        if (t == XML_ATTRIBUTE_VALUE) {

                                if (streq(name, "readwrite") || streq(name, "write"))
                                        context->member_writable = true;

                                state = STATE_PROPERTY;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected token in <property>. (4)");

                        break;
                }
        }
}

int parse_xml_introspect(const char *prefix, const char *xml, const XMLIntrospectOps *ops, void *userdata) {
        _cleanup_(context_reset_interface) Context context = {
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
                if (r < 0)
                        return log_error_errno(r, "XML parse error");

                if (r == XML_END)
                        break;

                if (r == XML_TAG_OPEN) {

                        if (streq(name, "node")) {
                                r = parse_xml_node(&context, prefix, 0);
                                if (r < 0)
                                        return r;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Unexpected tag '%s' in introspection data.", name);
                } else if (r != XML_TEXT || !in_charset(name, WHITESPACE))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected token.");
        }

        return 0;
}
