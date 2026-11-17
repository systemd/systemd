/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink.h"

#include "forward.h"

/* An item of a channel from varlink_observe_channel_new(). error_id is NULL for a successful reply. */
typedef struct VarlinkReply {
        sd_json_variant *parameters;
        char *error_id;
        sd_varlink_reply_flags_t flags;
} VarlinkReply;

VarlinkReply* varlink_reply_free(VarlinkReply *reply);
DEFINE_TRIVIAL_CLEANUP_FUNC(VarlinkReply*, varlink_reply_free);

/* Start a method call with the "more" flag on link and push every reply into a new channel. The link has to
 * be attached to an event loop, otherwise this returns -ENOPKG. The link must not have a reply callback.
 * The channel sets the reply callback and the userdata of the link, and keeps a reference to the link.
 * Closing or freeing the channel closes the link. Closing the link ends the call. The channel closes itself
 * after the final reply or an error reply. sd_channel_pop() then returns the buffered replies, and fails
 * with -EPIPE once the buffer is empty. A disconnect or a timeout arrives as an error reply, like with
 * sd_varlink_observe(). If the channel is full, the reply is dropped. */
int varlink_observe_channel_new(
                sd_varlink *link,
                const char *method,
                sd_json_variant *parameters,
                size_t capacity,
                sd_channel **ret);

/* Like varlink_observe_channel_new(), but backed by sd_channel_new_conflated(). A new reply replaces the
 * reply that is still buffered, so a consumer only sees the most recent reply. The final reply or an error
 * reply also replaces a buffered notification. Use this when only the latest state matters, for example
 * to learn whether a call is still running. */
int varlink_observe_channel_new_conflated(
                sd_varlink *link,
                const char *method,
                sd_json_variant *parameters,
                sd_channel **ret);
