/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "metrics.h"
#include "tests.h"

static int generate_nothing(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        return 0;
}

static int generate_two(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        int r;

        r = metric_build_send_unsigned(mf, link, "one.service", 1, /* fields= */ NULL);
        if (r < 0)
                return r;

        return metric_build_send_unsigned(mf, link, "two.service", 2, /* fields= */ NULL);
}

static const MetricFamily metric_families_empty[] = {
        {
                .name = "io.test.Nothing",
                .description = "A metric family that currently has nothing to report",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = generate_nothing,
        },
        {}
};

static const MetricFamily metric_families_two[] = {
        {
                .name = "io.test.Two",
                .description = "A metric family reporting two metrics",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = generate_two,
        },
        {}
};

static int method_list_empty(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(metric_families_empty, link, parameters, flags, userdata);
}

static int method_list_two(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(metric_families_two, link, parameters, flags, userdata);
}

static int method_describe_two(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(metric_families_two, link, parameters, flags, userdata);
}

typedef struct Replies {
        unsigned n_metrics;
        unsigned n_terminators;
        unsigned n_errors;
        bool done;
} Replies;

static int on_reply(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        Replies *replies = ASSERT_PTR(userdata);

        ASSERT_FALSE(replies->done);

        if (error_id) {
                log_info("Got error reply: %s", error_id);
                replies->n_errors++;
        } else if (sd_json_variant_is_blank_object(parameters)) {
                /* An empty reply may only ever be used as terminator of an empty stream */
                ASSERT_FALSE(FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES));
                replies->n_terminators++;
        } else {
                ASSERT_NOT_NULL(sd_json_variant_by_key(parameters, "name"));
                replies->n_metrics++;
        }

        if (!FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES)) {
                replies->done = true;
                ASSERT_OK(sd_event_exit(sd_varlink_get_event(link), EXIT_SUCCESS));
        }

        return 0;
}

static void observe(const char *method, Replies *ret) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        ASSERT_OK(sd_varlink_server_new(&s, 0));
        ASSERT_OK(sd_varlink_server_attach_event(s, e, 0));
        ASSERT_OK(sd_varlink_server_bind_method_many(
                        s,
                        "io.test.ListEmpty",   method_list_empty,
                        "io.test.ListTwo",     method_list_two,
                        "io.test.DescribeTwo", method_describe_two));

        int connfd[2];
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, connfd));
        ASSERT_OK(sd_varlink_server_add_connection(s, connfd[0], /* ret= */ NULL));

        _cleanup_(sd_varlink_unrefp) sd_varlink *c = NULL;
        ASSERT_OK(sd_varlink_connect_fd(&c, connfd[1]));
        ASSERT_OK(sd_varlink_attach_event(c, e, 0));

        *ret = (Replies) {};
        (void) sd_varlink_set_userdata(c, ret);
        ASSERT_OK(sd_varlink_bind_reply(c, on_reply));
        ASSERT_OK(sd_varlink_observe(c, method, /* parameters= */ NULL));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_TRUE(ret->done);
}

TEST(list_empty) {
        Replies replies;

        /* Nothing to report is not an error, but a stream consisting of just the empty terminator */
        observe("io.test.ListEmpty", &replies);
        ASSERT_EQ(replies.n_errors, 0u);
        ASSERT_EQ(replies.n_metrics, 0u);
        ASSERT_EQ(replies.n_terminators, 1u);
}

TEST(list_two) {
        Replies replies;

        /* A non-empty stream must not get an extra empty terminator */
        observe("io.test.ListTwo", &replies);
        ASSERT_EQ(replies.n_errors, 0u);
        ASSERT_EQ(replies.n_metrics, 2u);
        ASSERT_EQ(replies.n_terminators, 0u);
}

TEST(describe_two) {
        Replies replies;

        observe("io.test.DescribeTwo", &replies);
        ASSERT_EQ(replies.n_errors, 0u);
        ASSERT_EQ(replies.n_metrics, 1u);
        ASSERT_EQ(replies.n_terminators, 0u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
