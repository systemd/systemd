/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "dns-answer.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "fd-util.h"
#include "fileio.h"
#include "ordered-set.h"
#include "path-util.h"
#include "resolved-manager.h"
#include "resolved-static-records.h"
#include "rm-rf.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

static void assert_override_address(Manager *manager, const char *name, uint32_t address) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceKey *key;
        DnsResourceRecord *rr;

        ASSERT_NOT_NULL(question = dns_question_new(1));
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, name));
        ASSERT_OK(dns_question_add(question, key, 0));
        dns_resource_key_unref(key);

        ASSERT_OK(manager_static_record_overrides_lookup(manager, question, &answer));
        ASSERT_EQ(dns_answer_size(answer), 1u);

        DnsAnswerItem *item = ASSERT_PTR(ordered_set_first(answer->items));
        rr = item->rr;
        ASSERT_EQ(rr->key->type, DNS_TYPE_A);
        ASSERT_EQ(rr->a.in_addr.s_addr, htobe32(address));
}

TEST(static_record_overrides) {
        _cleanup_(rm_rf_physical_and_freep) char *credential_dir = NULL;
        _cleanup_free_ char *credential_path = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(strv_freep) char **paths = NULL;
        _cleanup_(unlink_tempfilep) char path[] = "/tmp/test-resolved-static-records.XXXXXX";
        const char *old_credential_dir;
        _cleanup_free_ char *saved_credential_dir = NULL;
        Manager manager = {};
        int fd;

        old_credential_dir = getenv("CREDENTIALS_DIRECTORY");
        if (old_credential_dir)
                ASSERT_NOT_NULL(saved_credential_dir = strdup(old_credential_dir));

        ASSERT_OK(mkdtemp_malloc(NULL, &credential_dir));
        ASSERT_OK_ERRNO(setenv("CREDENTIALS_DIRECTORY", credential_dir, true));

        ASSERT_NOT_NULL(credential_path = path_join(credential_dir, "network.rr"));
        ASSERT_OK(write_string_file(
                              credential_path,
                              "{ \"key\": { \"name\": \"rr-override.waldo\", \"type\": 1 }, "
                              "\"address\": [ 5, 6, 7, 8 ] }",
                              WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));

        ASSERT_OK(fd = mkostemp_safe(path));
        safe_close(fd);
        ASSERT_OK(write_string_file(
                              path,
                              "{ \"key\": { \"name\": \"rr-override.waldo\", \"type\": 1 }, "
                              "\"address\": [ 1, 2, 3, 4 ] }",
                              WRITE_STRING_FILE_TRUNCATE|WRITE_STRING_FILE_AVOID_NEWLINE));

        ASSERT_OK(sd_event_new(&event));
        ASSERT_NOT_NULL(paths = strv_new(path));

        manager = (Manager) {
                .event = event,
                .read_static_records = true,
                .static_records_last = USEC_INFINITY,
                .static_record_override_paths = TAKE_PTR(paths),
        };

        assert_override_address(&manager, "rr-override.waldo", 0x01020304);

        manager_static_records_flush(&manager);
        strv_free(manager.static_record_override_paths);

        if (saved_credential_dir)
                ASSERT_OK_ERRNO(setenv("CREDENTIALS_DIRECTORY", saved_credential_dir, true));
        else
                ASSERT_OK_ERRNO(unsetenv("CREDENTIALS_DIRECTORY"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
