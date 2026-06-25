/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journal-authenticate-internal.h"
#include "journal-file.h"

static const JournalAuthOps *auth_ops = NULL;

void journal_auth_set_ops(const JournalAuthOps *ops) {
        auth_ops = ops;
}

void journal_file_auth_done(JournalFile *f) {
        assert(f);

        if (!auth_ops)
                return;

        assert(auth_ops->free);
        f->auth_context = auth_ops->free(f->auth_context);
}

int journal_file_auth_load(JournalFile *f) {
        assert(f);

        if (!auth_ops)
                return -EOPNOTSUPP;

        if (f->auth_context)
                return -EBUSY;

        assert(auth_ops->load);
        return auth_ops->load(&f->auth_context);
}

int journal_file_auth_load_key(JournalFile *f, const char *key) {
        assert(f);

        if (!auth_ops)
                return -EOPNOTSUPP;

        if (f->auth_context)
                return -EBUSY;

        assert(auth_ops->load_key);
        return auth_ops->load_key(&f->auth_context, key);
}

int journal_file_auth_epoch_to_realtime_usec(JournalFile *f, uint64_t epoch, usec_t *ret_start, usec_t *ret_end) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return -EOPNOTSUPP;

        assert(auth_ops);
        assert(auth_ops->epoch_to_realtime_usec);
        return auth_ops->epoch_to_realtime_usec(f->auth_context, epoch, ret_start, ret_end);
}

int journal_file_auth_next_evolve_usec(JournalFile *f, usec_t *ret) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return -EOPNOTSUPP;

        assert(auth_ops);
        assert(auth_ops->next_evolve_usec);
        return auth_ops->next_evolve_usec(f->auth_context, ret);
}

int journal_file_auth_seek(JournalFile *f, uint64_t goal) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        assert(auth_ops);
        assert(auth_ops->seek);
        return auth_ops->seek(f->auth_context, goal);
}

int journal_file_auth_start(JournalFile *f) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        assert(auth_ops);
        assert(auth_ops->start);
        return auth_ops->start(f->auth_context);
}

int journal_file_auth_end(JournalFile *f, uint8_t ret[static TAG_LENGTH]) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return -EOPNOTSUPP;

        assert(auth_ops);
        assert(auth_ops->end);
        return auth_ops->end(f->auth_context, ret);
}

int journal_file_auth_put_header(JournalFile *f) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        assert(auth_ops);
        assert(auth_ops->put_header);
        return auth_ops->put_header(f->auth_context, f);
}

int journal_file_auth_put_object(JournalFile *f, ObjectType type, Object *o, uint64_t p) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        assert(auth_ops);
        assert(auth_ops->put_object);
        return auth_ops->put_object(f->auth_context, f, type, o, p);
}

int journal_file_auth_append_tag(JournalFile *f) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        if (!journal_file_writable(f))
                return 0;

        assert(auth_ops);
        assert(auth_ops->append_tag);
        return auth_ops->append_tag(f->auth_context, f);
}

int journal_file_auth_append_tag_first(JournalFile *f) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        if (!journal_file_writable(f))
                return 0;

        assert(auth_ops);
        assert(auth_ops->append_tag_first);
        return auth_ops->append_tag_first(f->auth_context, f);
}

int journal_file_auth_append_tag_maybe(JournalFile *f, usec_t realtime) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        if (!journal_file_writable(f))
                return 0;

        assert(auth_ops);
        assert(auth_ops->append_tag_maybe);
        return auth_ops->append_tag_maybe(f->auth_context, f, realtime);
}
