/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journal-authenticate.h"
#include "journal-authenticate-internal.h"
#include "journal-file.h"

void journal_file_auth_done(JournalFile *f) {
        assert(f);

#if HAVE_GCRYPT
        f->auth_context = journal_auth_free(f->auth_context);
#endif
}

int journal_file_auth_load(JournalFile *f) {
        assert(f);

#if HAVE_GCRYPT
        return journal_auth_load(&f->auth_context);
#else
        return -EOPNOTSUPP;
#endif
}

int journal_file_auth_load_key(JournalFile *f, const char *key) {
        assert(f);

#if HAVE_GCRYPT
        return journal_auth_load_key(&f->auth_context, key);
#else
        return -EOPNOTSUPP;
#endif
}

int journal_file_auth_epoch_to_realtime_usec(JournalFile *f, uint64_t epoch, usec_t *ret_start, usec_t *ret_end) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return -EOPNOTSUPP;

#if HAVE_GCRYPT
        return journal_auth_epoch_to_realtime_usec(f->auth_context, epoch, ret_start, ret_end);
#else
        assert_not_reached();
#endif
}

int journal_file_auth_next_evolve_usec(JournalFile *f, usec_t *ret) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return -EOPNOTSUPP;

#if HAVE_GCRYPT
        return journal_auth_next_evolve_usec(f->auth_context, ret);
#else
        assert_not_reached();
#endif
}

int journal_file_auth_seek(JournalFile *f, uint64_t goal) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

#if HAVE_GCRYPT
        return journal_auth_seek(f->auth_context, goal);
#else
        assert_not_reached();
#endif
}

int journal_file_auth_setup(JournalFile *f) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

#if HAVE_GCRYPT
        return journal_auth_setup(f->auth_context);
#else
        assert_not_reached();
#endif
}

int journal_file_auth_start(JournalFile *f) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

#if HAVE_GCRYPT
        return journal_auth_start(f->auth_context);
#else
        assert_not_reached();
#endif
}

int journal_file_auth_end(JournalFile *f, uint8_t ret[static TAG_LENGTH]) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return -EOPNOTSUPP;

#if HAVE_GCRYPT
        return journal_auth_end(f->auth_context, ret);
#else
        assert_not_reached();
#endif
}

int journal_file_auth_put_header(JournalFile *f) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

#if HAVE_GCRYPT
        return journal_auth_put_header(f->auth_context, f);
#else
        assert_not_reached();
#endif
}

int journal_file_auth_put_object(JournalFile *f, ObjectType type, Object *o, uint64_t p) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

#if HAVE_GCRYPT
        return journal_auth_put_object(f->auth_context, f, type, o, p);
#else
        assert_not_reached();
#endif
}

int journal_file_auth_append_tag(JournalFile *f) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        if (!journal_file_writable(f))
                return 0;

#if HAVE_GCRYPT
        return journal_auth_append_tag(f->auth_context, f);
#else
        assert_not_reached();
#endif
}

int journal_file_auth_append_tag_first(JournalFile *f) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        if (!journal_file_writable(f))
                return 0;

#if HAVE_GCRYPT
        return journal_auth_append_tag_first(f->auth_context, f);
#else
        assert_not_reached();
#endif
}

int journal_file_auth_append_tag_maybe(JournalFile *f, usec_t realtime) {
        assert(f);

        if (!JOURNAL_HEADER_SEALED(f->header))
                return 0;

        if (!journal_file_writable(f))
                return 0;

#if HAVE_GCRYPT
        return journal_auth_append_tag_maybe(f->auth_context, f, realtime);
#else
        assert_not_reached();
#endif
}
