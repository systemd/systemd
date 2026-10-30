/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "journal-remote-parse.h"
#include "journal-remote.h"
#include "log.h"
#include "string-util.h"

RemoteSource* source_free(RemoteSource *source) {
        if (!source)
                return NULL;

        journal_importer_cleanup(&source->importer);

        log_trace("Writer ref count %u", source->writer->n_ref);
        writer_unref(source->writer);

        sd_event_source_unref(source->event);
        sd_event_source_unref(source->buffer_event);

        free(source->encoding);
        free(source->client_certificate_subject);
        return mfree(source);
}

/**
 * Initialize zero-filled source with given values. On success, takes
 * ownership of fd and writer, otherwise does not touch them. Always takes
 * ownership of name, even on failure.
 */
RemoteSource* source_new(int fd, bool passive_fd, char *name, Writer *writer) {
        RemoteSource *source;

        log_debug("Creating source for %sfd:%d (%s)",
                  passive_fd ? "passive " : "", fd, name);

        assert(fd >= 0);

        source = new0(RemoteSource, 1);
        if (!source) {
                free(name);
                return NULL;
        }

        source->importer = JOURNAL_IMPORTER_MAKE(fd);
        source->importer.passive_fd = passive_fd;
        source->importer.name = name;

        source->writer = writer;

        return source;
}

int process_source(RemoteSource *source, JournalFileFlags file_flags) {
        int r;

        assert(source);
        assert(source->writer);

        r = journal_importer_process_data(&source->importer);
        if (r <= 0)
                return r;

        /* We have a full event */
        log_trace("Received full event from source@%p fd:%d (%s)",
                  source, source->importer.fd, source->importer.name);

        if (source->importer.iovw.count == 0) {
                log_warning("Entry with no payload, skipping");
                goto freeing;
        }

        assert(source->importer.iovw.iovec);

        if (source->writer->server->add_client_certificate_subject) {
                struct iovec_wrapper *iovw = &source->importer.iovw;
                size_t n = 0;

                /* Drop all supplied copies, including binary fields and metadata from earlier hops. */
                FOREACH_ARRAY(i, iovw->iovec, iovw->count) {
                        if (memory_startswith(i->iov_base, i->iov_len, REMOTE_CERTIFICATE_SUBJECT_FIELD))
                                continue;
                        iovw->iovec[n++] = *i;
                }
                iovw->count = n;

                if (source->client_certificate_subject) {
                        r = iovw_put(iovw, source->client_certificate_subject, strlen(source->client_certificate_subject));
                        if (r == -E2BIG) {
                                log_warning("Entry has no room for the client certificate subject, skipping.");
                                r = 1;
                                goto freeing;
                        }
                        if (r < 0)
                                goto freeing;
                }

                if (iovw_isempty(iovw)) {
                        log_warning("Entry with no payload after removing certificate subjects, skipping.");
                        goto freeing;
                }
        }

        r = writer_write(source->writer,
                         &source->importer.iovw,
                         &source->importer.ts,
                         &source->importer.boot_id,
                         file_flags);
        if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)) {
                log_warning_errno(r, "Entry is invalid, ignoring.");
                r = 0;
        } else if (r < 0)
                log_error_errno(r, "Failed to write entry of %zu bytes: %m",
                                iovw_size(&source->importer.iovw));
        else
                r = 1;

 freeing:
        journal_importer_drop_iovw(&source->importer);
        return r;
}
