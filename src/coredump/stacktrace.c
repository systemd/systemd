/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dwarf.h>
#include <elfutils/libdwelf.h>
#include <elfutils/libdwfl.h>
#include <libelf.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fileio.h"
#include "fd-util.h"
#include "format-util.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "macro.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "stacktrace.h"
#include "string-util.h"
#include "util.h"

#define FRAMES_MAX 64
#define THREADS_MAX 64
#define ELF_PACKAGE_METADATA_ID 0xcafe1a7e

typedef struct StackContext {
        FILE *f;
        Dwfl *dwfl;
        Elf *elf;
        unsigned n_thread;
        unsigned n_frame;
        JsonVariant **package_metadata;
        Set **modules;
} StackContext;

static StackContext* stack_context_destroy(StackContext *c) {
        if (!c)
                return NULL;

        c->f = safe_fclose(c->f);

        if (c->dwfl) {
                dwfl_end(c->dwfl);
                c->dwfl = NULL;
        }

        if (c->elf) {
                elf_end(c->elf);
                c->elf = NULL;
        }

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(Elf *, elf_end, NULL);

static int frame_callback(Dwfl_Frame *frame, void *userdata) {
        StackContext *c = userdata;
        Dwarf_Addr pc, pc_adjusted, bias = 0;
        _cleanup_free_ Dwarf_Die *scopes = NULL;
        const char *fname = NULL, *symbol = NULL;
        Dwfl_Module *module;
        bool is_activation;
        uint64_t module_offset = 0;

        assert(frame);
        assert(c);

        if (c->n_frame >= FRAMES_MAX)
                return DWARF_CB_ABORT;

        if (!dwfl_frame_pc(frame, &pc, &is_activation))
                return DWARF_CB_ABORT;

        pc_adjusted = pc - (is_activation ? 0 : 1);

        module = dwfl_addrmodule(c->dwfl, pc_adjusted);
        if (module) {
                Dwarf_Die *s, *cudie;
                int n;
                Dwarf_Addr start;

                cudie = dwfl_module_addrdie(module, pc_adjusted, &bias);
                if (cudie) {
                        n = dwarf_getscopes(cudie, pc_adjusted - bias, &scopes);
                        if (n > 0)
                                for (s = scopes; s && s < scopes + n; s++) {
                                        if (IN_SET(dwarf_tag(s), DW_TAG_subprogram, DW_TAG_inlined_subroutine, DW_TAG_entry_point)) {
                                                Dwarf_Attribute *a, space;

                                                a = dwarf_attr_integrate(s, DW_AT_MIPS_linkage_name, &space);
                                                if (!a)
                                                        a = dwarf_attr_integrate(s, DW_AT_linkage_name, &space);
                                                if (a)
                                                        symbol = dwarf_formstring(a);
                                                if (!symbol)
                                                        symbol = dwarf_diename(s);

                                                if (symbol)
                                                        break;
                                        }
                                }
                }

                if (!symbol)
                        symbol = dwfl_module_addrname(module, pc_adjusted);

                fname = dwfl_module_info(module, NULL, &start, NULL, NULL, NULL, NULL, NULL);
                module_offset = pc - start;
        }

        fprintf(c->f, "#%-2u 0x%016" PRIx64 " %s (%s + 0x%" PRIx64 ")\n", c->n_frame, (uint64_t) pc, strna(symbol), strna(fname), module_offset);
        c->n_frame++;

        return DWARF_CB_OK;
}

static int thread_callback(Dwfl_Thread *thread, void *userdata) {
        StackContext *c = userdata;
        pid_t tid;

        assert(thread);
        assert(c);

        if (c->n_thread >= THREADS_MAX)
                return DWARF_CB_ABORT;

        if (c->n_thread != 0)
                fputc('\n', c->f);

        c->n_frame = 0;

        tid = dwfl_thread_tid(thread);
        fprintf(c->f, "Stack trace of thread " PID_FMT ":\n", tid);

        if (dwfl_thread_getframes(thread, frame_callback, c) < 0)
                return DWARF_CB_ABORT;

        c->n_thread++;

        return DWARF_CB_OK;
}

static int parse_package_metadata(const char *name, JsonVariant *id_json, Elf *elf, StackContext *c) {
        size_t n_program_headers;
        int r;

        assert(name);
        assert(elf);
        assert(c);

        /* When iterating over PT_LOAD we will visit modules more than once */
        if (set_contains(*c->modules, name))
                return 0;

        r = elf_getphdrnum(elf, &n_program_headers);
        if (r < 0) /* Not the handle we are looking for - that's ok, skip it */
                return 0;

        /* Iterate over all program headers in that ELF object. These will have been copied by
         * the kernel verbatim when the core file is generated. */
        for (size_t i = 0; i < n_program_headers; ++i) {
                size_t note_offset = 0, name_offset, desc_offset;
                GElf_Phdr mem, *program_header;
                GElf_Nhdr note_header;
                Elf_Data *data;

                /* Package metadata is in PT_NOTE headers. */
                program_header = gelf_getphdr(elf, i, &mem);
                if (!program_header || program_header->p_type != PT_NOTE)
                        continue;

                /* Fortunately there is an iterator we can use to walk over the
                 * elements of a PT_NOTE program header. We are interested in the
                 * note with type. */
                data = elf_getdata_rawchunk(elf,
                                            program_header->p_offset,
                                            program_header->p_filesz,
                                            ELF_T_NHDR);
                if (!data)
                        continue;

                while (note_offset < data->d_size &&
                       (note_offset = gelf_getnote(data, note_offset, &note_header, &name_offset, &desc_offset)) > 0) {
                        const char *note_name = (const char *)data->d_buf + name_offset;
                        const char *payload = (const char *)data->d_buf + desc_offset;

                        if (note_header.n_namesz == 0 || note_header.n_descsz == 0)
                                continue;

                        /* Package metadata might have different owners, but the
                         * magic ID is always the same. */
                        if (note_header.n_type == ELF_PACKAGE_METADATA_ID) {
                                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *w = NULL;

                                r = json_parse(payload, 0, &v, NULL, NULL);
                                if (r < 0)
                                        return log_error_errno(r, "json_parse on %s failed: %m", payload);

                                /* First pretty-print to the buffer, so that the metadata goes as
                                 * plaintext in the journal. */
                                fprintf(c->f, "Metadata for module %s owned by %s found: ",
                                        name, note_name);
                                json_variant_dump(v, JSON_FORMAT_NEWLINE|JSON_FORMAT_PRETTY, c->f, NULL);
                                fputc('\n', c->f);

                                /* Secondly, if we have a build-id, merge it in the same JSON object
                                 * so that it appears all nicely together in the logs/metadata. */
                                if (id_json) {
                                        r = json_variant_merge(&v, id_json);
                                        if (r < 0)
                                                return log_error_errno(r, "json_variant_merge of package meta with buildid failed: %m");
                                }

                                /* Then we build a new object using the module name as the key, and merge it
                                 * with the previous parses, so that in the end it all fits together in a single
                                 * JSON blob. */
                                r = json_build(&w, JSON_BUILD_OBJECT(JSON_BUILD_PAIR(name, JSON_BUILD_VARIANT(v))));
                                if (r < 0)
                                        return log_error_errno(r, "Failed to build JSON object: %m");
                                r = json_variant_merge(c->package_metadata, w);
                                if (r < 0)
                                        return log_error_errno(r, "json_variant_merge of package meta with buildid failed: %m");

                                /* Finally stash the name, so we avoid double visits. */
                                r = set_put_strdup(c->modules, name);
                                if (r < 0)
                                        return log_error_errno(r, "set_put_strdup failed: %m");

                                return 1;
                        }
                }
        }

        /* Didn't find package metadata for this module - that's ok, just go to the next. */
        return 0;
}

static int module_callback(Dwfl_Module *mod, void **userdata, const char *name, Dwarf_Addr start, void *arg) {
        _cleanup_(json_variant_unrefp) JsonVariant *id_json = NULL;
        StackContext *c = arg;
        size_t n_program_headers;
        GElf_Addr id_vaddr, bias;
        const unsigned char *id;
        int id_len, r;
        Elf *elf;

        assert(mod);
        assert(c);

        if (!name)
                name = "(unnamed)"; /* For logging purposes */

        /* We are iterating on each "module", which is what dwfl calls ELF objects contained in the
         * core file, and extracting the build-id first and then the package metadata.
         * We proceed in a best-effort fashion - not all ELF objects might contain both or either.
         * The build-id is easy, as libdwfl parses it during the dwfl_core_file_report() call and
         * stores it separately in an internal library struct. */
        id_len = dwfl_module_build_id(mod, &id, &id_vaddr);
        if (id_len <= 0)
                /* If we don't find a build-id, note it in the journal message, and try
                 * anyway to find the package metadata. It's unlikely to have the latter
                 * without the former, but there's no hard rule. */
                fprintf(c->f, "Found module %s without build-id.\n", name);
        else {
                JsonVariant *build_id;

                /* We will later parse package metadata json and pass it to our caller. Prepare the
                * build-id in json format too, so that it can be appended and parsed cleanly. It
                * will then be added as metadata to the journal message with the stack trace. */
                r = json_build(&id_json, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("buildId", JSON_BUILD_HEX(id, id_len))));
                if (r < 0) {
                        log_error_errno(r, "json_build on build-id failed: %m");
                        return DWARF_CB_ABORT;
                }

                build_id = json_variant_by_key(id_json, "buildId");
                assert_se(build_id);
                fprintf(c->f, "Found module %s with build-id: %s\n", name, json_variant_string(build_id));
        }

        /* The .note.package metadata is more difficult. From the module, we need to get a reference
         * to the ELF object first. We might be lucky and just get it from elfutils. */
        elf = dwfl_module_getelf(mod, &bias);
        if (elf) {
                r = parse_package_metadata(name, id_json, elf, c);
                if (r < 0)
                        return DWARF_CB_ABORT;
                if (r > 0)
                        return DWARF_CB_OK;
        } else
                elf = c->elf;

        /* We did not get the ELF object, or it's just a reference to the core. That is likely
         * because we didn't get direct access to the executable, and the version of elfutils does
         * not yet support parsing it out of the core file directly.
         * So fallback to manual extraction - get the PT_LOAD section from the core,
         * and if it's the right one we can interpret it as an Elf object, and parse
         * its notes manually. */

        r = elf_getphdrnum(elf, &n_program_headers);
        if (r < 0) {
                log_warning("Could not parse number of program headers from core file: %s",
                            elf_errmsg(-1)); /* -1 retrieves the most recent error */
                return DWARF_CB_OK;
        }

        for (size_t i = 0; i < n_program_headers; ++i) {
                GElf_Phdr mem, *program_header;
                Elf_Data *data;

                /* The core file stores the ELF files in the PT_LOAD segment. */
                program_header = gelf_getphdr(elf, i, &mem);
                if (!program_header || program_header->p_type != PT_LOAD)
                        continue;

                /* Now get a usable Elf reference, and parse the notes from it. */
                data = elf_getdata_rawchunk(elf,
                                            program_header->p_offset,
                                            program_header->p_filesz,
                                            ELF_T_NHDR);
                if (!data)
                        continue;

                _cleanup_(elf_endp) Elf *memelf = elf_memory(data->d_buf, data->d_size);
                if (!memelf)
                        continue;
                r = parse_package_metadata(name, id_json, memelf, c);
                if (r < 0)
                        return DWARF_CB_ABORT;
                if (r > 0)
                        break;
        }

        return DWARF_CB_OK;
}

static int parse_core(int fd, const char *executable, char **ret, JsonVariant **ret_package_metadata) {

        static const Dwfl_Callbacks callbacks = {
                .find_elf = dwfl_build_id_find_elf,
                .section_address = dwfl_offline_section_address,
                .find_debuginfo = dwfl_standard_find_debuginfo,
        };

        _cleanup_(json_variant_unrefp) JsonVariant *package_metadata = NULL;
        _cleanup_(set_freep) Set *modules = NULL;
        _cleanup_free_ char *buf = NULL; /* buf should be freed last, c.f closed first (via stack_context_destroy) */
        _cleanup_(stack_context_destroy) StackContext c = {
                .package_metadata = &package_metadata,
                .modules = &modules,
        };
        size_t sz = 0;
        int r;

        assert(fd >= 0);
        assert(ret);

        if (lseek(fd, 0, SEEK_SET) == (off_t) -1)
                return -errno;

        c.f = open_memstream_unlocked(&buf, &sz);
        if (!c.f)
                return -ENOMEM;

        elf_version(EV_CURRENT);

        c.elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
        if (!c.elf)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, elf_begin() failed: %s", elf_errmsg(elf_errno()));

        c.dwfl = dwfl_begin(&callbacks);
        if (!c.dwfl)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, dwfl_begin() failed: %s", dwfl_errmsg(dwfl_errno()));

        if (dwfl_core_file_report(c.dwfl, c.elf, executable) < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, dwfl_core_file_report() failed: %s", dwfl_errmsg(dwfl_errno()));

        if (dwfl_report_end(c.dwfl, NULL, NULL) != 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, dwfl_report_end() failed: %s", dwfl_errmsg(dwfl_errno()));

        if (dwfl_getmodules(c.dwfl, &module_callback, &c, 0) < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, dwfl_getmodules() failed: %s", dwfl_errmsg(dwfl_errno()));

        if (dwfl_core_file_attach(c.dwfl, c.elf) < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, dwfl_core_file_attach() failed: %s", dwfl_errmsg(dwfl_errno()));

        if (dwfl_getthreads(c.dwfl, thread_callback, &c) < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, dwfl_getthreads() failed: %s", dwfl_errmsg(dwfl_errno()));

        r = fflush_and_check(c.f);
        if (r < 0)
                return log_warning_errno(r, "Could not parse core file, flushing file buffer failed: %m");

        c.f = safe_fclose(c.f);
        *ret = TAKE_PTR(buf);
        if (ret_package_metadata)
                *ret_package_metadata = TAKE_PTR(package_metadata);

        return 0;
}

int parse_elf_object(int fd, const char *executable, bool fork_disable_dump, char **ret, JsonVariant **ret_package_metadata) {
        _cleanup_close_pair_ int error_pipe[2] = { -1, -1 }, return_pipe[2] = { -1, -1 }, json_pipe[2] = { -1, -1 };
        _cleanup_(json_variant_unrefp) JsonVariant *package_metadata = NULL;
        _cleanup_free_ char *buf = NULL;
        int r;

        r = RET_NERRNO(pipe2(error_pipe, O_CLOEXEC|O_NONBLOCK));
        if (r < 0)
                return r;

        if (ret) {
                r = RET_NERRNO(pipe2(return_pipe, O_CLOEXEC));
                if (r < 0)
                        return r;
        }

        if (ret_package_metadata) {
                r = RET_NERRNO(pipe2(json_pipe, O_CLOEXEC));
                if (r < 0)
                        return r;
        }

        /* Parsing possibly malformed data is crash-happy, so fork. In case we crash,
         * the core file will not be lost, and the messages will still be attached to
         * the journal. Reading the elf object might be slow, but it still has an upper
         * bound since the core files have an upper size limit. It's also not doing any
         * system call or interacting with the system in any way, besides reading from
         * the file descriptor and writing into these four pipes. */
        r = safe_fork_full("(sd-parse-elf)",
                           (int[]){ fd, error_pipe[1], return_pipe[1], json_pipe[1] },
                           4,
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE|FORK_NEW_USERNS|FORK_WAIT|FORK_REOPEN_LOG,
                           NULL);
        if (r < 0) {
                if (r == -EPROTO) { /* We should have the errno from the child, but don't clobber original error */
                        int e, k;

                        k = read(error_pipe[0], &e, sizeof(e));
                        if (k < 0 && errno != EAGAIN) /* Pipe is non-blocking, EAGAIN means there's nothing */
                                return -errno;
                        if (k == sizeof(e))
                                return e; /* propagate error sent to us from child */
                        if (k != 0)
                                return -EIO;
                }

                return r;
        }
        if (r == 0) {
                /* We want to avoid loops, given this can be called from systemd-coredump */
                if (fork_disable_dump)
                        prctl(PR_SET_DUMPABLE, 0);

                r = parse_core(fd, executable, ret ? &buf : NULL, ret_package_metadata ? &package_metadata : NULL);
                if (r < 0)
                        goto child_fail;

                if (buf) {
                        r = loop_write(return_pipe[1], buf, strlen(buf), false);
                        if (r < 0)
                                goto child_fail;

                        return_pipe[1] = safe_close(return_pipe[1]);
                }

                if (package_metadata) {
                        _cleanup_fclose_ FILE *json_out = NULL;

                        json_out = take_fdopen(&json_pipe[1], "w");
                        if (!json_out) {
                                r = -errno;
                                goto child_fail;
                        }

                        json_variant_dump(package_metadata, JSON_FORMAT_FLUSH, json_out, NULL);
                }

                _exit(EXIT_SUCCESS);

        child_fail:
                (void) write(error_pipe[1], &r, sizeof(r));
                _exit(EXIT_FAILURE);
        }

        error_pipe[1] = safe_close(error_pipe[1]);
        return_pipe[1] = safe_close(return_pipe[1]);
        json_pipe[1] = safe_close(json_pipe[1]);

        if (ret) {
                _cleanup_fclose_ FILE *in = NULL;

                in = take_fdopen(&return_pipe[0], "r");
                if (!in)
                        return -errno;

                r = read_full_stream(in, &buf, NULL);
                if (r < 0)
                        return r;
        }

        if (ret_package_metadata) {
                _cleanup_fclose_ FILE *json_in = NULL;

                json_in = take_fdopen(&json_pipe[0], "r");
                if (!json_in)
                        return -errno;

                r = json_parse_file(json_in, NULL, 0, &package_metadata, NULL, NULL);
                if (r < 0 && r != -EINVAL) /* EINVAL: json was empty, so we got nothing, but that's ok */
                        return r;
        }

        if (ret)
                *ret = TAKE_PTR(buf);
        if (ret_package_metadata)
                *ret_package_metadata = TAKE_PTR(package_metadata);

        return 0;
}
