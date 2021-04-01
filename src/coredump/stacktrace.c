/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dwarf.h>
#include <elfutils/libdwelf.h>
#include <elfutils/libdwfl.h>
#include <libelf.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fileio.h"
#include "fd-util.h"
#include "format-util.h"
#include "hexdecoct.h"
#include "macro.h"
#include "stacktrace.h"
#include "string-util.h"
#include "util.h"

#define FRAMES_MAX 64
#define THREADS_MAX 64
#define ELF_PACKAGE_METADATA_ID 0xcafe1a7e

struct stack_context {
        FILE *f;
        Dwfl *dwfl;
        Elf *elf;
        unsigned n_thread;
        unsigned n_frame;
        Hashmap **package_metadata;
};

static int frame_callback(Dwfl_Frame *frame, void *userdata) {
        struct stack_context *c = userdata;
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
                        for (s = scopes; s < scopes + n; s++) {
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
        struct stack_context *c = userdata;
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

static int parse_package_metadata(const char *name, JsonVariant *id_json, Elf *elf, struct stack_context *c) {
        size_t n_program_headers;
        int r;

        assert(name);
        assert(elf);
        assert(c);

        /* When iterating over PT_LOAD we will visit modules more than once */
        if (hashmap_contains(*c->package_metadata, name))
                return DWARF_CB_OK;

        r = elf_getphdrnum(elf, &n_program_headers);
        if (r < 0) /* Not the handle we are looking for - that's ok, skip it */
                return DWARF_CB_OK;

        /* Iterate over all program headers in that ELF object. These will have been copied by
         * the kernel verbatim when the core file is generated. */
        for (size_t i = 0; i < n_program_headers; ++i) {
                size_t note_offset = 0, name_offset, desc_offset;
                GElf_Phdr mem, *program_header;
                GElf_Nhdr note_header;
                Elf_Data *data;

                /* Package metadata is in PT_NOTE headers */
                program_header = gelf_getphdr(elf, i, &mem);
                if (!program_header || program_header->p_type != PT_NOTE)
                        continue;

                /* Fortunately there is an iterator we can use to walk over the
                 * elements of a PT_NOTE program header. We are interested in the
                 * note with type*/
                data = elf_getdata_rawchunk(elf,
                                            program_header->p_offset,
                                            program_header->p_filesz,
                                            ELF_T_NHDR);

                while (note_offset < data->d_size &&
                       (note_offset = gelf_getnote(data, note_offset, &note_header, &name_offset, &desc_offset)) > 0) {
                        const char *note_name = (const char *)data->d_buf + name_offset;
                        const char *payload = (const char *)data->d_buf + desc_offset;

                        if (note_header.n_namesz == 0 || note_header.n_descsz == 0)
                                continue;

                        /* Package metadata might have different owners, but the
                         * magic ID is always the same. */
                        if (note_header.n_type == ELF_PACKAGE_METADATA_ID) {
                                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
                                _cleanup_free_ char *name_key = NULL;

                                r = json_parse(payload, 0, &v, NULL, NULL);
                                if (r < 0) {
                                        log_error_errno(r, "json_parse on %s failed: %m", payload);
                                        return DWARF_CB_ABORT;
                                }

                                /* First pretty-print to the buffer, so that the metadata goes as
                                 * plaintext in the journal*/
                                fprintf(c->f, "Metadata for module %s owned by %s found: ",
                                        name, note_name);
                                json_variant_dump(v, JSON_FORMAT_NEWLINE|JSON_FORMAT_PRETTY, c->f, NULL);
                                fputc('\n', c->f);

                                if (id_json) {
                                        r = json_variant_merge(&v, id_json);
                                        if (r < 0) {
                                                log_error_errno(r, "json_variant_merge of package meta with buildid failed: %m");
                                                return DWARF_CB_ABORT;
                                        }
                                }

                                /* Then stash it away, so that we can do structured logging */
                                name_key = strdup(name);
                                if (!name_key) {
                                        log_oom();
                                        return DWARF_CB_ABORT;
                                }
                                r = hashmap_put(*c->package_metadata, name_key, v);
                                if (r < 0) {
                                        log_error_errno(r, "hashmap_put failed: %m");
                                        return DWARF_CB_ABORT;
                                }
                                TAKE_PTR(v);
                                TAKE_PTR(name_key);

                                return DWARF_CB_OK;
                        }
                }
        }

        /* Didn't find package metadata for this module - that's ok, just go to the next */
        return DWARF_CB_OK;
}

static int module_callback(Dwfl_Module *mod, void **userdata, const char *name, Dwarf_Addr start, void *arg) {
        _cleanup_(json_variant_unrefp) JsonVariant *id_json = NULL;
        struct stack_context *c = arg;
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
        if (id_len <= 0) {
                /* If we don't find a build-id, note it in the journal message, and try
                 * anyway to find the package metadata. It's unlikely to have the latter
                 * without the former, but there's no hard rule. */
                fprintf(c->f, "Found module %s without build-id\n", name);
        } else {
                _cleanup_free_ char *id_hex = NULL, *id_hex_prefixed = NULL;

                id_hex = hexmem(id, id_len);
                if (!id_hex) {
                        log_oom();
                        return DWARF_CB_ABORT;
                }

                fprintf(c->f, "Found module %s with build-id: %s\n", name, id_hex);

                /* We will later parse package metadata json and pass it to our caller. Prepare the
                * build-id in json format too, so that it can be appended and parsed cleanly. It
                * will then be added as metadata to the journal message with the stack trace. */
                id_hex_prefixed = strjoin("{\"buildid\":\"", id_hex, "\"}");
                if (!id_hex_prefixed) {
                        log_oom();
                        return DWARF_CB_ABORT;
                }
                r = json_parse(id_hex_prefixed, 0, &id_json, NULL, NULL);
                if (r < 0) {
                        log_error_errno(r, "json_parse on %s failed: %m", id_hex_prefixed);
                        return DWARF_CB_ABORT;
                }
        }

        /* The .note.package metadata is more difficult. From the module, we need to get a reference
         * to the ELF object first. We might be lucky and just get it from elfutils. */
        elf = dwfl_module_getelf(mod, &bias);
        if (elf)
                return parse_package_metadata(name, id_json, elf, c);

        /* We did not get the ELF object. That is likely because we didn't get direct
         * access to the executable, and the version of elfutils does not yet support
         * parsing it out of the core file directly.
         * So fallback to manual extraction - get the PT_LOAD section from the core,
         * and if it's the right one we can interpret it as an Elf object, and parse
         * its notes manually. */

        r = elf_getphdrnum(c->elf, &n_program_headers);
        if (r < 0) {
                log_warning("Could not parse number of program headers from core file: %s",
                            elf_errmsg(-1)); /* -1 retrieves the most recent error */
                return DWARF_CB_OK;
        }

        for (size_t i = 0; i < n_program_headers; ++i) {
                GElf_Phdr mem, *program_header;
                Elf_Data *data;

                /* The core file stores the ELF files in the PT_LOAD segment .*/
                program_header = gelf_getphdr(c->elf, i, &mem);
                if (!program_header || program_header->p_type != PT_LOAD)
                        continue;

                /* Now get a usable Elf reference, and parse the notes from it. */
                data = elf_getdata_rawchunk(c->elf,
                                            program_header->p_offset,
                                            program_header->p_filesz,
                                            ELF_T_NHDR);

                Elf *memelf = elf_memory(data->d_buf, data->d_size);
                if (!memelf)
                        continue;
                r = parse_package_metadata(name, id_json, memelf, c);
                if (r != DWARF_CB_OK)
                        return r;
        }

        return DWARF_CB_OK;
}

static int parse_core(int fd, const char *executable, char **ret, Hashmap **ret_package_metadata) {

        static const Dwfl_Callbacks callbacks = {
                .find_elf = dwfl_build_id_find_elf,
                .section_address = dwfl_offline_section_address,
                .find_debuginfo = dwfl_standard_find_debuginfo,
        };

        _cleanup_(json_variant_hashmap_freep) Hashmap *package_metadata = NULL;
        struct stack_context c = {
                .package_metadata = &package_metadata,
        };
        char *buf = NULL;
        size_t sz = 0;
        int r;

        assert(fd >= 0);
        assert(ret);

        package_metadata = hashmap_new(&string_hash_ops);
        if (!package_metadata)
                return -ENOMEM;

        if (lseek(fd, 0, SEEK_SET) == (off_t) -1)
                return -errno;

        c.f = open_memstream_unlocked(&buf, &sz);
        if (!c.f)
                return -ENOMEM;

        elf_version(EV_CURRENT);

        c.elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
        if (!c.elf) {
                r = -EINVAL;
                goto finish;
        }

        c.dwfl = dwfl_begin(&callbacks);
        if (!c.dwfl) {
                r = -EINVAL;
                goto finish;
        }

        if (dwfl_core_file_report(c.dwfl, c.elf, executable) < 0) {
                r = -EINVAL;
                goto finish;
        }

        if (dwfl_report_end(c.dwfl, NULL, NULL) != 0) {
                r = -EINVAL;
                goto finish;
        }

        if (dwfl_getmodules(c.dwfl, &module_callback, &c, 0) < 0) {
                r = -EINVAL;
                goto finish;
        }

        if (dwfl_core_file_attach(c.dwfl, c.elf) < 0) {
                r = -EINVAL;
                goto finish;
        }

        if (dwfl_getthreads(c.dwfl, thread_callback, &c) < 0) {
                r = -EINVAL;
                goto finish;
        }

        c.f = safe_fclose(c.f);

        *ret = TAKE_PTR(buf);
        if (ret_package_metadata)
                *ret_package_metadata = TAKE_PTR(package_metadata);

        r = 0;

finish:
        if (c.dwfl)
                dwfl_end(c.dwfl);

        if (c.elf)
                elf_end(c.elf);

        safe_fclose(c.f);

        free(buf);

        return r;
}

void coredump_parse_core(int fd, const char *executable, char **ret, Hashmap **ret_package_metadata) {
        int r;

        r = parse_core(fd, executable, ret, ret_package_metadata);
        if (r == -EINVAL)
                log_warning("Failed to generate stack trace: %s", dwfl_errmsg(dwfl_errno()));
        else if (r < 0)
                log_warning_errno(r, "Failed to generate stack trace: %m");
}
