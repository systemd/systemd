/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Steven Hiscocks, Zbigniew Jędrzejewski-Szmek

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

#include <Python.h>
#include <structmember.h>
#include <datetime.h>
#include <time.h>
#include <stdio.h>

#include <systemd/sd-journal.h>

#include "pyutil.h"
#include "macro.h"
#include "util.h"
#include "strv.h"
#include "build.h"

typedef struct {
        PyObject_HEAD
        sd_journal *j;
} Reader;
static PyTypeObject ReaderType;

PyDoc_STRVAR(module__doc__,
             "Class to reads the systemd journal similar to journalctl.");


#if PY_MAJOR_VERSION >= 3
static PyTypeObject MonotonicType;

PyDoc_STRVAR(MonotonicType__doc__,
             "A tuple of (timestamp, bootid) for holding monotonic timestamps");

static PyStructSequence_Field MonotonicType_fields[] = {
        {(char*) "timestamp", (char*) "Time"},
        {(char*) "bootid", (char*) "Unique identifier of the boot"},
        {} /* Sentinel */
};

static PyStructSequence_Desc Monotonic_desc = {
        (char*) "journal.Monotonic",
        MonotonicType__doc__,
        MonotonicType_fields,
        2,
};
#endif

/**
 * Convert a Python sequence object into a strv (char**), and
 * None into a NULL pointer.
 */
static int strv_converter(PyObject* obj, void *_result) {
        char ***result = _result;
        Py_ssize_t i, len;

        assert(result);

        if (!obj)
                return 0;

        if (obj == Py_None) {
                *result = NULL;
                return 1;
        }

        if (!PySequence_Check(obj))
                return 0;

        len = PySequence_Length(obj);
        *result = new0(char*, len + 1);
        if (!*result) {
                set_error(-ENOMEM, NULL, NULL);
                return 0;
        }

        for (i = 0; i < len; i++) {
                PyObject *item;
#if PY_MAJOR_VERSION >=3 && PY_MINOR_VERSION >= 1
                int r;
                PyObject *bytes;
#endif
                char *s, *s2;

                item = PySequence_ITEM(obj, i);
#if PY_MAJOR_VERSION >=3 && PY_MINOR_VERSION >= 1
                r = PyUnicode_FSConverter(item, &bytes);
                if (r == 0)
                        goto cleanup;

                s = PyBytes_AsString(bytes);
#else
                s = PyString_AsString(item);
#endif
                if (!s)
                        goto cleanup;

                s2 = strdup(s);
                if (!s2)
                        log_oom();

                (*result)[i] = s2;
        }

        return 1;

cleanup:
        strv_free(*result);
        *result = NULL;

        return 0;
}

static void Reader_dealloc(Reader* self) {
        sd_journal_close(self->j);
        Py_TYPE(self)->tp_free((PyObject*)self);
}

PyDoc_STRVAR(Reader__doc__,
             "_Reader([flags | path | files]) -> ...\n\n"
             "_Reader allows filtering and retrieval of Journal entries.\n"
             "Note: this is a low-level interface, and probably not what you\n"
             "want, use systemd.journal.Reader instead.\n\n"
             "Argument `flags` sets open flags of the journal, which can be one\n"
             "of, or ORed combination of constants: LOCAL_ONLY (default) opens\n"
             "journal on local machine only; RUNTIME_ONLY opens only\n"
             "volatile journal files; and SYSTEM opens journal files of\n"
             "system services and the kernel, and CURRENT_USER opens files\n"
             "of the current user.\n\n"
             "Argument `path` is the directory of journal files.\n"
             "Argument `files` is a list of files. Note that\n"
             "`flags`, `path`, and `files` are exclusive.\n\n"
             "_Reader implements the context manager protocol: the journal\n"
             "will be closed when exiting the block.");
static int Reader_init(Reader *self, PyObject *args, PyObject *keywds) {
        int flags = 0, r;
        char *path = NULL;
        char **files = NULL;

        static const char* const kwlist[] = {"flags", "path", "files", NULL};
        if (!PyArg_ParseTupleAndKeywords(args, keywds, "|izO&:__init__", (char**) kwlist,
                                         &flags, &path, strv_converter, &files))
                return -1;

        if (!!flags + !!path + !!files > 1) {
                PyErr_SetString(PyExc_ValueError, "cannot use more than one of flags, path, and files");
                return -1;
        }

        if (!flags)
                flags = SD_JOURNAL_LOCAL_ONLY;

        Py_BEGIN_ALLOW_THREADS
        if (path)
                r = sd_journal_open_directory(&self->j, path, 0);
        else if (files)
                r = sd_journal_open_files(&self->j, (const char**) files, 0);
        else
                r = sd_journal_open(&self->j, flags);
        Py_END_ALLOW_THREADS

        return set_error(r, path, "Invalid flags or path");
}

PyDoc_STRVAR(Reader_fileno__doc__,
             "fileno() -> int\n\n"
             "Get a file descriptor to poll for changes in the journal.\n"
             "This method invokes sd_journal_get_fd().\n"
             "See man:sd_journal_get_fd(3).");
static PyObject* Reader_fileno(Reader *self, PyObject *args) {
        int fd;

        fd = sd_journal_get_fd(self->j);
        set_error(fd, NULL, NULL);
        if (fd < 0)
                return NULL;
        return long_FromLong(fd);
}

PyDoc_STRVAR(Reader_reliable_fd__doc__,
             "reliable_fd() -> bool\n\n"
             "Returns True iff the journal can be polled reliably.\n"
             "This method invokes sd_journal_reliable_fd().\n"
             "See man:sd_journal_reliable_fd(3).");
static PyObject* Reader_reliable_fd(Reader *self, PyObject *args) {
        int r;

        r = sd_journal_reliable_fd(self->j);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;
        return PyBool_FromLong(r);
}

PyDoc_STRVAR(Reader_get_events__doc__,
             "get_events() -> int\n\n"
             "Returns a mask of poll() events to wait for on the file\n"
             "descriptor returned by .fileno().\n\n"
             "See man:sd_journal_get_events(3) for further discussion.");
static PyObject* Reader_get_events(Reader *self, PyObject *args) {
        int r;

        r = sd_journal_get_events(self->j);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;
        return long_FromLong(r);
}

PyDoc_STRVAR(Reader_get_timeout__doc__,
             "get_timeout() -> int or None\n\n"
             "Returns a timeout value for usage in poll(), the time since the\n"
             "epoch of clock_gettime(2) in microseconds, or None if no timeout\n"
             "is necessary.\n\n"
             "The return value must be converted to a relative timeout in\n"
             "milliseconds if it is to be used as an argument for poll().\n"
             "See man:sd_journal_get_timeout(3) for further discussion.");
static PyObject* Reader_get_timeout(Reader *self, PyObject *args) {
        int r;
        uint64_t t;

        r = sd_journal_get_timeout(self->j, &t);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        if (t == (uint64_t) -1)
                Py_RETURN_NONE;

        assert_cc(sizeof(unsigned long long) == sizeof(t));
        return PyLong_FromUnsignedLongLong(t);
}

PyDoc_STRVAR(Reader_get_timeout_ms__doc__,
             "get_timeout_ms() -> int\n\n"
             "Returns a timeout value suitable for usage in poll(), the value\n"
             "returned by .get_timeout() converted to relative ms, or -1 if\n"
             "no timeout is necessary.");
static PyObject* Reader_get_timeout_ms(Reader *self, PyObject *args) {
        int r;
        uint64_t t;

        r = sd_journal_get_timeout(self->j, &t);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        return absolute_timeout(t);
}

PyDoc_STRVAR(Reader_close__doc__,
             "close() -> None\n\n"
             "Free resources allocated by this Reader object.\n"
             "This method invokes sd_journal_close().\n"
             "See man:sd_journal_close(3).");
static PyObject* Reader_close(Reader *self, PyObject *args) {
        assert(self);
        assert(!args);

        sd_journal_close(self->j);
        self->j = NULL;
        Py_RETURN_NONE;
}

PyDoc_STRVAR(Reader_get_usage__doc__,
             "get_usage() -> int\n\n"
             "Returns the total disk space currently used by journal\n"
             "files (in bytes). If `SD_JOURNAL_LOCAL_ONLY` was\n"
             "passed when opening the journal this value will only reflect\n"
             "the size of journal files of the local host, otherwise\n"
             "of all hosts.\n\n"
             "This method invokes sd_journal_get_usage().\n"
             "See man:sd_journal_get_usage(3).");
static PyObject* Reader_get_usage(Reader *self, PyObject *args) {
        int r;
        uint64_t bytes;

        r = sd_journal_get_usage(self->j, &bytes);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        assert_cc(sizeof(unsigned long long) == sizeof(bytes));
        return PyLong_FromUnsignedLongLong(bytes);
}

PyDoc_STRVAR(Reader___enter____doc__,
             "__enter__() -> self\n\n"
             "Part of the context manager protocol.\n"
             "Returns self.\n");
static PyObject* Reader___enter__(PyObject *self, PyObject *args) {
        assert(self);
        assert(!args);

        Py_INCREF(self);
        return self;
}

PyDoc_STRVAR(Reader___exit____doc__,
             "__exit__(type, value, traceback) -> None\n\n"
             "Part of the context manager protocol.\n"
             "Closes the journal.\n");
static PyObject* Reader___exit__(Reader *self, PyObject *args) {
        return Reader_close(self, args);
}

PyDoc_STRVAR(Reader_next__doc__,
             "next([skip]) -> bool\n\n"
             "Go to the next log entry. Optional skip value means to go to\n"
             "the `skip`\\-th log entry.\n"
             "Returns False if at end of file, True otherwise.");
static PyObject* Reader_next(Reader *self, PyObject *args) {
        int64_t skip = 1LL;
        int r;

        if (!PyArg_ParseTuple(args, "|L:next", &skip))
                return NULL;

        if (skip == 0LL) {
                PyErr_SetString(PyExc_ValueError, "skip must be nonzero");
                return NULL;
        }

        Py_BEGIN_ALLOW_THREADS
        if (skip == 1LL)
                r = sd_journal_next(self->j);
        else if (skip == -1LL)
                r = sd_journal_previous(self->j);
        else if (skip > 1LL)
                r = sd_journal_next_skip(self->j, skip);
        else if (skip < -1LL)
                r = sd_journal_previous_skip(self->j, -skip);
        else
                assert_not_reached("should not be here");
        Py_END_ALLOW_THREADS

        if (set_error(r, NULL, NULL) < 0)
                return NULL;
        return PyBool_FromLong(r);
}

PyDoc_STRVAR(Reader_previous__doc__,
             "previous([skip]) -> bool\n\n"
             "Go to the previous log entry. Optional skip value means to \n"
             "go to the `skip`\\-th previous log entry.\n"
             "Returns False if at start of file, True otherwise.");
static PyObject* Reader_previous(Reader *self, PyObject *args) {
        int64_t skip = 1LL;
        if (!PyArg_ParseTuple(args, "|L:previous", &skip))
                return NULL;

        return PyObject_CallMethod((PyObject *)self, (char*) "_next",
                                   (char*) "L", -skip);
}

static int extract(const char* msg, size_t msg_len,
                   PyObject **key, PyObject **value) {
        PyObject *k = NULL, *v;
        const char *delim_ptr;

        delim_ptr = memchr(msg, '=', msg_len);
        if (!delim_ptr) {
                PyErr_SetString(PyExc_OSError,
                                "journal gave us a field without '='");
                return -1;
        }

        if (key) {
                k = unicode_FromStringAndSize(msg, delim_ptr - (const char*) msg);
                if (!k)
                        return -1;
        }

        if (value) {
                v = PyBytes_FromStringAndSize(delim_ptr + 1,
                                              (const char*) msg + msg_len - (delim_ptr + 1));
                if (!v) {
                        Py_XDECREF(k);
                        return -1;
                }

                *value = v;
        }

        if (key)
                *key = k;

        return 0;
}

PyDoc_STRVAR(Reader_get__doc__,
             "get(str) -> str\n\n"
             "Return data associated with this key in current log entry.\n"
             "Throws KeyError is the data is not available.");
static PyObject* Reader_get(Reader *self, PyObject *args) {
        const char* field;
        const void* msg;
        size_t msg_len;
        PyObject *value;
        int r;

        assert(self);
        assert(args);

        if (!PyArg_ParseTuple(args, "s:get", &field))
                return NULL;

        r = sd_journal_get_data(self->j, field, &msg, &msg_len);
        if (r == -ENOENT) {
                PyErr_SetString(PyExc_KeyError, field);
                return NULL;
        }
        if (set_error(r, NULL, "field name is not valid") < 0)
                return NULL;

        r = extract(msg, msg_len, NULL, &value);
        if (r < 0)
                return NULL;
        return value;
}

PyDoc_STRVAR(Reader_get_all__doc__,
             "_get_all() -> dict\n\n"
             "Return dictionary of the current log entry.");
static PyObject* Reader_get_all(Reader *self, PyObject *args) {
        PyObject *dict;
        const void *msg;
        size_t msg_len;
        int r;

        dict = PyDict_New();
        if (!dict)
                return NULL;

        SD_JOURNAL_FOREACH_DATA(self->j, msg, msg_len) {
                _cleanup_Py_DECREF_ PyObject *key = NULL, *value = NULL;

                r = extract(msg, msg_len, &key, &value);
                if (r < 0)
                        goto error;

                if (PyDict_Contains(dict, key)) {
                        PyObject *cur_value = PyDict_GetItem(dict, key);

                        if (PyList_CheckExact(cur_value)) {
                                r = PyList_Append(cur_value, value);
                                if (r < 0)
                                        goto error;
                        } else {
                                _cleanup_Py_DECREF_ PyObject *tmp_list = PyList_New(0);
                                if (!tmp_list)
                                        goto error;

                                r = PyList_Append(tmp_list, cur_value);
                                if (r < 0)
                                        goto error;

                                r = PyList_Append(tmp_list, value);
                                if (r < 0)
                                        goto error;

                                r = PyDict_SetItem(dict, key, tmp_list);
                                if (r < 0)
                                        goto error;
                        }
                } else {
                        r = PyDict_SetItem(dict, key, value);
                        if (r < 0)
                                goto error;
                }
        }

        return dict;

error:
        Py_DECREF(dict);
        return NULL;
}

PyDoc_STRVAR(Reader_get_realtime__doc__,
             "get_realtime() -> int\n\n"
             "Return the realtime timestamp for the current journal entry\n"
             "in microseconds.\n\n"
             "Wraps sd_journal_get_realtime_usec().\n"
             "See man:sd_journal_get_realtime_usec(3).");
static PyObject* Reader_get_realtime(Reader *self, PyObject *args) {
        uint64_t timestamp;
        int r;

        assert(self);
        assert(!args);

        r = sd_journal_get_realtime_usec(self->j, &timestamp);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        assert_cc(sizeof(unsigned long long) == sizeof(timestamp));
        return PyLong_FromUnsignedLongLong(timestamp);
}

PyDoc_STRVAR(Reader_get_monotonic__doc__,
             "get_monotonic() -> (timestamp, bootid)\n\n"
             "Return the monotonic timestamp for the current journal entry\n"
             "as a tuple of time in microseconds and bootid.\n\n"
             "Wraps sd_journal_get_monotonic_usec().\n"
             "See man:sd_journal_get_monotonic_usec(3).");
static PyObject* Reader_get_monotonic(Reader *self, PyObject *args) {
        uint64_t timestamp;
        sd_id128_t id;
        PyObject *monotonic, *bootid, *tuple;
        int r;

        assert(self);
        assert(!args);

        r = sd_journal_get_monotonic_usec(self->j, &timestamp, &id);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        assert_cc(sizeof(unsigned long long) == sizeof(timestamp));
        monotonic = PyLong_FromUnsignedLongLong(timestamp);
        bootid = PyBytes_FromStringAndSize((const char*) &id.bytes, sizeof(id.bytes));
#if PY_MAJOR_VERSION >= 3
        tuple = PyStructSequence_New(&MonotonicType);
#else
        tuple = PyTuple_New(2);
#endif
        if (!monotonic || !bootid || !tuple) {
                Py_XDECREF(monotonic);
                Py_XDECREF(bootid);
                Py_XDECREF(tuple);
                return NULL;
        }

#if PY_MAJOR_VERSION >= 3
        PyStructSequence_SET_ITEM(tuple, 0, monotonic);
        PyStructSequence_SET_ITEM(tuple, 1, bootid);
#else
        PyTuple_SET_ITEM(tuple, 0, monotonic);
        PyTuple_SET_ITEM(tuple, 1, bootid);
#endif

        return tuple;
}

PyDoc_STRVAR(Reader_add_match__doc__,
             "add_match(match) -> None\n\n"
             "Add a match to filter journal log entries. All matches of different\n"
             "fields are combined with logical AND, and matches of the same field\n"
             "are automatically combined with logical OR.\n"
             "Match is a string of the form \"FIELD=value\".");
static PyObject* Reader_add_match(Reader *self, PyObject *args, PyObject *keywds) {
        char *match;
        int match_len, r;
        if (!PyArg_ParseTuple(args, "s#:add_match", &match, &match_len))
                return NULL;

        r = sd_journal_add_match(self->j, match, match_len);
        if (set_error(r, NULL, "Invalid match") < 0)
                return NULL;

        Py_RETURN_NONE;
}

PyDoc_STRVAR(Reader_add_disjunction__doc__,
             "add_disjunction() -> None\n\n"
             "Inserts a logical OR between matches added since previous\n"
             "add_disjunction() or add_conjunction() and the next\n"
             "add_disjunction() or add_conjunction().\n\n"
             "See man:sd_journal_add_disjunction(3) for explanation.");
static PyObject* Reader_add_disjunction(Reader *self, PyObject *args) {
        int r;
        r = sd_journal_add_disjunction(self->j);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;
        Py_RETURN_NONE;
}

PyDoc_STRVAR(Reader_add_conjunction__doc__,
             "add_conjunction() -> None\n\n"
             "Inserts a logical AND between matches added since previous\n"
             "add_disjunction() or add_conjunction() and the next\n"
             "add_disjunction() or add_conjunction().\n\n"
             "See man:sd_journal_add_disjunction(3) for explanation.");
static PyObject* Reader_add_conjunction(Reader *self, PyObject *args) {
        int r;
        r = sd_journal_add_conjunction(self->j);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;
        Py_RETURN_NONE;
}

PyDoc_STRVAR(Reader_flush_matches__doc__,
             "flush_matches() -> None\n\n"
             "Clear all current match filters.");
static PyObject* Reader_flush_matches(Reader *self, PyObject *args) {
        sd_journal_flush_matches(self->j);
        Py_RETURN_NONE;
}

PyDoc_STRVAR(Reader_seek_head__doc__,
             "seek_head() -> None\n\n"
             "Jump to the beginning of the journal.\n"
             "This method invokes sd_journal_seek_head().\n"
             "See man:sd_journal_seek_head(3).");
static PyObject* Reader_seek_head(Reader *self, PyObject *args) {
        int r;
        Py_BEGIN_ALLOW_THREADS
        r = sd_journal_seek_head(self->j);
        Py_END_ALLOW_THREADS

        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        Py_RETURN_NONE;
}

PyDoc_STRVAR(Reader_seek_tail__doc__,
             "seek_tail() -> None\n\n"
             "Jump to the end of the journal.\n"
             "This method invokes sd_journal_seek_tail().\n"
             "See man:sd_journal_seek_tail(3).");
static PyObject* Reader_seek_tail(Reader *self, PyObject *args) {
        int r;

        Py_BEGIN_ALLOW_THREADS
        r = sd_journal_seek_tail(self->j);
        Py_END_ALLOW_THREADS

        if (set_error(r, NULL, NULL) < 0)
                return NULL;
        Py_RETURN_NONE;
}

PyDoc_STRVAR(Reader_seek_realtime__doc__,
             "seek_realtime(realtime) -> None\n\n"
             "Seek to nearest matching journal entry to `realtime`. Argument\n"
             "`realtime` in specified in seconds.");
static PyObject* Reader_seek_realtime(Reader *self, PyObject *args) {
        uint64_t timestamp;
        int r;

        if (!PyArg_ParseTuple(args, "K:seek_realtime", &timestamp))
                return NULL;

        Py_BEGIN_ALLOW_THREADS
        r = sd_journal_seek_realtime_usec(self->j, timestamp);
        Py_END_ALLOW_THREADS

        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        Py_RETURN_NONE;
}

PyDoc_STRVAR(Reader_seek_monotonic__doc__,
             "seek_monotonic(monotonic[, bootid]) -> None\n\n"
             "Seek to nearest matching journal entry to `monotonic`. Argument\n"
             "`monotonic` is an timestamp from boot in microseconds.\n"
             "Argument `bootid` is a string representing which boot the\n"
             "monotonic time is reference to. Defaults to current bootid.");
static PyObject* Reader_seek_monotonic(Reader *self, PyObject *args) {
        char *bootid = NULL;
        uint64_t timestamp;
        sd_id128_t id;
        int r;

        if (!PyArg_ParseTuple(args, "K|z:seek_monotonic", &timestamp, &bootid))
                return NULL;

        if (bootid) {
                r = sd_id128_from_string(bootid, &id);
                if (set_error(r, NULL, "Invalid bootid") < 0)
                        return NULL;
        } else {
                Py_BEGIN_ALLOW_THREADS
                r = sd_id128_get_boot(&id);
                Py_END_ALLOW_THREADS

                if (set_error(r, NULL, NULL) < 0)
                        return NULL;
        }

        Py_BEGIN_ALLOW_THREADS
        r = sd_journal_seek_monotonic_usec(self->j, id, timestamp);
        Py_END_ALLOW_THREADS

        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        Py_RETURN_NONE;
}


PyDoc_STRVAR(Reader_process__doc__,
             "process() -> state change (integer)\n\n"
             "Process events and reset the readable state of the file\n"
             "descriptor returned by .fileno().\n\n"
             "Will return constants: NOP if no change; APPEND if new\n"
             "entries have been added to the end of the journal; and\n"
             "INVALIDATE if journal files have been added or removed.\n\n"
             "See man:sd_journal_process(3) for further discussion.");
static PyObject* Reader_process(Reader *self, PyObject *args) {
        int r;

        assert(!args);

        Py_BEGIN_ALLOW_THREADS
        r = sd_journal_process(self->j);
        Py_END_ALLOW_THREADS
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        return long_FromLong(r);
}

PyDoc_STRVAR(Reader_wait__doc__,
             "wait([timeout]) -> state change (integer)\n\n"
             "Wait for a change in the journal. Argument `timeout` specifies\n"
             "the maximum number of microseconds to wait before returning\n"
             "regardless of wheter the journal has changed. If `timeout` is -1,\n"
             "then block forever.\n\n"
             "Will return constants: NOP if no change; APPEND if new\n"
             "entries have been added to the end of the journal; and\n"
             "INVALIDATE if journal files have been added or removed.\n\n"
             "See man:sd_journal_wait(3) for further discussion.");
static PyObject* Reader_wait(Reader *self, PyObject *args) {
        int r;
        int64_t timeout;

        if (!PyArg_ParseTuple(args, "|L:wait", &timeout))
                return NULL;

        Py_BEGIN_ALLOW_THREADS
        r = sd_journal_wait(self->j, timeout);
        Py_END_ALLOW_THREADS

        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        return long_FromLong(r);
}

PyDoc_STRVAR(Reader_seek_cursor__doc__,
             "seek_cursor(cursor) -> None\n\n"
             "Seek to journal entry by given unique reference `cursor`.");
static PyObject* Reader_seek_cursor(Reader *self, PyObject *args) {
        const char *cursor;
        int r;

        if (!PyArg_ParseTuple(args, "s:seek_cursor", &cursor))
                return NULL;

        Py_BEGIN_ALLOW_THREADS
        r = sd_journal_seek_cursor(self->j, cursor);
        Py_END_ALLOW_THREADS

        if (set_error(r, NULL, "Invalid cursor") < 0)
                return NULL;

        Py_RETURN_NONE;
}

PyDoc_STRVAR(Reader_get_cursor__doc__,
             "get_cursor() -> str\n\n"
             "Return a cursor string for the current journal entry.\n\n"
             "Wraps sd_journal_get_cursor(). See man:sd_journal_get_cursor(3).");
static PyObject* Reader_get_cursor(Reader *self, PyObject *args) {
        _cleanup_free_ char *cursor = NULL;
        int r;

        assert(self);
        assert(!args);

        r = sd_journal_get_cursor(self->j, &cursor);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        return unicode_FromString(cursor);
}

PyDoc_STRVAR(Reader_test_cursor__doc__,
             "test_cursor(str) -> bool\n\n"
             "Test whether the cursor string matches current journal entry.\n\n"
             "Wraps sd_journal_test_cursor(). See man:sd_journal_test_cursor(3).");
static PyObject* Reader_test_cursor(Reader *self, PyObject *args) {
        const char *cursor;
        int r;

        assert(self);
        assert(args);

        if (!PyArg_ParseTuple(args, "s:test_cursor", &cursor))
                return NULL;

        r = sd_journal_test_cursor(self->j, cursor);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        return PyBool_FromLong(r);
}

PyDoc_STRVAR(Reader_query_unique__doc__,
             "query_unique(field) -> a set of values\n\n"
             "Return a set of unique values appearing in journal for the\n"
             "given `field`. Note this does not respect any journal matches.");
static PyObject* Reader_query_unique(Reader *self, PyObject *args) {
        char *query;
        int r;
        const void *uniq;
        size_t uniq_len;
        PyObject *value_set, *key, *value;

        if (!PyArg_ParseTuple(args, "s:query_unique", &query))
                return NULL;

        Py_BEGIN_ALLOW_THREADS
        r = sd_journal_query_unique(self->j, query);
        Py_END_ALLOW_THREADS

        if (set_error(r, NULL, "Invalid field name") < 0)
                return NULL;

        value_set = PySet_New(0);
        key = unicode_FromString(query);

        SD_JOURNAL_FOREACH_UNIQUE(self->j, uniq, uniq_len) {
                const char *delim_ptr;

                delim_ptr = memchr(uniq, '=', uniq_len);
                value = PyBytes_FromStringAndSize(
                                delim_ptr + 1,
                                (const char*) uniq + uniq_len - (delim_ptr + 1));
                PySet_Add(value_set, value);
                Py_DECREF(value);
        }

        Py_DECREF(key);
        return value_set;
}

PyDoc_STRVAR(Reader_get_catalog__doc__,
             "get_catalog() -> str\n\n"
             "Retrieve a message catalog entry for the current journal entry.\n"
             "Will throw IndexError if the entry has no MESSAGE_ID\n"
             "and KeyError is the id is specified, but hasn't been found\n"
             "in the catalog.\n\n"
             "Wraps man:sd_journal_get_catalog(3).");
static PyObject* Reader_get_catalog(Reader *self, PyObject *args) {
        int r;
        _cleanup_free_ char *msg = NULL;

        assert(self);
        assert(!args);

        Py_BEGIN_ALLOW_THREADS
        r = sd_journal_get_catalog(self->j, &msg);
        Py_END_ALLOW_THREADS

        if (r == -ENOENT) {
                const void* mid;
                size_t mid_len;

                r = sd_journal_get_data(self->j, "MESSAGE_ID", &mid, &mid_len);
                if (r == 0) {
                        const size_t l = sizeof("MESSAGE_ID");
                        assert(mid_len > l);
                        PyErr_Format(PyExc_KeyError, "%.*s", (int) (mid_len - l),
                                     (const char*) mid + l);
                } else if (r == -ENOENT)
                        PyErr_SetString(PyExc_IndexError, "no MESSAGE_ID field");
                else
                        set_error(r, NULL, NULL);
                return NULL;
        }

        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        return unicode_FromString(msg);
}

PyDoc_STRVAR(get_catalog__doc__,
             "get_catalog(id128) -> str\n\n"
             "Retrieve a message catalog entry for the given id.\n"
             "Wraps man:sd_journal_get_catalog_for_message_id(3).");
static PyObject* get_catalog(PyObject *self, PyObject *args) {
        int r;
        char *id_ = NULL;
        sd_id128_t id;
        _cleanup_free_ char *msg = NULL;

        assert(args);

        if (!PyArg_ParseTuple(args, "z:get_catalog", &id_))
                return NULL;

        r = sd_id128_from_string(id_, &id);
        if (set_error(r, NULL, "Invalid id128") < 0)
                return NULL;

        Py_BEGIN_ALLOW_THREADS
        r = sd_journal_get_catalog_for_message_id(id, &msg);
        Py_END_ALLOW_THREADS

        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        return unicode_FromString(msg);
}

PyDoc_STRVAR(data_threshold__doc__,
             "Threshold for field size truncation in bytes.\n\n"
             "Fields longer than this will be truncated to the threshold size.\n"
             "Defaults to 64Kb.");

static PyObject* Reader_get_data_threshold(Reader *self, void *closure) {
        size_t cvalue;
        int r;

        r = sd_journal_get_data_threshold(self->j, &cvalue);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        return long_FromSize_t(cvalue);
}

static int Reader_set_data_threshold(Reader *self, PyObject *value, void *closure) {
        int r;

        if (value == NULL) {
                PyErr_SetString(PyExc_AttributeError, "Cannot delete data threshold");
                return -1;
        }

        if (!long_Check(value)){
                PyErr_SetString(PyExc_TypeError, "Data threshold must be an int");
                return -1;
        }

        r = sd_journal_set_data_threshold(self->j, (size_t) long_AsLong(value));
        return set_error(r, NULL, NULL);
}

PyDoc_STRVAR(closed__doc__,
             "True iff journal is closed");
static PyObject* Reader_get_closed(Reader *self, void *closure) {
        return PyBool_FromLong(self->j == NULL);
}

static PyGetSetDef Reader_getsetters[] = {
        { (char*) "data_threshold",
          (getter) Reader_get_data_threshold,
          (setter) Reader_set_data_threshold,
          (char*) data_threshold__doc__,
          NULL },
        { (char*) "closed",
          (getter) Reader_get_closed,
          NULL,
          (char*) closed__doc__,
          NULL },
        {} /* Sentinel */
};

static PyMethodDef Reader_methods[] = {
        {"fileno",          (PyCFunction) Reader_fileno, METH_NOARGS, Reader_fileno__doc__},
        {"reliable_fd",     (PyCFunction) Reader_reliable_fd, METH_NOARGS, Reader_reliable_fd__doc__},
        {"get_events",      (PyCFunction) Reader_get_events, METH_NOARGS, Reader_get_events__doc__},
        {"get_timeout",     (PyCFunction) Reader_get_timeout, METH_NOARGS, Reader_get_timeout__doc__},
        {"get_timeout_ms",  (PyCFunction) Reader_get_timeout_ms, METH_NOARGS, Reader_get_timeout_ms__doc__},
        {"close",           (PyCFunction) Reader_close, METH_NOARGS, Reader_close__doc__},
        {"get_usage",       (PyCFunction) Reader_get_usage, METH_NOARGS, Reader_get_usage__doc__},
        {"__enter__",       (PyCFunction) Reader___enter__, METH_NOARGS, Reader___enter____doc__},
        {"__exit__",        (PyCFunction) Reader___exit__, METH_VARARGS, Reader___exit____doc__},
        {"_next",           (PyCFunction) Reader_next, METH_VARARGS, Reader_next__doc__},
        {"_previous",       (PyCFunction) Reader_previous, METH_VARARGS, Reader_previous__doc__},
        {"_get",            (PyCFunction) Reader_get, METH_VARARGS, Reader_get__doc__},
        {"_get_all",        (PyCFunction) Reader_get_all, METH_NOARGS, Reader_get_all__doc__},
        {"_get_realtime",   (PyCFunction) Reader_get_realtime, METH_NOARGS, Reader_get_realtime__doc__},
        {"_get_monotonic",  (PyCFunction) Reader_get_monotonic, METH_NOARGS, Reader_get_monotonic__doc__},
        {"add_match",       (PyCFunction) Reader_add_match, METH_VARARGS|METH_KEYWORDS, Reader_add_match__doc__},
        {"add_disjunction", (PyCFunction) Reader_add_disjunction, METH_NOARGS, Reader_add_disjunction__doc__},
        {"add_conjunction", (PyCFunction) Reader_add_conjunction, METH_NOARGS, Reader_add_conjunction__doc__},
        {"flush_matches",   (PyCFunction) Reader_flush_matches, METH_NOARGS, Reader_flush_matches__doc__},
        {"seek_head",       (PyCFunction) Reader_seek_head, METH_NOARGS, Reader_seek_head__doc__},
        {"seek_tail",       (PyCFunction) Reader_seek_tail, METH_NOARGS, Reader_seek_tail__doc__},
        {"seek_realtime",   (PyCFunction) Reader_seek_realtime, METH_VARARGS, Reader_seek_realtime__doc__},
        {"seek_monotonic",  (PyCFunction) Reader_seek_monotonic, METH_VARARGS, Reader_seek_monotonic__doc__},
        {"process",         (PyCFunction) Reader_process, METH_NOARGS, Reader_process__doc__},
        {"wait",            (PyCFunction) Reader_wait, METH_VARARGS, Reader_wait__doc__},
        {"seek_cursor",     (PyCFunction) Reader_seek_cursor, METH_VARARGS, Reader_seek_cursor__doc__},
        {"_get_cursor",     (PyCFunction) Reader_get_cursor, METH_NOARGS, Reader_get_cursor__doc__},
        {"test_cursor",     (PyCFunction) Reader_test_cursor, METH_VARARGS, Reader_test_cursor__doc__},
        {"query_unique",    (PyCFunction) Reader_query_unique, METH_VARARGS, Reader_query_unique__doc__},
        {"get_catalog",     (PyCFunction) Reader_get_catalog, METH_NOARGS, Reader_get_catalog__doc__},
        {}  /* Sentinel */
};

static PyTypeObject ReaderType = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name = "_reader._Reader",
        .tp_basicsize = sizeof(Reader),
        .tp_dealloc = (destructor) Reader_dealloc,
        .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
        .tp_doc = Reader__doc__,
        .tp_methods = Reader_methods,
        .tp_getset = Reader_getsetters,
        .tp_init = (initproc) Reader_init,
        .tp_new = PyType_GenericNew,
};

static PyMethodDef methods[] = {
        { "_get_catalog", get_catalog, METH_VARARGS, get_catalog__doc__},
        {} /* Sentinel */
};

#if PY_MAJOR_VERSION >= 3
static PyModuleDef module = {
        PyModuleDef_HEAD_INIT,
        "_reader",
        module__doc__,
        -1,
        methods,
};
#endif

#if PY_MAJOR_VERSION >= 3
static bool initialized = false;
#endif

DISABLE_WARNING_MISSING_PROTOTYPES;

PyMODINIT_FUNC
#if PY_MAJOR_VERSION >= 3
PyInit__reader(void)
#else
init_reader(void)
#endif
{
        PyObject* m;

        PyDateTime_IMPORT;

        if (PyType_Ready(&ReaderType) < 0)
#if PY_MAJOR_VERSION >= 3
                return NULL;
#else
                return;
#endif

#if PY_MAJOR_VERSION >= 3
        m = PyModule_Create(&module);
        if (m == NULL)
                return NULL;

        if (!initialized) {
                PyStructSequence_InitType(&MonotonicType, &Monotonic_desc);
                initialized = true;
        }
#else
        m = Py_InitModule3("_reader", methods, module__doc__);
        if (m == NULL)
                return;
#endif

        Py_INCREF(&ReaderType);
#if PY_MAJOR_VERSION >= 3
        Py_INCREF(&MonotonicType);
#endif
        if (PyModule_AddObject(m, "_Reader", (PyObject *) &ReaderType) ||
#if PY_MAJOR_VERSION >= 3
            PyModule_AddObject(m, "Monotonic", (PyObject*) &MonotonicType) ||
#endif
            PyModule_AddIntConstant(m, "NOP", SD_JOURNAL_NOP) ||
            PyModule_AddIntConstant(m, "APPEND", SD_JOURNAL_APPEND) ||
            PyModule_AddIntConstant(m, "INVALIDATE", SD_JOURNAL_INVALIDATE) ||
            PyModule_AddIntConstant(m, "LOCAL_ONLY", SD_JOURNAL_LOCAL_ONLY) ||
            PyModule_AddIntConstant(m, "RUNTIME_ONLY", SD_JOURNAL_RUNTIME_ONLY) ||
            PyModule_AddIntConstant(m, "SYSTEM", SD_JOURNAL_SYSTEM) ||
            PyModule_AddIntConstant(m, "SYSTEM_ONLY", SD_JOURNAL_SYSTEM_ONLY) ||
            PyModule_AddIntConstant(m, "CURRENT_USER", SD_JOURNAL_CURRENT_USER) ||
            PyModule_AddStringConstant(m, "__version__", PACKAGE_VERSION)) {
#if PY_MAJOR_VERSION >= 3
                Py_DECREF(m);
                return NULL;
#endif
        }

#if PY_MAJOR_VERSION >= 3
        return m;
#endif
}

REENABLE_WARNING;
