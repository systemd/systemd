/*-*- Mode: C; c-basic-offset: 4; indent-tabs-mode: nil -*-*/

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
#include <stdio.h>

#include <systemd/sd-journal.h>

#include "pyutil.h"
#include "macro.h"
#include "util.h"

typedef struct {
    PyObject_HEAD
    sd_journal *j;
} Reader;
static PyTypeObject ReaderType;

static int set_error(int r, const char* path, const char* invalid_message) {
    if (r >= 0)
        return r;
    if (r == -EINVAL && invalid_message)
        PyErr_SetString(PyExc_ValueError, invalid_message);
    else if (r == -ENOMEM)
        PyErr_SetString(PyExc_MemoryError, "Not enough memory");
    else {
        errno = -r;
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, path);
    }
    return -1;
}


PyDoc_STRVAR(module__doc__,
             "Class to reads the systemd journal similar to journalctl.");


#if PY_MAJOR_VERSION >= 3
static PyTypeObject MonotonicType;

PyDoc_STRVAR(MonotonicType__doc__,
             "A tuple of (timestamp, bootid) for holding monotonic timestamps");

static PyStructSequence_Field MonotonicType_fields[] = {
    {(char*) "timestamp", (char*) "Time"},
    {(char*) "bootid", (char*) "Unique identifier of the boot"},
    {NULL, NULL}
};

static PyStructSequence_Desc Monotonic_desc = {
    (char*) "journal.Monotonic",
    MonotonicType__doc__,
    MonotonicType_fields,
    2,
};
#endif


static void Reader_dealloc(Reader* self)
{
    sd_journal_close(self->j);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

PyDoc_STRVAR(Reader__doc__,
             "Reader([flags | path]) -> ...\n\n"
             "Reader allows filtering and retrieval of Journal entries.\n"
             "Note: this is a low-level interface, and probably not what you\n"
             "want, use systemd.journal.Reader instead.\n\n"
             "Argument `flags` sets open flags of the journal, which can be one\n"
             "of, or ORed combination of constants: LOCAL_ONLY (default) opens\n"
             "journal on local machine only; RUNTIME_ONLY opens only\n"
             "volatile journal files; and SYSTEM_ONLY opens only\n"
             "journal files of system services and the kernel.\n\n"
             "Argument `path` is the directory of journal files. Note that\n"
             "`flags` and `path` are exclusive.\n");
static int Reader_init(Reader *self, PyObject *args, PyObject *keywds)
{
    int flags = 0, r;
    char *path = NULL;

    static const char* const kwlist[] = {"flags", "path", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "|iz", (char**) kwlist,
                                     &flags, &path))
        return -1;

    if (!flags)
        flags = SD_JOURNAL_LOCAL_ONLY;
    else
        if (path) {
            PyErr_SetString(PyExc_ValueError, "cannot use both flags and path");
            return -1;
        }

    Py_BEGIN_ALLOW_THREADS
    if (path)
        r = sd_journal_open_directory(&self->j, path, 0);
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
static PyObject* Reader_fileno(Reader *self, PyObject *args)
{
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
static PyObject* Reader_reliable_fd(Reader *self, PyObject *args)
{
    int r;
    r = sd_journal_reliable_fd(self->j);
    set_error(r, NULL, NULL);
    if (r < 0)
        return NULL;
    return PyBool_FromLong(r);
}


PyDoc_STRVAR(Reader_close__doc__,
             "close() -> None\n\n"
             "Free resources allocated by this Reader object.\n"
             "This method invokes sd_journal_close().\n"
             "See man:sd_journal_close(3).");
static PyObject* Reader_close(Reader *self, PyObject *args)
{
    assert(self);
    assert(!args);

    sd_journal_close(self->j);
    self->j = NULL;
    Py_RETURN_NONE;
}


PyDoc_STRVAR(Reader_get_usage__doc__,
             "get_usage() -> int\n\n"
             "Returns the total disk space currently used by journal"
             "files (in bytes). If `SD_JOURNAL_LOCAL_ONLY` was"
             "passed when opening the journal this value will only reflect"
             "the size of journal files of the local host, otherwise"
             "of all hosts.\n\n"
             "This method invokes sd_journal_get_usage().\n"
             "See man:sd_journal_get_usage(3).");
static PyObject* Reader_get_usage(Reader *self, PyObject *args)
{
    int r;
    uint64_t bytes;

    r = sd_journal_get_usage(self->j, &bytes);
    if (set_error(r, NULL, NULL))
        return NULL;

    assert_cc(sizeof(unsigned long long) == sizeof(bytes));
    return PyLong_FromUnsignedLongLong(bytes);
}


PyDoc_STRVAR(Reader___enter____doc__,
             "__enter__() -> self\n\n"
             "Part of the context manager protocol.\n"
             "Returns self.\n");
static PyObject* Reader___enter__(PyObject *self, PyObject *args)
{
    assert(self);
    assert(!args);

    Py_INCREF(self);
    return self;
}

PyDoc_STRVAR(Reader___exit____doc__,
             "__exit__(type, value, traceback) -> None\n\n"
             "Part of the context manager protocol.\n"
             "Closes the journal.\n");
static PyObject* Reader___exit__(Reader *self, PyObject *args)
{
    assert(self);

    sd_journal_close(self->j);
    self->j = NULL;
    Py_RETURN_NONE;
}


PyDoc_STRVAR(Reader_get_next__doc__,
             "get_next([skip]) -> dict\n\n"
             "Return dictionary of the next log entry. Optional skip value will\n"
             "return the `skip`\\-th log entry.");
static PyObject* Reader_get_next(Reader *self, PyObject *args)
{
    PyObject *dict;
    const void *msg;
    size_t msg_len;
    int64_t skip = 1LL;
    int r;

    if (!PyArg_ParseTuple(args, "|L:_Reader.get_next", &skip))
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

    set_error(r, NULL, NULL);
    if (r < 0)
        return NULL;
    else if (r == 0) /* EOF */
        return PyDict_New();

    dict = PyDict_New();
    if (!dict)
            return NULL;

    SD_JOURNAL_FOREACH_DATA(self->j, msg, msg_len) {
        PyObject _cleanup_Py_DECREF_ *key = NULL, *value = NULL;
        const char *delim_ptr;

        delim_ptr = memchr(msg, '=', msg_len);
        if (!delim_ptr) {
            PyErr_SetString(PyExc_OSError,
                            "journal gave us a field without '='");
            goto error;
        }

        key = unicode_FromStringAndSize(msg, delim_ptr - (const char*) msg);
        if (!key)
            goto error;

        value = PyBytes_FromStringAndSize(
                delim_ptr + 1,
                (const char*) msg + msg_len - (delim_ptr + 1) );
        if (!value)
            goto error;

        if (PyDict_Contains(dict, key)) {
            PyObject *cur_value = PyDict_GetItem(dict, key);

            if (PyList_CheckExact(cur_value)) {
                r = PyList_Append(cur_value, value);
                if (r < 0)
                    goto error;
            } else {
                PyObject _cleanup_Py_DECREF_ *tmp_list = PyList_New(0);
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

    {
        PyObject _cleanup_Py_DECREF_ *key = NULL, *value = NULL;
        uint64_t realtime;

        r = sd_journal_get_realtime_usec(self->j, &realtime);
        if (set_error(r, NULL, NULL))
            goto error;

        key = unicode_FromString("__REALTIME_TIMESTAMP");
        if (!key)
            goto error;

        assert_cc(sizeof(unsigned long long) == sizeof(realtime));
        value = PyLong_FromUnsignedLongLong(realtime);
        if (!value)
            goto error;

        if (PyDict_SetItem(dict, key, value))
            goto error;
    }

    {
        PyObject _cleanup_Py_DECREF_
            *key = NULL, *timestamp = NULL, *bytes = NULL, *value = NULL;
        sd_id128_t id;
        uint64_t monotonic;

        r = sd_journal_get_monotonic_usec(self->j, &monotonic, &id);
        if (set_error(r, NULL, NULL))
            goto error;

        assert_cc(sizeof(unsigned long long) == sizeof(monotonic));
        key = unicode_FromString("__MONOTONIC_TIMESTAMP");
        timestamp = PyLong_FromUnsignedLongLong(monotonic);
        bytes = PyBytes_FromStringAndSize((const char*) &id.bytes, sizeof(id.bytes));
#if PY_MAJOR_VERSION >= 3
        value = PyStructSequence_New(&MonotonicType);
#else
        value = PyTuple_New(2);
#endif
        if (!key || !timestamp || !bytes || !value)
            goto error;

        Py_INCREF(timestamp);
        Py_INCREF(bytes);

#if PY_MAJOR_VERSION >= 3
        PyStructSequence_SET_ITEM(value, 0, timestamp);
        PyStructSequence_SET_ITEM(value, 1, bytes);
#else
        PyTuple_SET_ITEM(value, 0, timestamp);
        PyTuple_SET_ITEM(value, 1, bytes);
#endif

        if (PyDict_SetItem(dict, key, value))
            goto error;
    }

    {
        PyObject _cleanup_Py_DECREF_ *key = NULL, *value = NULL;
        char _cleanup_free_ *cursor = NULL;

        r = sd_journal_get_cursor(self->j, &cursor);
        if (set_error(r, NULL, NULL))
            goto error;

        key = unicode_FromString("__CURSOR");
        if (!key)
            goto error;

        value = PyBytes_FromString(cursor);
        if (!value)
            goto error;

        if (PyDict_SetItem(dict, key, value))
            goto error;
    }

    return dict;
error:
    Py_DECREF(dict);
    return NULL;
}


PyDoc_STRVAR(Reader_get_previous__doc__,
             "get_previous([skip]) -> dict\n\n"
             "Return dictionary of the previous log entry. Optional skip value\n"
             "will return the -`skip`\\-th log entry. Equivalent to get_next(-skip).");
static PyObject* Reader_get_previous(Reader *self, PyObject *args)
{
    int64_t skip = 1LL;
    if (!PyArg_ParseTuple(args, "|L:_Reader.get_previous", &skip))
        return NULL;

    return PyObject_CallMethod((PyObject *)self, (char*) "get_next",
                               (char*) "L", -skip);
}


PyDoc_STRVAR(Reader_add_match__doc__,
             "add_match(match) -> None\n\n"
             "Add a match to filter journal log entries. All matches of different\n"
             "fields are combined with logical AND, and matches of the same field\n"
             "are automatically combined with logical OR.\n"
             "Match is a string of the form \"FIELD=value\".");
static PyObject* Reader_add_match(Reader *self, PyObject *args, PyObject *keywds)
{
    char *match;
    int match_len, r;
    if (!PyArg_ParseTuple(args, "s#:_Reader.add_match", &match, &match_len))
        return NULL;

    r = sd_journal_add_match(self->j, match, match_len);
    set_error(r, NULL, "Invalid match");
    if (r < 0)
            return NULL;

    Py_RETURN_NONE;
}


PyDoc_STRVAR(Reader_add_disjunction__doc__,
             "add_disjunction() -> None\n\n"
             "Inserts a logical OR between matches added before and afterwards.");
static PyObject* Reader_add_disjunction(Reader *self, PyObject *args)
{
    int r;
    r = sd_journal_add_disjunction(self->j);
    set_error(r, NULL, NULL);
    if (r < 0)
        return NULL;
    Py_RETURN_NONE;
}


PyDoc_STRVAR(Reader_flush_matches__doc__,
             "flush_matches() -> None\n\n"
             "Clear all current match filters.");
static PyObject* Reader_flush_matches(Reader *self, PyObject *args)
{
    sd_journal_flush_matches(self->j);
    Py_RETURN_NONE;
}


PyDoc_STRVAR(Reader_seek_head__doc__,
             "seek_head() -> None\n\n"
             "Jump to the beginning of the journal.\n"
             "This method invokes sd_journal_seek_head().\n"
             "See man:sd_journal_seek_head(3).");
static PyObject* Reader_seek_head(Reader *self, PyObject *args)
{
    int r;
    Py_BEGIN_ALLOW_THREADS
    r = sd_journal_seek_head(self->j);
    Py_END_ALLOW_THREADS
    if (set_error(r, NULL, NULL))
        return NULL;
    Py_RETURN_NONE;
}


PyDoc_STRVAR(Reader_seek_tail__doc__,
             "seek_tail() -> None\n\n"
             "Jump to the end of the journal.\n"
             "This method invokes sd_journal_seek_tail().\n"
             "See man:sd_journal_seek_tail(3).");
static PyObject* Reader_seek_tail(Reader *self, PyObject *args)
{
    int r;
    Py_BEGIN_ALLOW_THREADS
    r = sd_journal_seek_tail(self->j);
    Py_END_ALLOW_THREADS
    if (set_error(r, NULL, NULL))
        return NULL;
    Py_RETURN_NONE;
}


PyDoc_STRVAR(Reader_seek_realtime__doc__,
             "seek_realtime(realtime) -> None\n\n"
             "Seek to nearest matching journal entry to `realtime`. Argument\n"
             "`realtime` can must be an integer unix timestamp.");
static PyObject* Reader_seek_realtime(Reader *self, PyObject *args)
{
    double timedouble;
    uint64_t timestamp;
    int r;

    if (!PyArg_ParseTuple(args, "d:_Reader.seek_realtime", &timedouble))
        return NULL;

    timestamp = (uint64_t) (timedouble * 1.0E6);
    if ((int64_t) timestamp < 0LL) {
        PyErr_SetString(PyExc_ValueError, "Time must be a positive integer");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    r = sd_journal_seek_realtime_usec(self->j, timestamp);
    Py_END_ALLOW_THREADS
    if (set_error(r, NULL, NULL))
        return NULL;
    Py_RETURN_NONE;
}


PyDoc_STRVAR(Reader_seek_monotonic__doc__,
             "seek_monotonic(monotonic[, bootid]) -> None\n\n"
             "Seek to nearest matching journal entry to `monotonic`. Argument\n"
             "`monotonic` is an timestamp from boot in seconds.\n"
             "Argument `bootid` is a string representing which boot the\n"
             "monotonic time is reference to. Defaults to current bootid.");
static PyObject* Reader_seek_monotonic(Reader *self, PyObject *args)
{
    double timedouble;
    char *bootid = NULL;
    uint64_t timestamp;
    sd_id128_t id;
    int r;

    if (!PyArg_ParseTuple(args, "d|z:_Reader.seek_monotonic", &timedouble, &bootid))
        return NULL;

    timestamp = (uint64_t) (timedouble * 1.0E6);

    if ((int64_t) timestamp < 0LL) {
        PyErr_SetString(PyExc_ValueError, "Time must be positive number");
        return NULL;
    }

    if (bootid) {
        r = sd_id128_from_string(bootid, &id);
        if (set_error(r, NULL, "Invalid bootid"))
            return NULL;
    } else {
        Py_BEGIN_ALLOW_THREADS
        r = sd_id128_get_boot(&id);
        Py_END_ALLOW_THREADS
        if (set_error(r, NULL, NULL))
            return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    r = sd_journal_seek_monotonic_usec(self->j, id, timestamp);
    Py_END_ALLOW_THREADS
    if (set_error(r, NULL, NULL))
        return NULL;
    Py_RETURN_NONE;
}


PyDoc_STRVAR(Reader_wait__doc__,
             "wait([timeout]) -> state change (integer)\n\n"
             "Wait for a change in the journal. Argument `timeout` specifies\n"
             "the maximum number of seconds to wait before returning\n"
             "regardless of wheter the journal has changed. If `timeout` is not given\n"
             "or is 0, then block forever.\n"
             "Will return constants: NOP if no change; APPEND if new\n"
             "entries have been added to the end of the journal; and\n"
             "INVALIDATE if journal files have been added or removed.");
static PyObject* Reader_wait(Reader *self, PyObject *args, PyObject *keywds)
{
    int r;
    int64_t timeout = 0LL;

    if (!PyArg_ParseTuple(args, "|L:_Reader.wait", &timeout))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    r = sd_journal_wait(self->j,
                        timeout == 0 ? (uint64_t) -1 : timeout * 1E6);
    Py_END_ALLOW_THREADS
    if (set_error(r, NULL, NULL) < 0)
        return NULL;

    return long_FromLong(r);
}


PyDoc_STRVAR(Reader_seek_cursor__doc__,
             "seek_cursor(cursor) -> None\n\n"
             "Seek to journal entry by given unique reference `cursor`.");
static PyObject* Reader_seek_cursor(Reader *self, PyObject *args)
{
    const char *cursor;
    int r;

    if (!PyArg_ParseTuple(args, "s:_Reader.seek_cursor", &cursor))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    r = sd_journal_seek_cursor(self->j, cursor);
    Py_END_ALLOW_THREADS
    if (set_error(r, NULL, "Invalid cursor"))
        return NULL;
    Py_RETURN_NONE;
}


static PyObject* Reader_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}

static PyObject* Reader_iternext(PyObject *self)
{
    PyObject *dict;
    Py_ssize_t dict_size;

    dict = PyObject_CallMethod(self, (char*) "get_next", (char*) "");
    if (PyErr_Occurred())
        return NULL;
    dict_size = PyDict_Size(dict);
    if ((int64_t) dict_size > 0LL) {
        return dict;
    } else {
        Py_DECREF(dict);
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }
}


PyDoc_STRVAR(Reader_query_unique__doc__,
             "query_unique(field) -> a set of values\n\n"
             "Return a set of unique values appearing in journal for the\n"
             "given `field`. Note this does not respect any journal matches.");
static PyObject* Reader_query_unique(Reader *self, PyObject *args)
{
    char *query;
    int r;
    const void *uniq;
    size_t uniq_len;
    PyObject *value_set, *key, *value;

    if (!PyArg_ParseTuple(args, "s:_Reader.query_unique", &query))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    r = sd_journal_query_unique(self->j, query);
    Py_END_ALLOW_THREADS
    if (set_error(r, NULL, "Invalid field name"))
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
             "Wraps man:sd_journal_get_catalog(3).");
static PyObject* Reader_get_catalog(Reader *self, PyObject *args)
{
    int r;
    char _cleanup_free_ *msg = NULL;

    assert(self);
    assert(!args);

    Py_BEGIN_ALLOW_THREADS
    r = sd_journal_get_catalog(self->j, &msg);
    Py_END_ALLOW_THREADS
    if (set_error(r, NULL, NULL))
        return NULL;

    return unicode_FromString(msg);
}


PyDoc_STRVAR(get_catalog__doc__,
             "get_catalog(id128) -> str\n\n"
             "Retrieve a message catalog entry for the given id.\n"
             "Wraps man:sd_journal_get_catalog_for_message_id(3).");
static PyObject* get_catalog(PyObject *self, PyObject *args)
{
    int r;
    char *id_ = NULL;
    sd_id128_t id;
    char _cleanup_free_ *msg = NULL;

    assert(!self);
    assert(args);

    if (!PyArg_ParseTuple(args, "z:get_catalog", &id_))
        return NULL;

    r = sd_id128_from_string(id_, &id);
    if (set_error(r, NULL, "Invalid id128"))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    r = sd_journal_get_catalog_for_message_id(id, &msg);
    Py_END_ALLOW_THREADS
    if (set_error(r, NULL, NULL))
        return NULL;

    return unicode_FromString(msg);
}


PyDoc_STRVAR(data_threshold__doc__,
             "Threshold for field size truncation in bytes.\n\n"
             "Fields longer than this will be truncated to the threshold size.\n"
             "Defaults to 64Kb.");

static PyObject* Reader_get_data_threshold(Reader *self, void *closure)
{
    size_t cvalue;
    int r;

    r = sd_journal_get_data_threshold(self->j, &cvalue);
    if (set_error(r, NULL, NULL))
        return NULL;

    return long_FromSize_t(cvalue);
}

static int Reader_set_data_threshold(Reader *self, PyObject *value, void *closure)
{
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
static PyObject* Reader_get_closed(Reader *self, void *closure)
{
    return PyBool_FromLong(self->j == NULL);
}


static PyGetSetDef Reader_getsetters[] = {
    {(char*) "data_threshold",
     (getter) Reader_get_data_threshold,
     (setter) Reader_set_data_threshold,
     (char*) data_threshold__doc__,
     NULL},
    {(char*) "closed",
     (getter) Reader_get_closed,
     NULL,
     (char*) closed__doc__,
     NULL},
    {NULL}
};

static PyMethodDef Reader_methods[] = {
    {"fileno",          (PyCFunction) Reader_fileno, METH_NOARGS, Reader_fileno__doc__},
    {"reliable_fd",     (PyCFunction) Reader_reliable_fd, METH_NOARGS, Reader_reliable_fd__doc__},
    {"close",           (PyCFunction) Reader_close, METH_NOARGS, Reader_close__doc__},
    {"get_usage",       (PyCFunction) Reader_get_usage, METH_NOARGS, Reader_get_usage__doc__},
    {"__enter__",       (PyCFunction) Reader___enter__, METH_NOARGS, Reader___enter____doc__},
    {"__exit__",        (PyCFunction) Reader___exit__, METH_VARARGS, Reader___exit____doc__},
    {"get_next",        (PyCFunction) Reader_get_next, METH_VARARGS, Reader_get_next__doc__},
    {"get_previous",    (PyCFunction) Reader_get_previous, METH_VARARGS, Reader_get_previous__doc__},
    {"add_match",       (PyCFunction) Reader_add_match, METH_VARARGS|METH_KEYWORDS, Reader_add_match__doc__},
    {"add_disjunction", (PyCFunction) Reader_add_disjunction, METH_NOARGS, Reader_add_disjunction__doc__},
    {"flush_matches",   (PyCFunction) Reader_flush_matches, METH_NOARGS, Reader_flush_matches__doc__},
    {"seek_head",       (PyCFunction) Reader_seek_head, METH_NOARGS, Reader_seek_head__doc__},
    {"seek_tail",       (PyCFunction) Reader_seek_tail, METH_NOARGS, Reader_seek_tail__doc__},
    {"seek_realtime",   (PyCFunction) Reader_seek_realtime, METH_VARARGS, Reader_seek_realtime__doc__},
    {"seek_monotonic",  (PyCFunction) Reader_seek_monotonic, METH_VARARGS, Reader_seek_monotonic__doc__},
    {"wait",            (PyCFunction) Reader_wait, METH_VARARGS, Reader_wait__doc__},
    {"seek_cursor",     (PyCFunction) Reader_seek_cursor, METH_VARARGS, Reader_seek_cursor__doc__},
    {"query_unique",    (PyCFunction) Reader_query_unique, METH_VARARGS, Reader_query_unique__doc__},
    {"get_catalog",     (PyCFunction) Reader_get_catalog, METH_NOARGS, Reader_get_catalog__doc__},
    {NULL}  /* Sentinel */
};

static PyTypeObject ReaderType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_reader._Reader",                        /*tp_name*/
    sizeof(Reader),                           /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Reader_dealloc,               /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    Reader__doc__,                            /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    Reader_iter,                              /* tp_iter */
    Reader_iternext,                          /* tp_iternext */
    Reader_methods,                           /* tp_methods */
    0,                                        /* tp_members */
    Reader_getsetters,                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    (initproc) Reader_init,                   /* tp_init */
    0,                                        /* tp_alloc */
    PyType_GenericNew,                        /* tp_new */
};

static PyMethodDef methods[] = {
        { "get_catalog", get_catalog, METH_VARARGS, get_catalog__doc__},
        { NULL, NULL, 0, NULL }        /* Sentinel */
};

#if PY_MAJOR_VERSION >= 3
static PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "_reader",
    module__doc__,
    -1,
    methods,
    NULL, NULL, NULL, NULL
};
#endif

#if PY_MAJOR_VERSION >= 3
static bool initialized = false;
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

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
        PyModule_AddIntConstant(m, "SYSTEM_ONLY", SD_JOURNAL_SYSTEM_ONLY)) {
#if PY_MAJOR_VERSION >= 3
        Py_DECREF(m);
        return NULL;
#endif
    }

#if PY_MAJOR_VERSION >= 3
    return m;
#endif
}

#pragma GCC diagnostic pop
