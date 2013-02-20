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
#include <systemd/sd-journal.h>

#include <Python.h>
#include <structmember.h>
#include <datetime.h>

#if PY_MAJOR_VERSION >=3
# define unicode_FromStringAndSize PyUnicode_FromStringAndSize
# define unicode_FromString PyUnicode_FromString
# define long_FromLong PyLong_FromLong
# define long_FromSize_t PyLong_FromSize_t
# define long_Check PyLong_Check
# define long_AsLong PyLong_AsLong
#else
/* Python 3 type naming convention is used */
# define unicode_FromStringAndSize PyString_FromStringAndSize
# define unicode_FromString PyString_FromString
# define long_FromLong PyInt_FromLong
# define long_FromSize_t PyInt_FromSize_t
# define long_Check PyInt_Check
# define long_AsLong PyInt_AsLong
#endif

typedef struct {
    PyObject_HEAD
    sd_journal *j;
} Journal;
static PyTypeObject JournalType;

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
    return 1;
}

static void Journal_dealloc(Journal* self)
{
    sd_journal_close(self->j);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

PyDoc_STRVAR(Journal__doc__,
             "Journal([flags][,path]) -> ...\n"
             "Journal instance\n\n"
             "Returns instance of Journal, which allows filtering and return\n"
             "of journal entries.\n"
             "Argument `flags` sets open flags of the journal, which can be one\n"
             "of, or ORed combination of constants: LOCAL_ONLY (default) opens\n"
             "journal on local machine only; RUNTIME_ONLY opens only\n"
             "volatile journal files; and SYSTEM_ONLY opens only\n"
             "journal files of system services and the kernel.\n"
             "Argument `path` is the directory of journal files. Note that\n"
             "currently flags are ignored when `path` is present as they are\n"
             " not relevant.");
static int Journal_init(Journal *self, PyObject *args, PyObject *keywds)
{
    int flags = SD_JOURNAL_LOCAL_ONLY, r;
    char *path = NULL;

    static const char* const kwlist[] = {"flags", "path", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "|iz", (char**) kwlist,
                                     &flags, &path))
        return 1;

    Py_BEGIN_ALLOW_THREADS
    if (path)
        r = sd_journal_open_directory(&self->j, path, 0);
    else
        r = sd_journal_open(&self->j, flags);
    Py_END_ALLOW_THREADS

    return set_error(r, path, "Invalid flags or path");
}

PyDoc_STRVAR(Journal_get_next__doc__,
             "get_next([skip]) -> dict\n\n"
             "Return dictionary of the next log entry. Optional skip value will\n"
             "return the `skip`th log entry.");
static PyObject* Journal_get_next(Journal *self, PyObject *args)
{
    PyObject *dict;
    const void *msg;
    size_t msg_len;
    const char *delim_ptr;
    PyObject *key, *value, *cur_value, *tmp_list;

    int64_t skip = 1LL, r = -EINVAL;
    if (!PyArg_ParseTuple(args, "|L", &skip))
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
    Py_END_ALLOW_THREADS

    set_error(r, NULL, NULL);
    if (r < 0)
        return NULL;
    else if (r == 0) /* EOF */
        return PyDict_New();

    dict = PyDict_New();

    SD_JOURNAL_FOREACH_DATA(self->j, msg, msg_len) {
        delim_ptr = memchr(msg, '=', msg_len);
        key = unicode_FromStringAndSize(msg, delim_ptr - (const char*) msg);
        value = PyBytes_FromStringAndSize(delim_ptr + 1, (const char*) msg + msg_len - (delim_ptr + 1) );
        if (PyDict_Contains(dict, key)) {
            cur_value = PyDict_GetItem(dict, key);
            if (PyList_CheckExact(cur_value)) {
                PyList_Append(cur_value, value);
            }else{
                tmp_list = PyList_New(0);
                PyList_Append(tmp_list, cur_value);
                PyList_Append(tmp_list, value);
                PyDict_SetItem(dict, key, tmp_list);
                Py_DECREF(tmp_list);
            }
        }else{
            PyDict_SetItem(dict, key, value);
        }
        Py_DECREF(key);
        Py_DECREF(value);
    }

    {
        uint64_t realtime;
        if (sd_journal_get_realtime_usec(self->j, &realtime) == 0) {
            char realtime_str[20];
            sprintf(realtime_str, "%llu", (long long unsigned) realtime);
            key = unicode_FromString("__REALTIME_TIMESTAMP");
            value = PyBytes_FromString(realtime_str);
            PyDict_SetItem(dict, key, value);
            Py_DECREF(key);
            Py_DECREF(value);
        }
    }

    {
        sd_id128_t sd_id;
        uint64_t monotonic;
        if (sd_journal_get_monotonic_usec(self->j, &monotonic, &sd_id) == 0) {
            char monotonic_str[20];
            sprintf(monotonic_str, "%llu", (long long unsigned) monotonic);
            key = unicode_FromString("__MONOTONIC_TIMESTAMP");
            value = PyBytes_FromString(monotonic_str);

            PyDict_SetItem(dict, key, value);
            Py_DECREF(key);
            Py_DECREF(value);
        }
    }

    {
        char *cursor;
        if (sd_journal_get_cursor(self->j, &cursor) > 0) { //Should return 0...
            key = unicode_FromString("__CURSOR");
            value = PyBytes_FromString(cursor);
            PyDict_SetItem(dict, key, value);
            free(cursor);
            Py_DECREF(key);
            Py_DECREF(value);
        }
    }

    return dict;
}

PyDoc_STRVAR(Journal_get_previous__doc__,
             "get_previous([skip]) -> dict\n\n"
             "Return dictionary of the previous log entry. Optional skip value\n"
             "will return the -`skip`th log entry. Equivalent to get_next(-skip).");
static PyObject* Journal_get_previous(Journal *self, PyObject *args)
{
    int64_t skip = 1LL;
    if (!PyArg_ParseTuple(args, "|L", &skip))
        return NULL;

    return PyObject_CallMethod((PyObject *)self, (char*) "get_next",
                               (char*) "L", -skip);
}

PyDoc_STRVAR(Journal_add_match__doc__,
             "add_match(match) -> None\n\n"
             "Add a match to filter journal log entries. All matches of different\n"
             "fields are combined in logical AND, and matches of the same field\n"
             "are automatically combined in logical OR.\n"
             "Match is a string of the form \"FIELD=value\".");
static PyObject* Journal_add_match(Journal *self, PyObject *args, PyObject *keywds)
{
    char *match;
    int match_len, r;
    if (!PyArg_ParseTuple(args, "s#", &match, &match_len))
        return NULL;

    r = sd_journal_add_match(self->j, match, match_len);
    set_error(r, NULL, "Invalid match");
    if (r < 0)
            return NULL;

    Py_RETURN_NONE;
}

PyDoc_STRVAR(Journal_add_disjunction__doc__,
             "add_disjunction() -> None\n\n"
             "Once called, all matches before and after are combined in logical\n"
             "OR.");
static PyObject* Journal_add_disjunction(Journal *self, PyObject *args)
{
    int r;
    r = sd_journal_add_disjunction(self->j);
    set_error(r, NULL, NULL);
    if (r < 0)
        return NULL;
    Py_RETURN_NONE;
}

PyDoc_STRVAR(Journal_flush_matches__doc__,
             "flush_matches() -> None\n\n"
             "Clears all current match filters.");
static PyObject* Journal_flush_matches(Journal *self, PyObject *args)
{
    sd_journal_flush_matches(self->j);
    Py_RETURN_NONE;
}

PyDoc_STRVAR(Journal_seek__doc__,
             "seek(offset[, whence]) -> None\n\n"
             "Seek through journal by `offset` number of entries. Argument\n"
             "`whence` defines what the offset is relative to:\n"
             "os.SEEK_SET (default) from first match in journal;\n"
             "os.SEEK_CUR from current position in journal;\n"
             "and os.SEEK_END is from last match in journal.");
static PyObject* Journal_seek(Journal *self, PyObject *args, PyObject *keywds)
{
    int64_t offset;
    int whence = SEEK_SET;
    PyObject *result = NULL;

    static const char* const kwlist[] = {"offset", "whence", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "L|i", (char**) kwlist,
                                     &offset, &whence))
        return NULL;

    switch(whence) {
    case SEEK_SET: {
        int r;
        Py_BEGIN_ALLOW_THREADS
        r = sd_journal_seek_head(self->j);
        Py_END_ALLOW_THREADS
        if (set_error(r, NULL, NULL))
            return NULL;

        if (offset > 0LL)
            result = PyObject_CallMethod((PyObject *)self, (char*) "get_next",
                                         (char*) "L", offset);
        break;
    }
    case SEEK_CUR:
        result = PyObject_CallMethod((PyObject *)self, (char*) "get_next",
                                     (char*) "L", offset);
        break;
    case SEEK_END: {
        int r;
        Py_BEGIN_ALLOW_THREADS
        r = sd_journal_seek_tail(self->j);
        Py_END_ALLOW_THREADS
        if (set_error(r, NULL, NULL))
            return NULL;

        result = PyObject_CallMethod((PyObject *)self, (char*) "get_next",
                                     (char*) "L", offset < 0LL ? offset : -1LL);
        break;
    }
    default:
        PyErr_SetString(PyExc_ValueError, "Invalid value for whence");
    }

    Py_XDECREF(result);
    if (PyErr_Occurred())
        return NULL;
    Py_RETURN_NONE;
}

PyDoc_STRVAR(Journal_seek_realtime__doc__,
             "seek_realtime(realtime) -> None\n\n"
             "Seek to nearest matching journal entry to `realtime`. Argument\n"
             "`realtime` can must be an integer unix timestamp.");
static PyObject* Journal_seek_realtime(Journal *self, PyObject *args)
{
    double timedouble;
    uint64_t timestamp;
    int r;

    if (!PyArg_ParseTuple(args, "d", &timedouble))
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

PyDoc_STRVAR(Journal_seek_monotonic__doc__,
             "seek_monotonic(monotonic[, bootid]) -> None\n\n"
             "Seek to nearest matching journal entry to `monotonic`. Argument\n"
             "`monotonic` is an timestamp from boot in seconds.\n"
             "Argument `bootid` is a string representing which boot the\n"
             "monotonic time is reference to. Defaults to current bootid.");
static PyObject* Journal_seek_monotonic(Journal *self, PyObject *args)
{
    double timedouble;
    char *bootid = NULL;
    uint64_t timestamp;
    sd_id128_t sd_id;
    int r;

    if (!PyArg_ParseTuple(args, "d|z", &timedouble, &bootid))
        return NULL;

    timestamp = (uint64_t) (timedouble * 1.0E6);

    if ((int64_t) timestamp < 0LL) {
        PyErr_SetString(PyExc_ValueError, "Time must be positive number");
        return NULL;
    }

    if (bootid) {
        r = sd_id128_from_string(bootid, &sd_id);
        if (set_error(r, NULL, "Invalid bootid"))
            return NULL;
    } else {
        Py_BEGIN_ALLOW_THREADS
        r = sd_id128_get_boot(&sd_id);
        Py_END_ALLOW_THREADS
        if (set_error(r, NULL, NULL))
            return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    r = sd_journal_seek_monotonic_usec(self->j, sd_id, timestamp);
    Py_END_ALLOW_THREADS
    if (set_error(r, NULL, NULL))
        return NULL;
    Py_RETURN_NONE;
}

PyDoc_STRVAR(Journal_wait__doc__,
             "wait([timeout]) -> Change state (integer)\n\n"
             "Waits until there is a change in the journal. Argument `timeout`\n"
             "is the maximum number of seconds to wait before returning\n"
             "regardless if journal has changed. If `timeout` is not given or is\n"
             "0, then it will block forever.\n"
             "Will return constants: NOP if no change; APPEND if new\n"
             "entries have been added to the end of the journal; and\n"
             "INVALIDATE if journal files have been added or removed.");
static PyObject* Journal_wait(Journal *self, PyObject *args, PyObject *keywds)
{
    int r;
    int64_t timeout = 0LL;

    if (!PyArg_ParseTuple(args, "|L", &timeout))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    r = sd_journal_wait(self->j, timeout ==0 ? (uint64_t) -1 : timeout * 1E6);
    Py_END_ALLOW_THREADS
    if (set_error(r, NULL, NULL))
        return NULL;

    return long_FromLong(r);
}

PyDoc_STRVAR(Journal_seek_cursor__doc__,
             "seek_cursor(cursor) -> None\n\n"
             "Seeks to journal entry by given unique reference `cursor`.");
static PyObject* Journal_seek_cursor(Journal *self, PyObject *args)
{
    const char *cursor;
    int r;

    if (!PyArg_ParseTuple(args, "s", &cursor))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    r = sd_journal_seek_cursor(self->j, cursor);
    Py_END_ALLOW_THREADS
    if (set_error(r, NULL, "Invalid cursor"))
        return NULL;
    Py_RETURN_NONE;
}

static PyObject* Journal_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}

static PyObject* Journal_iternext(PyObject *self)
{
    PyObject *dict;
    Py_ssize_t dict_size;

    dict = PyObject_CallMethod(self, (char*) "get_next", (char*) "");
    if (PyErr_Occurred())
        return NULL;
    dict_size = PyDict_Size(dict);
    if ((int64_t) dict_size > 0LL) {
        return dict;
    }else{
        Py_DECREF(dict);
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }
}

PyDoc_STRVAR(Journal_query_unique__doc__,
             "query_unique(field) -> a set of values\n\n"
             "Returns a set of unique values in journal for given `field`.\n"
             "Note this does not respect any journal matches.");
static PyObject* Journal_query_unique(Journal *self, PyObject *args)
{
    char *query;
    int r;
    const void *uniq;
    size_t uniq_len;
    PyObject *value_set, *key, *value;

    if (!PyArg_ParseTuple(args, "s", &query))
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
        value = PyBytes_FromStringAndSize(delim_ptr + 1, (const char*) uniq + uniq_len - (delim_ptr + 1));
        PySet_Add(value_set, value);
        Py_DECREF(value);
    }
    Py_DECREF(key);
    return value_set;
}

static PyObject* Journal_get_data_threshold(Journal *self, void *closure)
{
    size_t cvalue;
    int r;

    r = sd_journal_get_data_threshold(self->j, &cvalue);
    if (set_error(r, NULL, NULL))
        return NULL;

    return long_FromSize_t(cvalue);
}

static int Journal_set_data_threshold(Journal *self, PyObject *value, void *closure)
{
    int r;
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete data threshold");
        return -1;
    }
    if (!long_Check(value)){
        PyErr_SetString(PyExc_TypeError, "Data threshold must be an int");
        return -1;
    }
    r = sd_journal_set_data_threshold(self->j, (size_t) long_AsLong(value));
    return set_error(r, NULL, NULL);
}

static PyGetSetDef Journal_getseters[] = {
    {(char*) "data_threshold",
     (getter)Journal_get_data_threshold,
     (setter)Journal_set_data_threshold,
     (char*) "data threshold",
     NULL},
    {NULL}
};

static PyMethodDef Journal_methods[] = {
    {"get_next", (PyCFunction)Journal_get_next, METH_VARARGS,
    Journal_get_next__doc__},
    {"get_previous", (PyCFunction)Journal_get_previous, METH_VARARGS,
    Journal_get_previous__doc__},
    {"add_match", (PyCFunction)Journal_add_match, METH_VARARGS|METH_KEYWORDS,
    Journal_add_match__doc__},
    {"add_disjunction", (PyCFunction)Journal_add_disjunction, METH_NOARGS,
    Journal_add_disjunction__doc__},
    {"flush_matches", (PyCFunction)Journal_flush_matches, METH_NOARGS,
    Journal_flush_matches__doc__},
    {"seek", (PyCFunction)Journal_seek, METH_VARARGS | METH_KEYWORDS,
    Journal_seek__doc__},
    {"seek_realtime", (PyCFunction)Journal_seek_realtime, METH_VARARGS,
    Journal_seek_realtime__doc__},
    {"seek_monotonic", (PyCFunction)Journal_seek_monotonic, METH_VARARGS,
    Journal_seek_monotonic__doc__},
    {"wait", (PyCFunction)Journal_wait, METH_VARARGS,
    Journal_wait__doc__},
    {"seek_cursor", (PyCFunction)Journal_seek_cursor, METH_VARARGS,
    Journal_seek_cursor__doc__},
    {"query_unique", (PyCFunction)Journal_query_unique, METH_VARARGS,
    Journal_query_unique__doc__},
    {NULL}  /* Sentinel */
};

static PyTypeObject JournalType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_reader._Journal",               /*tp_name*/
    sizeof(Journal),                  /*tp_basicsize*/
    0,                                /*tp_itemsize*/
    (destructor)Journal_dealloc,      /*tp_dealloc*/
    0,                                /*tp_print*/
    0,                                /*tp_getattr*/
    0,                                /*tp_setattr*/
    0,                                /*tp_compare*/
    0,                                /*tp_repr*/
    0,                                /*tp_as_number*/
    0,                                /*tp_as_sequence*/
    0,                                /*tp_as_mapping*/
    0,                                /*tp_hash */
    0,                                /*tp_call*/
    0,                                /*tp_str*/
    0,                                /*tp_getattro*/
    0,                                /*tp_setattro*/
    0,                                /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,/*tp_flags*/
    Journal__doc__,                   /* tp_doc */
    0,                                /* tp_traverse */
    0,                                /* tp_clear */
    0,                                /* tp_richcompare */
    0,                                /* tp_weaklistoffset */
    Journal_iter,                     /* tp_iter */
    Journal_iternext,                 /* tp_iternext */
    Journal_methods,                  /* tp_methods */
    0,                                /* tp_members */
    Journal_getseters,                /* tp_getset */
    0,                                /* tp_base */
    0,                                /* tp_dict */
    0,                                /* tp_descr_get */
    0,                                /* tp_descr_set */
    0,                                /* tp_dictoffset */
    (initproc)Journal_init,           /* tp_init */
    0,                                /* tp_alloc */
    PyType_GenericNew,                /* tp_new */
};

#if PY_MAJOR_VERSION >= 3
static PyModuleDef _reader_module = {
    PyModuleDef_HEAD_INIT,
    "_reader",
    "Module that reads systemd journal similar to journalctl.",
    -1,
    NULL, NULL, NULL, NULL, NULL
};
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

    if (PyType_Ready(&JournalType) < 0)
#if PY_MAJOR_VERSION >= 3
        return NULL;
#else
        return;
#endif

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&_reader_module);
    if (m == NULL)
        return NULL;
#else
    m = Py_InitModule3("_reader", NULL,
                   "Module that reads systemd journal similar to journalctl.");
    if (m == NULL)
        return;
#endif

    Py_INCREF(&JournalType);
    PyModule_AddObject(m, "_Journal", (PyObject *)&JournalType);
    PyModule_AddIntConstant(m, "NOP", SD_JOURNAL_NOP);
    PyModule_AddIntConstant(m, "APPEND", SD_JOURNAL_APPEND);
    PyModule_AddIntConstant(m, "INVALIDATE", SD_JOURNAL_INVALIDATE);
    PyModule_AddIntConstant(m, "LOCAL_ONLY", SD_JOURNAL_LOCAL_ONLY);
    PyModule_AddIntConstant(m, "RUNTIME_ONLY", SD_JOURNAL_RUNTIME_ONLY);
    PyModule_AddIntConstant(m, "SYSTEM_ONLY", SD_JOURNAL_SYSTEM_ONLY);

#if PY_MAJOR_VERSION >= 3
    return m;
#endif
}

#pragma GCC diagnostic pop
