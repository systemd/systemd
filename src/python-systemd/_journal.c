/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 David Strauss <david@davidstrauss.net>

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

#include <alloca.h>
#include "util.h"

#define SD_JOURNAL_SUPPRESS_LOCATION
#include "systemd/sd-journal.h"

PyDoc_STRVAR(journal_sendv__doc__,
             "sendv('FIELD=value', 'FIELD=value', ...) -> None\n\n"
             "Send an entry to the journal."
);

static PyObject *journal_sendv(PyObject *self, PyObject *args) {
        struct iovec *iov = NULL;
        int argc;
        int i, r;
        PyObject *ret = NULL;
        PyObject **encoded;

        /* Allocate an array for the argument strings */
        argc = PyTuple_Size(args);
        encoded = alloca0(argc * sizeof(PyObject*));

        /* Allocate sufficient iovector space for the arguments. */
        iov = alloca(argc * sizeof(struct iovec));

        /* Iterate through the Python arguments and fill the iovector. */
        for (i = 0; i < argc; ++i) {
                PyObject *item = PyTuple_GetItem(args, i);
                char *stritem;
                Py_ssize_t length;

                if (PyUnicode_Check(item)) {
                        encoded[i] = PyUnicode_AsEncodedString(item, "utf-8", "strict");
                        if (encoded[i] == NULL)
                                goto out;
                        item = encoded[i];
                }
                if (PyBytes_AsStringAndSize(item, &stritem, &length))
                        goto out;

                iov[i].iov_base = stritem;
                iov[i].iov_len = length;
        }

        /* Send the iovector to the journal. */
        r = sd_journal_sendv(iov, argc);
        if (r < 0) {
                errno = -r;
                PyErr_SetFromErrno(PyExc_IOError);
                goto out;
        }

        /* End with success. */
        Py_INCREF(Py_None);
        ret = Py_None;

out:
        for (i = 0; i < argc; ++i)
                Py_XDECREF(encoded[i]);

        return ret;
}

PyDoc_STRVAR(journal_stream_fd__doc__,
             "stream_fd(identifier, priority, level_prefix) -> fd\n\n"
             "Open a stream to journal by calling sd_journal_stream_fd(3)."
);

static PyObject* journal_stream_fd(PyObject *self, PyObject *args) {
        const char* identifier;
        int priority, level_prefix;
        int fd;

        if (!PyArg_ParseTuple(args, "sii:stream_fd",
                              &identifier, &priority, &level_prefix))
                return NULL;

        fd = sd_journal_stream_fd(identifier, priority, level_prefix);
        if (fd < 0) {
                errno = -fd;
                return PyErr_SetFromErrno(PyExc_IOError);
        }

        return PyLong_FromLong(fd);
}

static PyMethodDef methods[] = {
        { "sendv",  journal_sendv, METH_VARARGS, journal_sendv__doc__ },
        { "stream_fd", journal_stream_fd, METH_VARARGS, journal_stream_fd__doc__ },
        { NULL, NULL, 0, NULL }        /* Sentinel */
};

#if PY_MAJOR_VERSION < 3

DISABLE_WARNING_MISSING_PROTOTYPES;
PyMODINIT_FUNC init_journal(void) {
        PyObject *m;

        m = Py_InitModule("_journal", methods);
        if (m == NULL)
                return;

        PyModule_AddStringConstant(m, "__version__", PACKAGE_VERSION);
}
REENABLE_WARNING;

#else

static struct PyModuleDef module = {
        PyModuleDef_HEAD_INIT,
        "_journal", /* name of module */
        NULL, /* module documentation, may be NULL */
        -1, /* size of per-interpreter state of the module */
        methods
};

DISABLE_WARNING_MISSING_PROTOTYPES;
PyMODINIT_FUNC PyInit__journal(void) {
        PyObject *m;

        m = PyModule_Create(&module);
        if (m == NULL)
                return NULL;

        if (PyModule_AddStringConstant(m, "__version__", PACKAGE_VERSION)) {
                Py_DECREF(m);
                return NULL;
        }

        return m;
}
REENABLE_WARNING;

#endif
