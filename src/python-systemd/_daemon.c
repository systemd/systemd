/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek <zbyszek@in.waw.pl>

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

#define PY_SSIZE_T_CLEAN
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-decls"
#include <Python.h>
#pragma GCC diagnostic pop

#include <stdbool.h>
#include <assert.h>
#include <sys/socket.h>

#include "systemd/sd-daemon.h"
#include "pyutil.h"
#include "macro.h"

PyDoc_STRVAR(module__doc__,
        "Python interface to the libsystemd-daemon library.\n\n"
        "Provides _listen_fds, notify, booted, and is_* functions\n"
        "which wrap sd_listen_fds, sd_notify, sd_booted, sd_is_* and\n"
        "useful for socket activation and checking if the system is\n"
        "running under systemd."
);

PyDoc_STRVAR(booted__doc__,
             "booted() -> bool\n\n"
             "Return True iff this system is running under systemd.\n"
             "Wraps sd_daemon_booted(3)."
);

static PyObject* booted(PyObject *self, PyObject *args) {
        int r;
        assert(args == NULL);

        r = sd_booted();
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        return PyBool_FromLong(r);
}

PyDoc_STRVAR(notify__doc__,
             "notify(status, unset_environment=False) -> bool\n\n"
             "Send a message to the init system about a status change.\n"
             "Wraps sd_notify(3).");

static PyObject* notify(PyObject *self, PyObject *args, PyObject *keywds) {
        int r;
        const char* msg;
        int unset = false;

        static const char* const kwlist[] = {
                "status",
                "unset_environment",
                NULL,
        };
#if PY_MAJOR_VERSION >=3 && PY_MINOR_VERSION >= 3
        if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|p:notify",
                                         (char**) kwlist, &msg, &unset))
                return NULL;
#else
        PyObject *obj = NULL;
        if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|O:notify",
                                         (char**) kwlist, &msg, &obj))
                return NULL;
        if (obj != NULL)
                unset = PyObject_IsTrue(obj);
        if (unset < 0)
                return NULL;
#endif

        r = sd_notify(unset, msg);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        return PyBool_FromLong(r);
}


PyDoc_STRVAR(listen_fds__doc__,
             "_listen_fds(unset_environment=True) -> int\n\n"
             "Return the number of descriptors passed to this process by the init system\n"
             "as part of the socket-based activation logic.\n"
             "Wraps sd_listen_fds(3)."
);

static PyObject* listen_fds(PyObject *self, PyObject *args, PyObject *keywds) {
        int r;
        int unset = true;

        static const char* const kwlist[] = {"unset_environment", NULL};
#if PY_MAJOR_VERSION >=3 && PY_MINOR_VERSION >= 3
        if (!PyArg_ParseTupleAndKeywords(args, keywds, "|p:_listen_fds",
                                         (char**) kwlist, &unset))
                return NULL;
#else
        PyObject *obj = NULL;
        if (!PyArg_ParseTupleAndKeywords(args, keywds, "|O:_listen_fds",
                                         (char**) kwlist, &obj))
                return NULL;
        if (obj != NULL)
                unset = PyObject_IsTrue(obj);
        if (unset < 0)
                return NULL;
#endif

        r = sd_listen_fds(unset);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        return long_FromLong(r);
}

PyDoc_STRVAR(is_fifo__doc__,
             "_is_fifo(fd, path) -> bool\n\n"
             "Returns True iff the descriptor refers to a FIFO or a pipe.\n"
             "Wraps sd_is_fifo(3)."
);


static PyObject* is_fifo(PyObject *self, PyObject *args) {
        int r;
        int fd;
        const char *path = NULL;

#if PY_MAJOR_VERSION >=3 && PY_MINOR_VERSION >= 1
        if (!PyArg_ParseTuple(args, "i|O&:_is_fifo",
                              &fd, Unicode_FSConverter, &path))
                return NULL;
#else
        if (!PyArg_ParseTuple(args, "i|z:_is_fifo", &fd, &path))
                return NULL;
#endif

        r = sd_is_fifo(fd, path);
        if (set_error(r, path, NULL) < 0)
                return NULL;

        return PyBool_FromLong(r);
}


PyDoc_STRVAR(is_mq__doc__,
             "_is_mq(fd, path) -> bool\n\n"
             "Returns True iff the descriptor refers to a POSIX message queue.\n"
             "Wraps sd_is_mq(3)."
);

static PyObject* is_mq(PyObject *self, PyObject *args) {
        int r;
        int fd;
        const char *path = NULL;

#if PY_MAJOR_VERSION >=3 && PY_MINOR_VERSION >= 1
        if (!PyArg_ParseTuple(args, "i|O&:_is_mq",
                              &fd, Unicode_FSConverter, &path))
                return NULL;
#else
        if (!PyArg_ParseTuple(args, "i|z:_is_mq", &fd, &path))
                return NULL;
#endif

        r = sd_is_mq(fd, path);
        if (set_error(r, path, NULL) < 0)
                return NULL;

        return PyBool_FromLong(r);
}



PyDoc_STRVAR(is_socket__doc__,
             "_is_socket(fd, family=AF_UNSPEC, type=0, listening=-1) -> bool\n\n"
             "Returns True iff the descriptor refers to a socket.\n"
             "Wraps sd_is_socket(3).\n\n"
             "Constants for `family` are defined in the socket module."
);

static PyObject* is_socket(PyObject *self, PyObject *args) {
        int r;
        int fd, family = AF_UNSPEC, type = 0, listening = -1;

        if (!PyArg_ParseTuple(args, "i|iii:_is_socket",
                              &fd, &family, &type, &listening))
                return NULL;

        r = sd_is_socket(fd, family, type, listening);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        return PyBool_FromLong(r);
}


PyDoc_STRVAR(is_socket_inet__doc__,
             "_is_socket_inet(fd, family=AF_UNSPEC, type=0, listening=-1, port=0) -> bool\n\n"
             "Wraps sd_is_socket_inet(3).\n\n"
             "Constants for `family` are defined in the socket module."
);

static PyObject* is_socket_inet(PyObject *self, PyObject *args) {
        int r;
        int fd, family = AF_UNSPEC, type = 0, listening = -1, port = 0;

        if (!PyArg_ParseTuple(args, "i|iiii:_is_socket_inet",
                              &fd, &family, &type, &listening, &port))
                return NULL;

        if (port < 0 || port > UINT16_MAX) {
                set_error(-EINVAL, NULL, "port must fit into uint16_t");
                return NULL;
        }

        r = sd_is_socket_inet(fd, family, type, listening, (uint16_t) port);
        if (set_error(r, NULL, NULL) < 0)
                return NULL;

        return PyBool_FromLong(r);
}


PyDoc_STRVAR(is_socket_unix__doc__,
             "_is_socket_unix(fd, type, listening, path) -> bool\n\n"
             "Wraps sd_is_socket_unix(3)."
);

static PyObject* is_socket_unix(PyObject *self, PyObject *args) {
        int r;
        int fd, type = 0, listening = -1;
        char* path = NULL;
        Py_ssize_t length = 0;

#if PY_MAJOR_VERSION >=3 && PY_MINOR_VERSION >= 1
        _cleanup_Py_DECREF_ PyObject *_path = NULL;
        if (!PyArg_ParseTuple(args, "i|iiO&:_is_socket_unix",
                              &fd, &type, &listening, Unicode_FSConverter, &_path))
                return NULL;
        if (_path) {
                assert(PyBytes_Check(_path));
                if (PyBytes_AsStringAndSize(_path, &path, &length))
                        return NULL;
        }
#else
        if (!PyArg_ParseTuple(args, "i|iiz#:_is_socket_unix",
                              &fd, &type, &listening, &path, &length))
                return NULL;
#endif

        r = sd_is_socket_unix(fd, type, listening, path, length);
        if (set_error(r, path, NULL) < 0)
                return NULL;

        return PyBool_FromLong(r);
}


static PyMethodDef methods[] = {
        { "booted", booted, METH_NOARGS, booted__doc__},
        { "notify", (PyCFunction) notify, METH_VARARGS | METH_KEYWORDS, notify__doc__},
        { "_listen_fds", (PyCFunction) listen_fds, METH_VARARGS | METH_KEYWORDS, listen_fds__doc__},
        { "_is_fifo", is_fifo, METH_VARARGS, is_fifo__doc__},
        { "_is_mq", is_mq, METH_VARARGS, is_mq__doc__},
        { "_is_socket", is_socket, METH_VARARGS, is_socket__doc__},
        { "_is_socket_inet", is_socket_inet, METH_VARARGS, is_socket_inet__doc__},
        { "_is_socket_unix", is_socket_unix, METH_VARARGS, is_socket_unix__doc__},
        { NULL, NULL, 0, NULL }        /* Sentinel */
};

#if PY_MAJOR_VERSION < 3

DISABLE_WARNING_MISSING_PROTOTYPES;
PyMODINIT_FUNC init_daemon(void) {
        PyObject *m;

        m = Py_InitModule3("_daemon", methods, module__doc__);
        if (m == NULL)
                return;

        PyModule_AddIntConstant(m, "LISTEN_FDS_START", SD_LISTEN_FDS_START);
        PyModule_AddStringConstant(m, "__version__", PACKAGE_VERSION);
}
REENABLE_WARNING;

#else

static struct PyModuleDef module = {
        PyModuleDef_HEAD_INIT,
        "_daemon", /* name of module */
        module__doc__, /* module documentation, may be NULL */
        0, /* size of per-interpreter state of the module */
        methods
};

DISABLE_WARNING_MISSING_PROTOTYPES;
PyMODINIT_FUNC PyInit__daemon(void) {
        PyObject *m;

        m = PyModule_Create(&module);
        if (m == NULL)
                return NULL;

        if (PyModule_AddIntConstant(m, "LISTEN_FDS_START", SD_LISTEN_FDS_START) ||
            PyModule_AddStringConstant(m, "__version__", PACKAGE_VERSION)) {
                Py_DECREF(m);
                return NULL;
        }

        return m;
}
REENABLE_WARNING;

#endif
