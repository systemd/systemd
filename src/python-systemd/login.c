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

#include "systemd/sd-login.h"
#include "pyutil.h"
#include "util.h"
#include "strv.h"

PyDoc_STRVAR(module__doc__,
             "Python interface to the libsystemd-login library."
);

#define helper(name)                                                    \
static PyObject* name(PyObject *self, PyObject *args) {                 \
        _cleanup_strv_free_ char **list = NULL;                         \
        int r;                                                          \
        PyObject *ans;                                                  \
                                                                        \
        assert(args == NULL);                                           \
                                                                        \
        r = sd_get_##name(&list);                                       \
        if (r < 0) {                                                    \
                errno = -r;                                             \
                return PyErr_SetFromErrno(PyExc_IOError);               \
        }                                                               \
                                                                        \
        ans = PyList_New(r);                                            \
        if (!ans)                                                       \
                return NULL;                                            \
                                                                        \
        for (r--; r >= 0; r--) {                                        \
                PyObject *s = unicode_FromString(list[r]);              \
                if (!s) {                                               \
                        Py_DECREF(ans);                                 \
                        return NULL;                                    \
                }                                                       \
                                                                        \
                PyList_SetItem(ans, r, s);                              \
        }                                                               \
                                                                        \
        return ans;                                                     \
}

helper(seats)
helper(sessions)
helper(machine_names)
#undef helper

static PyObject* uids(PyObject *self, PyObject *args) {
        _cleanup_free_ uid_t *list = NULL;
        int r;
        PyObject *ans;

        assert(args == NULL);

        r = sd_get_uids(&list);
        if (r < 0) {
                errno = -r;
                return PyErr_SetFromErrno(PyExc_IOError);
        }

        ans = PyList_New(r);
        if (!ans)
                return NULL;

        for (r--; r >= 0; r--) {
                PyObject *s = long_FromLong(list[r]);
                if (!s) {
                        Py_DECREF(ans);
                        return NULL;
                }

                PyList_SetItem(ans, r, s);
        }

        return ans;
}

PyDoc_STRVAR(seats__doc__,
             "seats() -> list\n\n"
             "Returns a list of currently available local seats.\n"
             "Wraps sd_get_seats(3)."
);

PyDoc_STRVAR(sessions__doc__,
             "sessions() -> list\n\n"
             "Returns a list of current login sessions.\n"
             "Wraps sd_get_sessions(3)."
);

PyDoc_STRVAR(machine_names__doc__,
             "machine_names() -> list\n\n"
             "Returns a list of currently running virtual machines\n"
             "and containers on the system.\n"
             "Wraps sd_get_machine_names(3)."
);

PyDoc_STRVAR(uids__doc__,
             "uids() -> list\n\n"
             "Returns a list of uids of users who currently have login sessions.\n"
             "Wraps sd_get_uids(3)."
);

static PyMethodDef methods[] = {
        { "seats", seats, METH_NOARGS, seats__doc__},
        { "sessions", sessions, METH_NOARGS, sessions__doc__},
        { "machine_names", machine_names, METH_NOARGS, machine_names__doc__},
        { "uids", uids, METH_NOARGS, uids__doc__},
        {} /* Sentinel */
};


typedef struct {
        PyObject_HEAD
        sd_login_monitor *monitor;
} Monitor;
static PyTypeObject MonitorType;

static void Monitor_dealloc(Monitor* self) {
        sd_login_monitor_unref(self->monitor);
        Py_TYPE(self)->tp_free((PyObject*)self);
}

PyDoc_STRVAR(Monitor__doc__,
             "Monitor([category]) -> ...\n\n"
             "Monitor may be used to monitor login sessions, users, seats,\n"
             "and virtual machines/containers. Monitor provides a file\n"
             "descriptor which can be integrated in an external event loop.\n"
             "See man:sd_login_monitor_new(3) for the details about what\n"
             "can be monitored.");
static int Monitor_init(Monitor *self, PyObject *args, PyObject *keywds) {
        const char *category = NULL;
        int r;

        static const char* const kwlist[] = {"category", NULL};
        if (!PyArg_ParseTupleAndKeywords(args, keywds, "|z:__init__", (char**) kwlist,
                                         &category))
                return -1;

        Py_BEGIN_ALLOW_THREADS
        r = sd_login_monitor_new(category, &self->monitor);
        Py_END_ALLOW_THREADS

        return set_error(r, NULL, "Invalid category");
}


PyDoc_STRVAR(Monitor_fileno__doc__,
             "fileno() -> int\n\n"
             "Get a file descriptor to poll for events.\n"
             "This method wraps sd_login_monitor_get_fd(3).");
static PyObject* Monitor_fileno(Monitor *self, PyObject *args) {
        int fd = sd_login_monitor_get_fd(self->monitor);
        set_error(fd, NULL, NULL);
        if (fd < 0)
                return NULL;
        return long_FromLong(fd);
}


PyDoc_STRVAR(Monitor_get_events__doc__,
             "get_events() -> int\n\n"
             "Returns a mask of poll() events to wait for on the file\n"
             "descriptor returned by .fileno().\n\n"
             "See man:sd_login_monitor_get_events(3) for further discussion.");
static PyObject* Monitor_get_events(Monitor *self, PyObject *args) {
        int r = sd_login_monitor_get_events(self->monitor);
        set_error(r, NULL, NULL);
        if (r < 0)
                return NULL;
        return long_FromLong(r);
}


PyDoc_STRVAR(Monitor_get_timeout__doc__,
             "get_timeout() -> int or None\n\n"
             "Returns a timeout value for usage in poll(), the time since the\n"
             "epoch of clock_gettime(2) in microseconds, or None if no timeout\n"
             "is necessary.\n\n"
             "The return value must be converted to a relative timeout in\n"
             "milliseconds if it is to be used as an argument for poll().\n"
             "See man:sd_login_monitor_get_timeout(3) for further discussion.");
static PyObject* Monitor_get_timeout(Monitor *self, PyObject *args) {
        int r;
        uint64_t t;

        r = sd_login_monitor_get_timeout(self->monitor, &t);
        set_error(r, NULL, NULL);
        if (r < 0)
                return NULL;

        if (t == (uint64_t) -1)
                Py_RETURN_NONE;

        assert_cc(sizeof(unsigned long long) == sizeof(t));
        return PyLong_FromUnsignedLongLong(t);
}


PyDoc_STRVAR(Monitor_get_timeout_ms__doc__,
             "get_timeout_ms() -> int\n\n"
             "Returns a timeout value suitable for usage in poll(), the value\n"
             "returned by .get_timeout() converted to relative ms, or -1 if\n"
             "no timeout is necessary.");
static PyObject* Monitor_get_timeout_ms(Monitor *self, PyObject *args) {
        int r;
        uint64_t t;

        r = sd_login_monitor_get_timeout(self->monitor, &t);
        set_error(r, NULL, NULL);
        if (r < 0)
                return NULL;

        return absolute_timeout(t);
}


PyDoc_STRVAR(Monitor_close__doc__,
             "close() -> None\n\n"
             "Free resources allocated by this Monitor object.\n"
             "This method invokes sd_login_monitor_unref().\n"
             "See man:sd_login_monitor_unref(3).");
static PyObject* Monitor_close(Monitor *self, PyObject *args) {
        assert(self);
        assert(!args);

        sd_login_monitor_unref(self->monitor);
        self->monitor = NULL;
        Py_RETURN_NONE;
}


PyDoc_STRVAR(Monitor_flush__doc__,
             "flush() -> None\n\n"
             "Reset the wakeup state of the monitor object.\n"
             "This method invokes sd_login_monitor_flush().\n"
             "See man:sd_login_monitor_flush(3).");
static PyObject* Monitor_flush(Monitor *self, PyObject *args) {
        assert(self);
        assert(!args);

        Py_BEGIN_ALLOW_THREADS
        sd_login_monitor_flush(self->monitor);
        Py_END_ALLOW_THREADS
        Py_RETURN_NONE;
}


PyDoc_STRVAR(Monitor___enter____doc__,
             "__enter__() -> self\n\n"
             "Part of the context manager protocol.\n"
             "Returns self.\n");
static PyObject* Monitor___enter__(PyObject *self, PyObject *args) {
        assert(self);
        assert(!args);

        Py_INCREF(self);
        return self;
}


PyDoc_STRVAR(Monitor___exit____doc__,
             "__exit__(type, value, traceback) -> None\n\n"
             "Part of the context manager protocol.\n"
             "Closes the monitor..\n");
static PyObject* Monitor___exit__(Monitor *self, PyObject *args) {
        return Monitor_close(self, args);
}


static PyMethodDef Monitor_methods[] = {
        {"fileno",          (PyCFunction) Monitor_fileno, METH_NOARGS, Monitor_fileno__doc__},
        {"get_events",      (PyCFunction) Monitor_get_events, METH_NOARGS, Monitor_get_events__doc__},
        {"get_timeout",     (PyCFunction) Monitor_get_timeout, METH_NOARGS, Monitor_get_timeout__doc__},
        {"get_timeout_ms",  (PyCFunction) Monitor_get_timeout_ms, METH_NOARGS, Monitor_get_timeout_ms__doc__},
        {"close",           (PyCFunction) Monitor_close, METH_NOARGS, Monitor_close__doc__},
        {"flush",           (PyCFunction) Monitor_flush, METH_NOARGS, Monitor_flush__doc__},
        {"__enter__",       (PyCFunction) Monitor___enter__, METH_NOARGS, Monitor___enter____doc__},
        {"__exit__",        (PyCFunction) Monitor___exit__, METH_VARARGS, Monitor___exit____doc__},
        {}  /* Sentinel */
};

static PyTypeObject MonitorType = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name = "login.Monitor",
        .tp_basicsize = sizeof(Monitor),
        .tp_dealloc = (destructor) Monitor_dealloc,
        .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
        .tp_doc = Monitor__doc__,
        .tp_methods = Monitor_methods,
        .tp_init = (initproc) Monitor_init,
        .tp_new = PyType_GenericNew,
};

#if PY_MAJOR_VERSION < 3

DISABLE_WARNING_MISSING_PROTOTYPES;
PyMODINIT_FUNC initlogin(void) {
        PyObject *m;

        if (PyType_Ready(&MonitorType) < 0)
                return;

        m = Py_InitModule3("login", methods, module__doc__);
        if (m == NULL)
                return;

        PyModule_AddStringConstant(m, "__version__", PACKAGE_VERSION);

        Py_INCREF(&MonitorType);
        PyModule_AddObject(m, "Monitor", (PyObject *) &MonitorType);
}
REENABLE_WARNING;

#else

static struct PyModuleDef module = {
        PyModuleDef_HEAD_INIT,
        "login", /* name of module */
        module__doc__, /* module documentation, may be NULL */
        -1, /* size of per-interpreter state of the module */
        methods
};

DISABLE_WARNING_MISSING_PROTOTYPES;
PyMODINIT_FUNC PyInit_login(void) {
        PyObject *m;

        if (PyType_Ready(&MonitorType) < 0)
                return NULL;

        m = PyModule_Create(&module);
        if (m == NULL)
                return NULL;

        if (PyModule_AddStringConstant(m, "__version__", PACKAGE_VERSION)) {
                Py_DECREF(m);
                return NULL;
        }

        Py_INCREF(&MonitorType);
        if (PyModule_AddObject(m, "Monitor", (PyObject *) &MonitorType)) {
                Py_DECREF(&MonitorType);
                Py_DECREF(m);
                return NULL;
        }

        return m;
}
REENABLE_WARNING;

#endif
