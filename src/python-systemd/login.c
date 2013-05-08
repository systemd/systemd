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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

#if PY_MAJOR_VERSION < 3

PyMODINIT_FUNC initlogin(void) {
        PyObject *m;

        m = Py_InitModule3("login", methods, module__doc__);
        if (m == NULL)
                return;
        PyModule_AddStringConstant(m, "__version__", PACKAGE_VERSION);
}
#else

static struct PyModuleDef module = {
        PyModuleDef_HEAD_INIT,
        "login", /* name of module */
        module__doc__, /* module documentation, may be NULL */
        -1, /* size of per-interpreter state of the module */
        methods
};

PyMODINIT_FUNC PyInit_login(void) {
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

#endif

#pragma GCC diagnostic pop
