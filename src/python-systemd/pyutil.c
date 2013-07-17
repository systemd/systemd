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

#include <Python.h>
#include "pyutil.h"

void cleanup_Py_DECREFp(PyObject **p) {
        if (!*p)
                return;

        Py_DECREF(*p);
}

PyObject* absolute_timeout(uint64_t t) {
        if (t == (uint64_t) -1)
                return PyLong_FromLong(-1);
        else {
                struct timespec ts;
                uint64_t n;
                int msec;

                clock_gettime(CLOCK_MONOTONIC, &ts);
                n = (uint64_t) ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
                msec = t > n ? (int) ((t - n + 999) / 1000) : 0;

                return PyLong_FromLong(msec);
        }
}

int set_error(int r, const char* path, const char* invalid_message) {
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

#if PY_MAJOR_VERSION >=3 && PY_MINOR_VERSION >= 1
int Unicode_FSConverter(PyObject* obj, void *_result) {
        PyObject **result = _result;

        assert(result);

        if (!obj)
                /* cleanup: we don't return Py_CLEANUP_SUPPORTED, so
                 * we can assume that it was PyUnicode_FSConverter. */
                return PyUnicode_FSConverter(obj, result);

        if (obj == Py_None) {
                *result = NULL;
                return 1;
        }

        return PyUnicode_FSConverter(obj, result);
}
#endif
