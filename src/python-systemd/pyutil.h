/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#ifndef Py_TYPE
/* avoid duplication warnings from errors in Python 2.7 headers */
# include <Python.h>
#endif

void cleanup_Py_DECREFp(PyObject **p);
PyObject* absolute_timeout(uint64_t t);
int set_error(int r, const char* path, const char* invalid_message);

#if PY_MAJOR_VERSION >=3 && PY_MINOR_VERSION >= 1
int Unicode_FSConverter(PyObject* obj, void *_result);
#endif

#define _cleanup_Py_DECREF_ __attribute__((cleanup(cleanup_Py_DECREFp)))

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
