#include <Python.h>

#define SD_JOURNAL_SUPPRESS_LOCATION
#include <systemd/sd-journal.h>

#include "macro.h"

PyDoc_STRVAR(journal_sendv__doc__,
             "sendv('FIELD=value', 'FIELD=value', ...) -> None\n\n"
             "Send an entry to the journal."
             );

static PyObject *
journal_sendv(PyObject *self, PyObject *args) {
    struct iovec *iov = NULL;
    int argc = PyTuple_Size(args);
    int i, r;
    PyObject *ret = NULL;

    PyObject **encoded = calloc(argc, sizeof(PyObject*));
    if (!encoded) {
        ret = PyErr_NoMemory();
        goto out1;
    }

    // Allocate sufficient iovector space for the arguments.
    iov = malloc(argc * sizeof(struct iovec));
    if (!iov) {
        ret = PyErr_NoMemory();
        goto out;
    }

    // Iterate through the Python arguments and fill the iovector.
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

    // Clear errno, because sd_journal_sendv will not set it by
    // itself, unless an error occurs in one of the system calls.
    errno = 0;

    // Send the iovector to the journal.
    r = sd_journal_sendv(iov, argc);

    if (r) {
        if (errno)
            PyErr_SetFromErrno(PyExc_IOError);
        else
            PyErr_SetString(PyExc_ValueError, "invalid message format");
        goto out;
    }

    // End with success.
    Py_INCREF(Py_None);
    ret = Py_None;

out:
    for (i = 0; i < argc; ++i)
        Py_XDECREF(encoded[i]);

    free(encoded);

out1:
    // Free the iovector. The actual strings
    // are already managed by Python.
    free(iov);

    return ret;
}

PyDoc_STRVAR(journal_stream_fd__doc__,
             "stream_fd(identifier, priority, level_prefix) -> fd\n\n"
             "Open a stream to journal by calling sd_journal_stream_fd(3)."
             );

static PyObject*
journal_stream_fd(PyObject *self, PyObject *args) {
    const char* identifier;
    int priority, level_prefix;
    int fd;
    if (!PyArg_ParseTuple(args, "sii:stream_fd",
                          &identifier, &priority, &level_prefix))
        return NULL;

    fd = sd_journal_stream_fd(identifier, priority, level_prefix);
    if (fd < 0)
        return PyErr_SetFromErrno(PyExc_IOError);

    return PyLong_FromLong(fd);
}

static PyMethodDef methods[] = {
    {"sendv",  journal_sendv, METH_VARARGS, journal_sendv__doc__},
    {"stream_fd", journal_stream_fd, METH_VARARGS,
     journal_stream_fd__doc__},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

#if PY_MAJOR_VERSION < 3

PyMODINIT_FUNC
init_journal(void)
{
    (void) Py_InitModule("_journal", methods);
}

#else

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "_journal", /* name of module */
    NULL, /* module documentation, may be NULL */
    0, /* size of per-interpreter state of the module */
    methods
};

PyMODINIT_FUNC
PyInit__journal(void)
{
    return PyModule_Create(&module);
}

#endif
