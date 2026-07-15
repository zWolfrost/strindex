#define PY_SSIZE_T_CLEAN
#include <Python.h>


static int is_control(unsigned char c)
{
    return (c >= 1 && c <= 8) ||
           (c >= 11 && c <= 31) ||
           c == 127;
}


static PyObject *strings_find_fast(PyObject *self, PyObject *args)
{
    PyObject *obj;
    int sep;
    Py_ssize_t min_length;

    if (!PyArg_ParseTuple(args, "Oin", &obj, &sep, &min_length))
        return NULL;

    Py_buffer view;

    if (PyObject_GetBuffer(obj, &view, PyBUF_SIMPLE) < 0)
        return NULL;

    unsigned char *data = view.buf;
    Py_ssize_t size = view.len;

    PyObject *result = PyList_New(0);

    Py_ssize_t start = 0;

    for (Py_ssize_t i = 0; i <= size; i++)
    {
        if (i == size || data[i] == (unsigned char)sep)
        {
            Py_ssize_t len = i - start;

            if (len >= min_length)
            {
                int valid = 1;

                for (Py_ssize_t j = start; j < i; j++)
                {
                    if (is_control(data[j]))
                    {
                        valid = 0;
                        break;
                    }
                }

                if (valid)
                {
                    PyObject *str = PyUnicode_DecodeUTF8((char *)data + start, len, "strict");

                    if (str)
                    {
                        PyObject *tuple = PyTuple_New(3);

                        PyTuple_SET_ITEM(tuple, 0, str);
                        PyTuple_SET_ITEM(tuple, 1, PyLong_FromSsize_t(start));
                        PyTuple_SET_ITEM(tuple, 2, PyLong_FromSsize_t(i));

                        PyList_Append(result, tuple);
                        Py_DECREF(tuple);
                    }
                    else
                    {
                        PyErr_Clear();
                    }
                }
            }

            start = i + 1;
        }
    }

    PyBuffer_Release(&view);

    return result;
}


static PyMethodDef Methods[] =
{
    {
        "strings_find_fast",
        strings_find_fast,
        METH_VARARGS,
        "Find UTF-8 strings separated by a byte separator."
    },
    {NULL, NULL, 0, NULL}
};


static struct PyModuleDef module =
{
    PyModuleDef_HEAD_INIT,
    "strings_find_fast",
    NULL,
    -1,
    Methods
};


PyMODINIT_FUNC PyInit_strings_find_fast(void)
{
    return PyModule_Create(&module);
}
