#define PY_SSIZE_T_CLEAN
#include <Python.h>

typedef struct {
    Py_ssize_t start;
    Py_ssize_t stop;
} Range;

typedef struct {
    Range *items;
    Py_ssize_t count;
} RangeList;

static void free_range_list(RangeList *rl) {
    if (rl) {
        PyMem_Free(rl->items);
        rl->items = NULL;
        rl->count = 0;
    }
}

static int parse_range_list(PyObject *list, RangeList *rl) {
    if (!list || list == Py_None || !PyList_Check(list)) return 0;

    Py_ssize_t count = PyList_GET_SIZE(list);
    if (count == 0) return 0;

    rl->items = PyMem_Malloc(count * sizeof(Range));
    if (!rl->items) return -1;

    for (Py_ssize_t r = 0; r < count; r++) {
        PyObject *item = PyList_GET_ITEM(list, r);
        rl->items[r].start = PyLong_AsSsize_t(PyTuple_GET_ITEM(item, 0));
        rl->items[r].stop  = PyLong_AsSsize_t(PyTuple_GET_ITEM(item, 1));
    }

    rl->count = count;
    return 0;
}

static int is_in_ranges(Py_ssize_t start, Py_ssize_t end, const RangeList *rl) {
    // "end" is unused in this function, but we keep it for consistency

    if (rl->count == 0) return 1;

    for (Py_ssize_t r = 0; r < rl->count; r++) {
        if (start >= rl->items[r].start && start <= rl->items[r].stop)
            return 1;
    }
    return 0;
}

static int contains_control_chars(const unsigned char *data, Py_ssize_t start, Py_ssize_t end) {
    for (Py_ssize_t j = start; j < end; j++) {
        unsigned char c = data[j];
        if ((c >= 1 && c <= 8) || (c >= 11 && c <= 31) || c == 127)
            return 1;
    }
    return 0;
}

static void append_match(PyObject *result, const unsigned char *data, Py_ssize_t start, Py_ssize_t end) {
    PyObject *str = PyUnicode_DecodeUTF8((char *)data + start, end - start, "strict");
    if (str) {
        PyObject *tuple = Py_BuildValue("(Nnn)", str, start, end);
        if (tuple) {
            PyList_Append(result, tuple);
            Py_DECREF(tuple);
        }
    } else {
        PyErr_Clear();
    }
}

static PyObject *strings_find_fast(PyObject *self, PyObject *args) {
    PyObject *obj, *ranges_obj;
    int sep;
    Py_ssize_t min_length;

    if (!PyArg_ParseTuple(args, "OinO", &obj, &sep, &min_length, &ranges_obj))
        return NULL;

    RangeList rl= {0};
    if (parse_range_list(ranges_obj, &rl) < 0)
        return NULL;

    Py_buffer view;
    if (PyObject_GetBuffer(obj, &view, PyBUF_SIMPLE) < 0) {
        free_range_list(&rl);
        return NULL;
    }

    unsigned char *data = view.buf;
    Py_ssize_t size = view.len;
    PyObject *result = PyList_New(0);
    Py_ssize_t start = 0;

    for (Py_ssize_t i = 0; i <= size; i++) {
        if (i == size || data[i] == (unsigned char)sep) {
            if ((i - start) >= min_length) {
                if (is_in_ranges(start, i, &rl) && !contains_control_chars(data, start, i)) {
                    append_match(result, data, start, i);
                }
            }
            start = i + 1;
        }
    }

    PyBuffer_Release(&view);
    free_range_list(&rl);

    return result;
}

static PyMethodDef Methods[] = {
    {"strings_find_fast", strings_find_fast, METH_VARARGS, "Find UTF-8 strings separated by a byte separator."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "strings_find_fast", NULL, -1, Methods
};

PyMODINIT_FUNC PyInit_strings_find_fast(void) {
    return PyModule_Create(&module);
}
