#include <arpa/inet.h>
#include <poll.h>

#define PY_SSIZE_T_CLEAN
#define Py_LIMITED_API 0x03030000
#include <Python.h>

#include "ishoal.h"

static struct thread *python_main_thread;

static PyObject *
ishoalc_should_stop(PyObject *self, PyObject *args)
{
    PyObject *res = thread_should_stop(python_main_thread) ? Py_True : Py_False;
    Py_INCREF(res);
    return res;
}

static PyObject *
ishoalc_sleep(PyObject *self, PyObject *args)
{
    /* This sleep will also wake on stop event */
    int millis;

    if (!PyArg_ParseTuple(args, "i:sleep",
                          &millis))
        return NULL;

    struct pollfd fds[1] = {{thread_stop_eventfd(python_main_thread), POLLIN}};
    poll(fds, 1, millis);

    Py_RETURN_NONE;
}

static PyObject *
ishoalc_set_remote_addr(PyObject *self, PyObject *args)
{
    const char *str_vpn_addr;
    const char *str_remote_addr;
    uint16_t remote_port;

    ipaddr_t vpn_addr;
    ipaddr_t remote_addr;

    if (!PyArg_ParseTuple(args, "ssH:set_remote_addr",
                          &str_vpn_addr,
                          &str_remote_addr,
                          &remote_port))
        return NULL;

    if (inet_pton(AF_INET, str_vpn_addr, &vpn_addr) != 1) {
        PyErr_Format(PyExc_ValueError,
                     "\"%s\" is not an IPv4 address", str_vpn_addr);
        return NULL;
    }

    if (inet_pton(AF_INET, str_remote_addr, &remote_addr) != 1) {
        PyErr_Format(PyExc_ValueError,
                     "\"%s\" is not an IPv4 address", str_remote_addr);
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
ishoalc_delete_remote_addr(PyObject *self, PyObject *args)
{
    const char *str_vpn_addr;

    ipaddr_t vpn_addr;

    if (!PyArg_ParseTuple(args, "s:delete_remote_addr",
                          &str_vpn_addr))
        return NULL;

    if (inet_pton(AF_INET, str_vpn_addr, &vpn_addr) != 1) {
        PyErr_Format(PyExc_ValueError,
                     "\"%s\" is not an IPv4 address", str_vpn_addr);
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyMethodDef IshoalcMethods[] = {
    {"should_stop", ishoalc_should_stop, METH_NOARGS, NULL},
    {"sleep", ishoalc_sleep, METH_VARARGS, NULL},
    {"set_remote_addr", ishoalc_set_remote_addr, METH_VARARGS, NULL},
    {"delete_remote_addr", ishoalc_delete_remote_addr, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef IshoalcModule = {
    PyModuleDef_HEAD_INIT, "ishoalc", NULL, -1, IshoalcMethods,
    NULL, NULL, NULL, NULL
};

static PyObject *
PyInit_ishoalc(void)
{
    return PyModule_Create(&IshoalcModule);
}

void python_thread(void *arg)
{
    python_main_thread = current;

    PyImport_AppendInittab("ishoalc", &PyInit_ishoalc);

    Py_Initialize();

    PyObject *sys_path = PySys_GetObject("path");
    if (!sys_path) {
        PyErr_SetString(PyExc_RuntimeError, "Can't get sys.path");
        goto out;
    }

    PyObject *selfpath = NULL;
    PyObject *mainmod = NULL;

    selfpath = PyUnicode_FromString("/proc/self/exe");
    if (!selfpath)
        goto out;

    if (PyList_Insert(sys_path, 0, selfpath))
        goto out;

    mainmod = PyImport_ImportModule("ishoal");
    if (!mainmod)
        goto out;

out:
    Py_XDECREF(mainmod);
    Py_XDECREF(selfpath);

    Py_Finalize();

    thread_all_stop();
}
