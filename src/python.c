#include "features.h"

#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <urcu.h>

#define PY_SSIZE_T_CLEAN
#define Py_LIMITED_API 0x03030000
#include <Python.h>

#include "ishoal.h"

static struct thread *python_main_thread;

static PyObject *
ishoalc_thread_all_stop(PyObject *self, PyObject *args)
{
    thread_all_stop();
    Py_RETURN_NONE;
}

static PyObject *
ishoalc_should_stop(PyObject *self, PyObject *args)
{
    PyObject *res = thread_should_stop(python_main_thread) ? Py_True : Py_False;
    Py_INCREF(res);
    return res;
}

static PyObject *
ishoalc_rcu_register_thread(PyObject *self, PyObject *args)
{
    rcu_register_thread();
    Py_RETURN_NONE;
}

static PyObject *
ishoalc_rcu_unregister_thread(PyObject *self, PyObject *args)
{
    rcu_unregister_thread();
    Py_RETURN_NONE;
}

static PyObject *
ishoalc_sleep(PyObject *self, PyObject *args)
{
    /* This sleep will also wake on stop event */
    int millis;

    if (!PyArg_ParseTuple(args, "i:sleep",
                          &millis))
        return NULL;

    Py_BEGIN_ALLOW_THREADS

    struct eventloop *wait_for_stun = eventloop_new();
    eventloop_install_break(wait_for_stun, thread_stop_eventfd(python_main_thread));
    eventloop_enter(wait_for_stun, millis);
    eventloop_destroy(wait_for_stun);

    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;
}

static PyObject *
ishoalc_set_ikiwi_addr(PyObject *self, PyObject *args)
{
    const char *str_ikiwi_ip;
    uint16_t arg_ikiwi_port;

    ipaddr_t arg_ikiwi_ip;

    if (!PyArg_ParseTuple(args, "sH:set_ikiwi_addr",
                          &str_ikiwi_ip,
                          &arg_ikiwi_port))
        return NULL;

    if (inet_pton(AF_INET, str_ikiwi_ip, &arg_ikiwi_ip) != 1) {
        PyErr_Format(PyExc_ValueError,
                     "\"%s\" is not an IPv4 address", str_ikiwi_ip);
        return NULL;
    }

    bpf_set_ikiwi_addr(arg_ikiwi_ip, arg_ikiwi_port);

    Py_RETURN_NONE;
}

#ifdef SERVER_BUILD
static PyObject *
ishoalc_get_server_port(PyObject *self, PyObject *args)
{
    return PyLong_FromLong(vpn_port);
}

static void python_reaper_thread(void *arg)
{
    struct eventloop *wait_reap_el = eventloop_new();
    eventloop_install_break(wait_reap_el, thread_stop_eventfd(current));
    eventloop_enter(wait_reap_el, -1);
    eventloop_destroy(wait_reap_el);

    thread_signal(python_main_thread, SIGUSR1);
}

static PyObject *
ishoalc_start_reaper(PyObject *self, PyObject *args)
{
    thread_start(python_reaper_thread, NULL, "py-reaper");

    Py_RETURN_NONE;
}
#endif

static PyMethodDef IshoalcMethods[] = {
    {"thread_all_stop", ishoalc_thread_all_stop, METH_NOARGS, NULL},
    {"should_stop", ishoalc_should_stop, METH_NOARGS, NULL},
    {"rcu_register_thread", ishoalc_rcu_register_thread, METH_NOARGS, NULL},
    {"rcu_unregister_thread", ishoalc_rcu_unregister_thread, METH_NOARGS, NULL},
    {"sleep", ishoalc_sleep, METH_VARARGS, NULL},
    {"set_ikiwi_addr", ishoalc_set_ikiwi_addr, METH_VARARGS, NULL},
#ifdef SERVER_BUILD
    {"get_server_port", ishoalc_get_server_port, METH_NOARGS, NULL},
    {"start_reaper", ishoalc_start_reaper, METH_NOARGS, NULL},
#endif
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

    PyObject *selfpath = NULL;
    PyObject *mainmod = NULL;

    PyObject *sys_path = PySys_GetObject("path");
    if (!sys_path) {
        PyErr_SetString(PyExc_RuntimeError, "Can't get sys.path");
        goto out;
    }

#ifdef SERVER_BUILD
    selfpath = PyUnicode_FromString("py_dist_build");
#else
    selfpath = PyUnicode_FromString("/proc/self/exe");
#endif
    if (!selfpath)
        goto out;

    if (PyList_Insert(sys_path, 0, selfpath))
        goto out;

#ifdef SERVER_BUILD
    mainmod = PyImport_ImportModule("ikiwi_server");
#else
    mainmod = PyImport_ImportModule("ikiwi");
#endif
    if (!mainmod)
        goto out;

out:
    if (PyErr_Occurred()) {
        PyErr_Print();
        exitcode = 1;
    }

    Py_XDECREF(mainmod);
    Py_XDECREF(selfpath);

    Py_Finalize();

    thread_all_stop();
}
