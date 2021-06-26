#include "features.h"

#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
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

    struct eventloop *el = eventloop_new();
    eventloop_install_break(el, thread_stop_eventfd(python_main_thread));
    eventloop_enter(el, millis);
    eventloop_destroy(el);

    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;
}


static PyObject *ishoalc_rpc_handler;
static PyThreadState *ishoalc_rpc_tssave;
static int ishoalc_rpc_breakfd;

static int ishoalc_rpc, ishoalc_rpc_recv;

static PyObject *
ishoalc_rpc_threadfn(PyObject *self, PyObject *args)
{
    if (ishoalc_rpc_handler) {
        PyErr_SetString(PyExc_AssertionError,
                        "rps_threadfn cannot be called twice");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:rps_threadfn", &ishoalc_rpc_handler))
        return NULL;

    if (!PyCallable_Check(ishoalc_rpc_handler)) {
        PyErr_SetString(PyExc_ValueError,
                        "rps_threadfn argument 1 is not callable");
        return NULL;
    }

    ishoalc_rpc_tssave = PyEval_SaveThread();
    ishoalc_rpc_breakfd = eventfd(0, EFD_CLOEXEC);
    if (ishoalc_rpc_breakfd < 0)
        perror_exit("eventfd");

    make_fd_pair(&ishoalc_rpc, &ishoalc_rpc_recv);

    struct eventloop *el = eventloop_new();

    eventloop_install_break(el, thread_stop_eventfd(python_main_thread));
    eventloop_install_break(el, ishoalc_rpc_breakfd);
    eventloop_install_rpc(el, ishoalc_rpc_recv);
    eventloop_enter(el, -1);

    eventloop_destroy(el);
    close(ishoalc_rpc_breakfd);

    PyEval_RestoreThread(ishoalc_rpc_tssave);

    if (PyErr_Occurred())
        return NULL;

    Py_RETURN_NONE;
}

struct ishoalc_rpc_ctx {
    char *data;
    size_t len;
};

static int ishoalc_rpc_cb(void *_ctx)
{
    struct ishoalc_rpc_ctx *ctx = _ctx;
    int result = -1;

    PyEval_RestoreThread(ishoalc_rpc_tssave);

    PyObject *arg = PyBytes_FromStringAndSize(ctx->data, ctx->len);
    if (!arg)
        goto err;

    PyObject *res = PyObject_CallFunctionObjArgs(ishoalc_rpc_handler, arg, NULL);
    if (!res)
        goto err_arg;

    if (!PyLong_Check(res)) {
        PyErr_SetString(PyExc_TypeError, "RPC return must be int");
        goto err_res;
    }

    result = PyLong_AsLong(res);

err_res:
    Py_DECREF(res);

err_arg:
    Py_DECREF(arg);

err:
    if (PyErr_Occurred()) {
        if (eventfd_write(ishoalc_rpc_breakfd, 1))
            perror_exit("eventfd_write");
    }

    ishoalc_rpc_tssave = PyEval_SaveThread();

    return result;
}

int python_rpc(void *data, size_t len)
{
    struct ishoalc_rpc_ctx ctx = {
        .data = data,
        .len = len,
    };

    if (!ishoalc_rpc_handler)
        return -1; // Not ready

    return invoke_rpc_sync(ishoalc_rpc, ishoalc_rpc_cb, &ctx);
}

static PyObject *
ishoalc_get_remotes_log_fd(PyObject *self, PyObject *args)
{
    return PyLong_FromLong(remotes_log_fd);
}

static PyObject *
ishoalc_get_public_host_ip(PyObject *self, PyObject *args)
{
    char str[IP_STR_BULEN];
    ip_str(public_host_ip, str);
    return PyUnicode_FromString(str);
}

static PyObject *
ishoalc_get_version(PyObject *self, PyObject *args)
{
    return PyUnicode_FromString(ISHOAL_VERSION_STR);
}

static PyMethodDef IshoalcMethods[] = {
    {"thread_all_stop", ishoalc_thread_all_stop, METH_NOARGS, NULL},
    {"should_stop", ishoalc_should_stop, METH_NOARGS, NULL},
    {"rcu_register_thread", ishoalc_rcu_register_thread, METH_NOARGS, NULL},
    {"rcu_unregister_thread", ishoalc_rcu_unregister_thread, METH_NOARGS, NULL},
    {"sleep", ishoalc_sleep, METH_VARARGS, NULL},
    {"rpc_threadfn", ishoalc_rpc_threadfn, METH_VARARGS, NULL},
    {"get_public_host_ip", ishoalc_get_public_host_ip, METH_NOARGS, NULL},
    {"get_remotes_log_fd", ishoalc_get_remotes_log_fd, METH_NOARGS, NULL},
    {"get_version", ishoalc_get_version, METH_NOARGS, NULL},
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

    selfpath = PyUnicode_FromString("/proc/self/exe");
    if (!selfpath)
        goto out;

    if (PyList_Insert(sys_path, 0, selfpath))
        goto out;

    mainmod = PyImport_ImportModule("ishoal");
    if (!mainmod)
        goto out;

out:
    thread_all_stop();

    if (PyErr_Occurred()) {
        PyErr_Print();
        exitcode = 1;
    }

    Py_XDECREF(mainmod);
    Py_XDECREF(selfpath);

    Py_Finalize();
}
