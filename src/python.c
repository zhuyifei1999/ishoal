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

static PyObject *
ishoalc_wait_for_switch(PyObject *self, PyObject *args)
{
    Py_BEGIN_ALLOW_THREADS

    int replica_fd = broadcast_replica(switch_change_broadcast);
    struct eventloop *el = eventloop_new();

    eventloop_install_break(el, thread_stop_eventfd(python_main_thread));
    eventloop_install_event_sync(el, &(struct event){
        .fd = replica_fd,
        .eventfd_ack = true,
        .handler_type = EVT_BREAK,
    });

    while ((!switch_ip ||
            !memcmp(switch_mac, (macaddr_t){}, sizeof(macaddr_t))) &&
           !thread_should_stop(python_main_thread)) {
        eventloop_enter(el, -1);
    }

    eventloop_destroy(el);
    broadcast_replica_del(switch_change_broadcast, replica_fd);

    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;
}

struct ishoalc_on_switch_chg_threadfn_ctx {
    PyObject *handler;
    PyThreadState *tssave;
    int breakfd;
};

static void ishoalc_on_switch_chg_threadfn_cb(int fd, void *_ctx, bool expired)
{
    struct ishoalc_on_switch_chg_threadfn_ctx *ctx = _ctx;

    PyEval_RestoreThread(ctx->tssave);

    PyObject *res = PyObject_CallFunctionObjArgs(ctx->handler, NULL);
    if (!res)
        if (eventfd_write(ctx->breakfd, 1))
            perror_exit("eventfd_write");

    Py_DECREF(res);

    ctx->tssave = PyEval_SaveThread();
}

static PyObject *
ishoalc_on_switch_chg_threadfn(PyObject *self, PyObject *args)
{
    struct ishoalc_on_switch_chg_threadfn_ctx ctx;

    if (!PyArg_ParseTuple(args, "O:on_switch_chg_threadfn", &ctx.handler))
        return NULL;

    if (!PyCallable_Check(ctx.handler)) {
        PyErr_SetString(PyExc_ValueError,
                        "on_switch_chg_threadfn argument 1 is not callable");
        return NULL;
    }

    ctx.tssave = PyEval_SaveThread();
    ctx.breakfd = eventfd(0, EFD_CLOEXEC);
    if (ctx.breakfd < 0)
        perror_exit("eventfd");

    int replica_fd = broadcast_replica(switch_change_broadcast);
    struct eventloop *el = eventloop_new();

    eventloop_install_break(el, thread_stop_eventfd(python_main_thread));
    eventloop_install_break(el, ctx.breakfd);
    eventloop_install_event_sync(el, &(struct event){
        .fd = replica_fd,
        .eventfd_ack = true,
        .handler_type = EVT_CALL_FN,
        .handler_fn = ishoalc_on_switch_chg_threadfn_cb,
        .handler_ctx = &ctx,
    });

    eventloop_enter(el, -1);

    eventloop_destroy(el);
    broadcast_replica_del(switch_change_broadcast, replica_fd);
    close(ctx.breakfd);

    PyEval_RestoreThread(ctx.tssave);

    Py_RETURN_NONE;
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
ishoalc_get_switch_ip(PyObject *self, PyObject *args)
{
    char str[IP_STR_BULEN];
    ip_str(switch_ip, str);
    return PyUnicode_FromString(str);
}

static PyObject *
ishoalc_add_connection(PyObject *self, PyObject *args)
{
    const char *str_local_ip;
    const char *str_remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    int endpoint_fd;

    ipaddr_t local_ip;
    ipaddr_t remote_ip;

    if (!PyArg_ParseTuple(args, "sHsHi:add_connection",
                          &str_local_ip,
                          &local_port,
                          &str_remote_ip,
                          &remote_port,
                          &endpoint_fd))
        return NULL;

    if (inet_pton(AF_INET, str_local_ip, &local_ip) != 1) {
        PyErr_Format(PyExc_ValueError,
                     "\"%s\" is not an IPv4 address", str_local_ip);
        return NULL;
    }

    if (inet_pton(AF_INET, str_remote_ip, &remote_ip) != 1) {
        PyErr_Format(PyExc_ValueError,
                     "\"%s\" is not an IPv4 address", str_remote_ip);
        return NULL;
    }

    add_connection(local_ip, local_port, remote_ip, remote_port, endpoint_fd);

    Py_RETURN_NONE;
}

static PyObject *
ishoalc_delete_connection(PyObject *self, PyObject *args)
{
    const char *str_local_ip;

    ipaddr_t local_ip;

    if (!PyArg_ParseTuple(args, "s:delete_connection",
                          &str_local_ip))
        return NULL;

    if (inet_pton(AF_INET, str_local_ip, &local_ip) != 1) {
        PyErr_Format(PyExc_ValueError,
                     "\"%s\" is not an IPv4 address", str_local_ip);
        return NULL;
    }

    delete_connection(local_ip);

    Py_RETURN_NONE;
}

static PyMethodDef IshoalcMethods[] = {
    {"thread_all_stop", ishoalc_thread_all_stop, METH_NOARGS, NULL},
    {"should_stop", ishoalc_should_stop, METH_NOARGS, NULL},
    {"rcu_register_thread", ishoalc_rcu_register_thread, METH_NOARGS, NULL},
    {"rcu_unregister_thread", ishoalc_rcu_unregister_thread, METH_NOARGS, NULL},
    {"sleep", ishoalc_sleep, METH_VARARGS, NULL},
    {"wait_for_switch", ishoalc_wait_for_switch, METH_NOARGS, NULL},
    {"on_switch_chg_threadfn", ishoalc_on_switch_chg_threadfn, METH_VARARGS, NULL},
    {"get_public_host_ip", ishoalc_get_public_host_ip, METH_NOARGS, NULL},
    {"get_switch_ip", ishoalc_get_switch_ip, METH_NOARGS, NULL},
    {"get_remotes_log_fd", ishoalc_get_remotes_log_fd, METH_NOARGS, NULL},
    {"add_connection", ishoalc_add_connection, METH_VARARGS, NULL},
    {"delete_connection", ishoalc_delete_connection, METH_VARARGS, NULL},
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
