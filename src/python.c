#include "features.h"

#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/eventfd.h>
#include <urcu.h>

#define PY_SSIZE_T_CLEAN
#define Py_LIMITED_API 0x03030000
#include <Python.h>

#include "ishoal.h"

static bool main_exiting;
__thread bool thread_is_python;

static void prepare_dump_trace(void)
{
    if (CMM_ACCESS_ONCE(tui_thread)) {
        Py_BEGIN_ALLOW_THREADS
        thread_stop(tui_thread);
        thread_join(tui_thread);
        Py_END_ALLOW_THREADS
    }

    fork_tee();
}

static PyObject *
ishoalc_thread_all_stop(PyObject *self, PyObject *args)
{
    thread_all_stop();
    Py_RETURN_NONE;
}

static PyObject *
ishoalc_should_stop(PyObject *self, PyObject *args)
{
    PyObject *res = thread_should_stop(python_thread) ? Py_True : Py_False;
    Py_INCREF(res);
    return res;
}

static PyObject *old_signal;
static PyOS_sighandler_t chained_py_handler[NSIG];

static void ishoalc_signal_handler(int sig_num)
{
    int save_errno = errno;

    // Python must run signal handlers on main thread, but it may not
    // immediately return from syscall if we handle the syscall ourselves.
    // So instead of doing that we propagate the signal to the main thread.
    if (current == python_thread) {
        chained_py_handler[sig_num](sig_num);

        // Python's signal handler always calls PyOS_setsig to itself
        // to override us
        PyOS_setsig(sig_num, ishoalc_signal_handler);
    } else {
        thread_signal(python_thread, sig_num);
    }

    errno = save_errno;
}

static PyObject *
ishoalc_signal(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"signalnum", "handler", NULL};
    int signalnum;
    PyObject *handler;
    PyObject *result;
    sigset_t mask, oldset;
    PyOS_sighandler_t old_handler;
    int r;

    // Block this signal while we are playing with it
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iO:signal",
                                     keywords, &signalnum, &handler))
        return NULL;

    if (signalnum < 1 || signalnum >= NSIG) {
        PyErr_SetString(PyExc_ValueError,
                        "signal number out of range");
        return NULL;
    }

    if (sigemptyset(&mask))
        return PyErr_SetFromErrno(PyExc_OSError);
    if (sigaddset(&mask, signalnum))
        return PyErr_SetFromErrno(PyExc_OSError);

    r = pthread_sigmask(SIG_BLOCK, &mask, &oldset);
    if (r) {
        errno = r;
        return PyErr_SetFromErrno(PyExc_OSError);
    }

    result = PyObject_Call(old_signal, args, kwargs);
    if (!result)
        goto unblock;

    old_handler = PyOS_getsig(signalnum);
    if (old_handler == SIG_ERR) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto unblock;
    }

    chained_py_handler[signalnum] = old_handler;

    if (PyOS_setsig(signalnum, ishoalc_signal_handler) == SIG_ERR) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto unblock;
    }

unblock:
    r = sigismember(&oldset, signalnum);
    if (r < 0) {
        if (!PyErr_Occurred())
            PyErr_SetFromErrno(PyExc_OSError);
        goto err;
    }
    if (r > 0)
        goto out;

    r = pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
    if (r) {
        errno = r;
        if (!PyErr_Occurred())
            PyErr_SetFromErrno(PyExc_OSError);
        goto err;
    }

out:
    if (!PyErr_Occurred())
        return result;

err:
    Py_XDECREF(result);
    return NULL;
}

static PyMethodDef signal_methoddef = {
    "signal", (PyCFunction)ishoalc_signal,
    METH_VARARGS | METH_KEYWORDS, NULL
};

static PyObject *
ishoalc_patch_signal(PyObject *self, PyObject *arg)
{
    if (!PyCallable_Check(arg)) {
        PyErr_SetString(PyExc_ValueError,
                        "patch_signal argument 1 is not callable");
        return NULL;
    }

    if (old_signal) {
        PyErr_SetString(PyExc_AssertionError,
                        "patch_signal cannot be called twice");
        return NULL;
    }

    old_signal = arg;

    // This is needed because reference is kept even after we return
    Py_INCREF(arg);

    return PyCFunction_New(&signal_methoddef, self);
}

static PyObject *old_thread_bootstrap;
static PyObject *texc_thread_name, *texc_type, *texc_value, *texc_traceback;

static void set_exc_context(PyObject **type, PyObject **value, PyObject **traceback)
{
    PyObject *i_type, *i_value, *i_traceback;

    PyErr_Fetch(&i_type, &i_value, &i_traceback);
    PyErr_NormalizeException(type, value, traceback);
    PyErr_NormalizeException(&i_type, &i_value, &i_traceback);
    PyException_SetContext(i_value, *value);
    PyErr_Restore(i_type, i_value, i_traceback);
}

static PyObject *
ishoalc_thread_bootstrap(PyObject *self, PyObject *args, PyObject *kwargs)
{
    PyObject *result;

    faulthandler_altstack_init();
    rcu_register_thread();
    thread_is_python = true;

    if (PyMapping_Length(args) || (kwargs && PyMapping_Length(kwargs))) {
        // Main thread is waiting for us to start, so if we raise here,
        // there is no way for us to signal main thread to perform a
        // recoverable exit of all threads, so invoking exit is the best
        // we can do to dump the error.
        PyErr_SetString(PyExc_NotImplementedError,
                        "thread_bootstrap can't take arguments");

        prepare_dump_trace();
        PyErr_Print();

        exit(1);
    }


    result = PyObject_CallFunctionObjArgs(old_thread_bootstrap, self, NULL);

    // If we have an error, propagate to main thread
    if (PyErr_Occurred() && !PyErr_ExceptionMatches(PyExc_SystemExit)) {
        PyObject *thread_name, *type, *value, *traceback;

        PyErr_Fetch(&type, &value, &traceback);

        thread_name = PyObject_GetAttrString(self, "name");
        if (thread_name) {
            PyErr_Restore(type, value, traceback);
        } else {
            set_exc_context(&type, &value, &traceback);
        }

        if (CMM_ACCESS_ONCE(texc_type) || CMM_ACCESS_ONCE(main_exiting)) {
            // Oh noes another thread crashed too?
            prepare_dump_trace();

            if (thread_name)
                PySys_FormatStderr("iShoal Fatal Python exception in thread %R:\n",
                                   thread_name);
            else
                PySys_WriteStderr("iShoal Fatal Python exception in (unknown thread):\n");
            PyErr_Print();
        } else {
            texc_thread_name = thread_name;
            PyErr_Fetch(&texc_type, &texc_value, &texc_traceback);
        }

        thread_stop(python_thread);

        result = Py_None;
        Py_INCREF(result);
    }

    rcu_unregister_thread();
    faulthandler_altstack_deinit();

    return result;
}

static PyMethodDef thread_bootstrap_methoddef = {
    "thread_bootstrap", (PyCFunction)ishoalc_thread_bootstrap,
    METH_VARARGS | METH_KEYWORDS, NULL
};

static PyObject *
ishoalc_patch_thread_bootstrap(PyObject *self, PyObject *args)
{
    PyTypeObject *type = NULL;
    PyObject *_bootstrap = NULL;

    if (!PyArg_ParseTuple(args, "O!O:patch_thread_bootstrap",
                          &PyType_Type, &type, &_bootstrap))
        return NULL;

    if (!PyCallable_Check(_bootstrap)) {
        PyErr_SetString(PyExc_ValueError,
                        "patch_thread_bootstrap argument 1 is not callable");
        return NULL;
    }

    if (old_thread_bootstrap) {
        PyErr_SetString(PyExc_AssertionError,
                        "patch_thread_bootstrap cannot be called twice");
        return NULL;
    }

    old_thread_bootstrap = _bootstrap;

    // This is needed because reference is kept even after we return
    Py_INCREF(_bootstrap);

    return PyDescr_NewMethod(type, &thread_bootstrap_methoddef);
}

static PyObject *
ishoalc_faulthandler_hijack_pre(PyObject *self, PyObject *args)
{
    faulthandler_hijack_py_pre();
    Py_RETURN_NONE;
}

static PyObject *
ishoalc_faulthandler_hijack_post(PyObject *self, PyObject *args)
{
    faulthandler_hijack_py_post();
    Py_RETURN_NONE;
}

static PyObject *
ishoalc_invoke_crash(PyObject *self, PyObject *args)
{
    trigger_crash_cb_invoke(NULL);
    Py_RETURN_NONE;
}

static bool ishoalc_sleep_do_signal(struct eventloop *el, void *ctx)
{
    PyThreadState **tssave = ctx;

    PyEval_RestoreThread(*tssave);
    PyErr_CheckSignals();
    *tssave = PyEval_SaveThread();

    return !PyErr_Occurred();
}

static PyObject *
ishoalc_sleep(PyObject *self, PyObject *args)
{
    /* This sleep will also wake on stop event */
    int millis;

    if (!PyArg_ParseTuple(args, "i:sleep",
                          &millis))
        return NULL;

    PyThreadState *tssave = PyEval_SaveThread();

    struct eventloop *el = eventloop_new();
    eventloop_install_break(el, thread_stop_eventfd(python_thread));
    eventloop_set_intr_should_restart(el, ishoalc_sleep_do_signal, &tssave);
    eventloop_enter(el, millis);
    eventloop_destroy(el);

    PyEval_RestoreThread(tssave);

    if (PyErr_Occurred())
        return NULL;

    Py_RETURN_NONE;
}

static PyObject *
ishoalc_wait_for_switch(PyObject *self, PyObject *args)
{
    Py_BEGIN_ALLOW_THREADS

    int replica_fd = broadcast_replica(switch_change_broadcast);
    struct eventloop *el = eventloop_new();

    eventloop_install_break(el, thread_stop_eventfd(python_thread));
    eventloop_install_event_sync(el, &(struct event){
        .fd = replica_fd,
        .eventfd_ack = true,
        .handler_type = EVT_BREAK,
    });

    while ((!switch_ip ||
            !memcmp(switch_mac, (macaddr_t){}, sizeof(macaddr_t))) &&
           !thread_should_stop(python_thread)) {
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
ishoalc_on_switch_chg_threadfn(PyObject *self, PyObject *arg)
{
    struct ishoalc_on_switch_chg_threadfn_ctx ctx;

    if (!PyCallable_Check(arg)) {
        PyErr_SetString(PyExc_ValueError,
                        "on_switch_chg_threadfn argument 1 is not callable");
        return NULL;
    }

    ctx.handler = arg;
    ctx.tssave = PyEval_SaveThread();
    ctx.breakfd = eventfd(0, EFD_CLOEXEC);
    if (ctx.breakfd < 0)
        perror_exit("eventfd");

    int replica_fd = broadcast_replica(switch_change_broadcast);
    struct eventloop *el = eventloop_new();

    eventloop_install_break(el, thread_stop_eventfd(python_thread));
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

static PyObject *ishoalc_rpc_handler;
static PyThreadState *ishoalc_rpc_tssave;
static int ishoalc_rpc_breakfd;

static int ishoalc_rpc, ishoalc_rpc_recv;

static PyObject *
ishoalc_rpc_threadfn(PyObject *self, PyObject *arg)
{
    if (!PyCallable_Check(arg)) {
        PyErr_SetString(PyExc_ValueError,
                        "rps_threadfn argument 1 is not callable");
        return NULL;
    }

    if (ishoalc_rpc_handler) {
        PyErr_SetString(PyExc_AssertionError,
                        "rps_threadfn cannot be called twice");
        return NULL;
    }

    ishoalc_rpc_handler = arg;
    ishoalc_rpc_tssave = PyEval_SaveThread();
    ishoalc_rpc_breakfd = eventfd(0, EFD_CLOEXEC);
    if (ishoalc_rpc_breakfd < 0)
        perror_exit("eventfd");

    make_fd_pair(&ishoalc_rpc, &ishoalc_rpc_recv);

    struct eventloop *el = eventloop_new();

    eventloop_install_break(el, thread_stop_eventfd(python_thread));
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
    PyObject *arg = NULL;
    PyObject *res = NULL;

    PyEval_RestoreThread(ishoalc_rpc_tssave);

    arg = PyBytes_FromStringAndSize(ctx->data, ctx->len);
    if (!arg)
        goto err;

    res = PyObject_CallFunctionObjArgs(ishoalc_rpc_handler, arg, NULL);
    if (!res)
        goto err;

    if (!PyLong_Check(res)) {
        PyErr_SetString(PyExc_TypeError, "RPC return must be int");
        goto err;
    }

    result = PyLong_AsLong(res);

err:
    Py_XDECREF(arg);
    Py_XDECREF(res);

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
ishoalc_get_switch_ip(PyObject *self, PyObject *args)
{
    char str[IP_STR_BULEN];
    ip_str(switch_ip, str);
    return PyUnicode_FromString(str);
}

static PyObject *
ishoalc_get_relay_ip(PyObject *self, PyObject *args)
{
    char str[IP_STR_BULEN];
    ip_str(relay_ip, str);
    return PyUnicode_FromString(str);
}

static PyObject *
ishoalc_get_version(PyObject *self, PyObject *args)
{
    return PyUnicode_FromString(ISHOAL_VERSION_STR);
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
    {"patch_signal", ishoalc_patch_signal, METH_O, NULL},
    {"patch_thread_bootstrap", ishoalc_patch_thread_bootstrap, METH_VARARGS, NULL},
    {"faulthandler_hijack_pre", ishoalc_faulthandler_hijack_pre, METH_NOARGS, NULL},
    {"faulthandler_hijack_post", ishoalc_faulthandler_hijack_post, METH_NOARGS, NULL},
    {"invoke_crash", ishoalc_invoke_crash, METH_NOARGS, NULL},
    {"sleep", ishoalc_sleep, METH_VARARGS, NULL},
    {"wait_for_switch", ishoalc_wait_for_switch, METH_NOARGS, NULL},
    {"on_switch_chg_threadfn", ishoalc_on_switch_chg_threadfn, METH_O, NULL},
    {"rpc_threadfn", ishoalc_rpc_threadfn, METH_O, NULL},
    {"get_public_host_ip", ishoalc_get_public_host_ip, METH_NOARGS, NULL},
    {"get_switch_ip", ishoalc_get_switch_ip, METH_NOARGS, NULL},
    {"get_relay_ip", ishoalc_get_relay_ip, METH_NOARGS, NULL},
    {"get_remotes_log_fd", ishoalc_get_remotes_log_fd, METH_NOARGS, NULL},
    {"get_version", ishoalc_get_version, METH_NOARGS, NULL},
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

void python_thread_fn(void *arg)
{
    python_thread = current;
    thread_is_python = true;

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
    CMM_ACCESS_ONCE(main_exiting) = true;
    thread_all_stop();

    bool propagated = false;

    if (CMM_ACCESS_ONCE(texc_type)) {
        if (PyErr_Occurred()) {
            PyObject *type, *value, *traceback;

            // Thread crashed while we crashed too,
            // swap to it, print it, swap back
            prepare_dump_trace();

            if (CMM_ACCESS_ONCE(texc_thread_name))
                PySys_FormatStderr("iShoal Fatal Python exception in thread %R:\n",
                                   texc_thread_name);
            else
                PySys_WriteStderr("iShoal Fatal Python exception in (unknown thread):\n");
            PyErr_Fetch(&type, &value, &traceback);
            PyErr_Restore(texc_type, texc_value, texc_traceback);
            PyErr_Print();
            PyErr_Restore(type, value, traceback);
        } else {
            PyErr_Restore(texc_type, texc_value, texc_traceback);
            propagated = true;
        }
    }

    if (PyErr_Occurred()) {
        prepare_dump_trace();

        if (!propagated)
            PySys_WriteStderr("iShoal Fatal Python exception in (python main thread):\n");
        else if (CMM_ACCESS_ONCE(texc_thread_name))
            PySys_FormatStderr("iShoal Fatal Python exception in thread %R:\n",
                               texc_thread_name);
        else
            PySys_WriteStderr("iShoal Fatal Python exception in (unknown thread):\n");
        PyErr_Print();
        exitcode = 1;
    }

    Py_XDECREF(mainmod);
    Py_XDECREF(selfpath);

    Py_Finalize();
}
