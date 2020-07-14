#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <sys/eventfd.h>

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

    Py_BEGIN_ALLOW_THREADS

    struct pollfd fds[1] = {{thread_stop_eventfd(python_main_thread), POLLIN}};
    poll(fds, 1, millis);

    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;
}

static pthread_mutex_t wait_switch_chg_eventfd_lock;
static int wait_switch_chg_eventfd = -1;

static pthread_mutex_t on_switch_chg_threadfn_lock;
static int on_switch_chg_threadfn_eventfd = -1;

__attribute__((constructor))
static void ishoalc_switch_chg_init(void)
{
    pthread_mutex_init(&wait_switch_chg_eventfd_lock, NULL);
    pthread_mutex_init(&on_switch_chg_threadfn_lock, NULL);
}

static void ishoalc_on_switch_chg(void)
{
    uint64_t event_data = 1;

    pthread_mutex_lock(&wait_switch_chg_eventfd_lock);
    if (wait_switch_chg_eventfd >= 0) {
        if (write(wait_switch_chg_eventfd, &event_data, sizeof(event_data)) !=
                sizeof(event_data)) {
            int saved_errno = errno;
            pthread_mutex_unlock(&wait_switch_chg_eventfd_lock);
            errno = saved_errno;
            perror_exit("write(eventfd)");
        }
    }
    pthread_mutex_unlock(&wait_switch_chg_eventfd_lock);

    pthread_mutex_lock(&on_switch_chg_threadfn_lock);
    if (on_switch_chg_threadfn_eventfd >= 0) {
        if (write(on_switch_chg_threadfn_eventfd, &event_data, sizeof(event_data)) !=
                sizeof(event_data)) {
            int saved_errno = errno;
            pthread_mutex_unlock(&on_switch_chg_threadfn_lock);
            errno = saved_errno;
            perror_exit("write(eventfd)");
        }
    }
    pthread_mutex_unlock(&on_switch_chg_threadfn_lock);
}

static PyObject *
ishoalc_wait_for_switch(PyObject *self, PyObject *args)
{
    Py_BEGIN_ALLOW_THREADS

    pthread_mutex_lock(&wait_switch_chg_eventfd_lock);
    bool need_eventfd = wait_switch_chg_eventfd < 0;

    if (need_eventfd) {
        wait_switch_chg_eventfd = eventfd(0, EFD_CLOEXEC);
        if (wait_switch_chg_eventfd < 0) {
            int saved_errno = errno;
            pthread_mutex_unlock(&wait_switch_chg_eventfd_lock);
            errno = saved_errno;
            return PyErr_SetFromErrno(PyExc_OSError);
        }
    }
    pthread_mutex_unlock(&wait_switch_chg_eventfd_lock);

    while ((!switch_ip ||
            !memcmp(switch_mac, (macaddr_t){}, sizeof(macaddr_t))) &&
           !thread_should_stop(python_main_thread)) {
        struct pollfd fds[2] = {
            {thread_stop_eventfd(python_main_thread), POLLIN},
            {wait_switch_chg_eventfd, POLLIN},
        };
        poll(fds, 2, -1);
    }

    if (need_eventfd) {
        pthread_mutex_lock(&wait_switch_chg_eventfd_lock);
        close(wait_switch_chg_eventfd);
        wait_switch_chg_eventfd = -1;
        pthread_mutex_unlock(&wait_switch_chg_eventfd_lock);
    }

    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;
}

static PyObject *
ishoalc_on_switch_chg_threadfn(PyObject *self, PyObject *args)
{
    PyObject *handler;
    if (!PyArg_ParseTuple(args, "O:on_switch_chg_threadfn", &handler))
        return NULL;

    if (!PyCallable_Check(handler)) {
        PyErr_SetString(PyExc_ValueError,
                        "on_switch_chg_threadfn argument 1 is not callable");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS

    pthread_mutex_lock(&on_switch_chg_threadfn_lock);
    if (on_switch_chg_threadfn_eventfd >= 0) {
        pthread_mutex_unlock(&on_switch_chg_threadfn_lock);
        PyErr_SetString(PyExc_RuntimeError,
                        "on_switch_chg_threadfn is not reentrant");
        return NULL;
    }

    on_switch_chg_threadfn_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (on_switch_chg_threadfn_eventfd < 0) {
        int saved_errno = errno;
        pthread_mutex_unlock(&on_switch_chg_threadfn_lock);
        errno = saved_errno;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    pthread_mutex_unlock(&on_switch_chg_threadfn_lock);

    while (!thread_should_stop(python_main_thread)) {
        struct pollfd fds[2] = {
            {thread_stop_eventfd(python_main_thread), POLLIN},
            {on_switch_chg_threadfn_eventfd, POLLIN},
        };
        int res = poll(fds, 2, -1);

        uint64_t event_data;
		(void)!read(on_switch_chg_threadfn_eventfd, &event_data, sizeof(event_data));

        if (res < 0)
            continue;

        if (!thread_should_stop(python_main_thread)) {
            Py_BLOCK_THREADS
            PyObject *res = PyObject_CallFunctionObjArgs(handler, NULL);
            if (!res)
                break;

            Py_DECREF(res);
            Py_UNBLOCK_THREADS
        }
    }

    pthread_mutex_lock(&on_switch_chg_threadfn_lock);
    close(on_switch_chg_threadfn_eventfd);
    on_switch_chg_threadfn_eventfd = -1;
    pthread_mutex_unlock(&on_switch_chg_threadfn_lock);

    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;
}

static PyObject *
ishoalc_get_switch_ip(PyObject *self, PyObject *args)
{
    return PyUnicode_FromString(ip_str(switch_ip));
}

static PyObject *
ishoalc_get_vpn_port(PyObject *self, PyObject *args)
{
    return PyLong_FromLong(vpn_port);
}

static PyObject *
ishoalc_set_remote_addr(PyObject *self, PyObject *args)
{
    const char *str_local_ip;
    const char *str_remote_ip;
    uint16_t remote_port;

    ipaddr_t local_ip;
    ipaddr_t remote_ip;

    if (!PyArg_ParseTuple(args, "ssH:set_remote_addr",
                          &str_local_ip,
                          &str_remote_ip,
                          &remote_port))
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

    Py_RETURN_NONE;
}

static PyObject *
ishoalc_delete_remote_addr(PyObject *self, PyObject *args)
{
    const char *str_local_ip;

    ipaddr_t local_ip;

    if (!PyArg_ParseTuple(args, "s:delete_remote_addr",
                          &str_local_ip))
        return NULL;

    if (inet_pton(AF_INET, str_local_ip, &local_ip) != 1) {
        PyErr_Format(PyExc_ValueError,
                     "\"%s\" is not an IPv4 address", str_local_ip);
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyMethodDef IshoalcMethods[] = {
    {"should_stop", ishoalc_should_stop, METH_NOARGS, NULL},
    {"sleep", ishoalc_sleep, METH_VARARGS, NULL},
    {"wait_for_switch", ishoalc_wait_for_switch, METH_NOARGS, NULL},
    {"on_switch_chg_threadfn", ishoalc_on_switch_chg_threadfn, METH_VARARGS, NULL},
    {"get_switch_ip", ishoalc_get_switch_ip, METH_NOARGS, NULL},
    {"get_vpn_port", ishoalc_get_vpn_port, METH_NOARGS, NULL},
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

    on_switch_change(ishoalc_on_switch_chg);

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
