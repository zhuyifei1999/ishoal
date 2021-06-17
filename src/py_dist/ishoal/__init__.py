import ctypes
import ctypes.util
import os
import signal
import threading

import ishoalc
import ishoal.handshake
import ishoal.c_rpc
import ishoal.sio


# credit: https://bugs.python.org/issue15500#msg230736
def monkey_patch():
    libpthread_path = ctypes.util.find_library('pthread')
    libpthread = ctypes.CDLL(libpthread_path)

    pthread_setname_np = libpthread.pthread_setname_np
    pthread_setname_np.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    pthread_setname_np.restype = ctypes.c_int

    orig_start = threading.Thread.start

    def new_start(self):
        orig_start(self)
        try:
            name = self.name
            if not name or name.startswith('Thread-'):
                name = self.__class__.__name__
                if name == 'Thread':
                    try:
                        name = self._target.__name__
                    except Exception:
                        name = self.name
            if name:
                if isinstance(name, str):
                    name = name.encode('ascii', 'replace')
                ident = self.ident
                pthread_setname_np(ident, name[:15])
        except Exception:
            pass  # Don't care about failure to set name

    threading.Thread.start = new_start

    orig_bootstrap = threading.Thread._bootstrap

    def new_bootstrap(self):
        ishoalc.rcu_register_thread()
        try:
            orig_bootstrap(self)
        finally:
            ishoalc.rcu_unregister_thread()

    threading.Thread._bootstrap = new_bootstrap


monkey_patch()


def sig_handler(sig_num, frame):
    ishoalc.thread_all_stop()


signal.signal(signal.SIGINT, sig_handler)

remotes_log = os.fdopen(os.dup(ishoalc.get_remotes_log_fd()), 'a', buffering=1)


def log_remote(*args, **kwargs):
    print(file=remotes_log, *args, **kwargs)


handshaker = ishoal.handshake.start()
c_rpc = ishoal.c_rpc.start()
sio = ishoal.sio.start()

threading.Thread(target=ishoalc.on_switch_chg_threadfn,
                 args=(sio.on_switch_change,),
                 name='py_switch_chg').start()

# Python is dumb that signal handlers must execute on main thread :(
# if we ishoalc.sleep(-1) then signal handler will never execute
# wake up every 100ms to check for signals
while not ishoalc.should_stop():
    ishoalc.sleep(100)


sio.stop()
# c_rpc.stop()  # Not needed, will be stopped by thread_all_stop()
handshaker.stop()
