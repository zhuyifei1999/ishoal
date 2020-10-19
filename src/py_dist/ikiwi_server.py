import ctypes
import ctypes.util
import re
import signal
import threading

import eventlet
import socketio

import ishoalc


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
    raise SystemExit


signal.signal(signal.SIGUSR1, sig_handler)
ishoalc.start_reaper()

# regex credit: https://stackoverflow.com/a/26445549/13673228
IPV4_REGEXP = re.compile(
    r'^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$')

sio = socketio.Server()
app = socketio.WSGIApp(sio)

connected_client = None
connected_client_ip = None


@sio.event
def connect(sid, environ):
    global connected_client

    print('connect ', sid)

    if connected_client is None:
        connected_client = sid
        connected_client_ip = environ['HTTP_X_FORWARDED_FOR']

        ishoalc.set_ikiwi_addr(connected_client_ip, 0)

        sio.emit('connection', ishoalc.get_server_port(), room=sid)
        print(f'sent {ishoalc.get_server_port()}')


@sio.event
def disconnect(sid):
    global connected_client

    if sid == connected_client:
        connected_client = None
        ishoalc.set_ikiwi_addr('0.0.0.0', 0)


def main():
    eventlet.wsgi.server(eventlet.listen(('127.0.0.1', 5000)), app)


main()
