import ctypes
import ctypes.util
import os
import re
import signal
import threading
import traceback

import socketio

import ishoalc
from . import handshake


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

# regex credit: https://stackoverflow.com/a/26445549/13673228
IPV4_REGEXP = re.compile(
    r'^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$')


remotes_log = os.fdopen(os.dup(ishoalc.get_remotes_log_fd()), 'a', buffering=1)

finalizing = False
g_sio = None


def new_socketio():
    ishoalc.wait_for_switch()
    if ishoalc.should_stop():
        return

    all_connections = set()

    sio = socketio.Client(reconnection=False)

    def handshake_cb(typ, args):
        if typ == 'port_exchange':
            sio.emit('handshake', args)

        if typ == 'complete':
            switchip,  *_ = args
            all_connections.add(switchip)
            ishoalc.add_connection(*args)

        if typ == 'timeout':
            switchip, = args
            print(f'* Remote IP {switchip}, handshake time out',
                  file=remotes_log)

        if typ == 'error':
            switchip, e = args
            print(f'* Remote IP {switchip}, handshake error: '
                  f'{type(e).__qualname__}: {e}', file=remotes_log)

            try:
                with open('/var/log/ishoal-error.log', 'a') as f:
                    traceback.print_exc(file=f)
            except Exception:
                pass

    @sio.on('disconnect')
    def on_disconnect():
        for switchip in all_connections:
            ishoalc.delete_connection(switchip)

        global g_sio
        g_sio = None

        all_connections.clear()
        print('Disconnected', file=remotes_log)

        ishoalc.sleep(100)

        if not finalizing:
            new_socketio()

    @sio.on('connected')
    def on_connected():
        sio.emit('protocol', (2, ishoalc.get_switch_ip()))

        global g_sio
        g_sio = sio

        print('Joined iShoal network', file=remotes_log)

    @sio.on('ip_collision')
    def on_ip_collision():
        print(f'Cannot join iShoal network, '
              f'{ishoalc.get_switch_ip()} collision',
              file=remotes_log)

    @sio.on('add_remote')
    def on_add_remote(remoteid, remoteip, switchip):
        if not isinstance(remoteip, str) or not IPV4_REGEXP.match(remoteip):
            return
        if not isinstance(switchip, str) or not IPV4_REGEXP.match(switchip):
            return

        handshake.do_handshake(loop, remoteid, remoteip,
                               switchip, handshake_cb)

    @sio.on('handshake')
    def on_handshake(remoteid, exchangeid, port):
        if not isinstance(port, int) or not (0 < port < 65536):
            return
        if exchangeid not in (0, 1):
            return

        handshake.on_handshake_msg(loop, remoteid, exchangeid, port)

    @sio.on('del_remote')
    def on_del_remote(remoteid, remoteip, switchip):
        if not isinstance(switchip, str) or not IPV4_REGEXP.match(switchip):
            return

        all_connections.discard(switchip)
        ishoalc.delete_connection(switchip)

    try:
        sio.connect('https://ishoal.ink/')
    except Exception as e:
        print(f'Failed to join iShoal network, check connection? Error:\n'
              f'{type(e).__qualname__}: {e}', file=remotes_log)

        try:
            with open('/var/log/ishoal-error.log', 'a') as f:
                traceback.print_exc(file=f)
        except Exception:
            pass


def main():
    global loop
    loop = handshake.start_handshaker()

    new_socketio()

    def on_switch_change():
        if g_sio:
            g_sio.disconnect()

    threading.Thread(target=ishoalc.on_switch_chg_threadfn,
                     args=(on_switch_change,),
                     name='py_switch_chg').start()

    # Python is dumb that signal handlers must execute on main thread :(
    # if we ishoalc.sleep(-1) then signal handler will never execute
    # wake up every 100ms to check for signals
    while not ishoalc.should_stop():
        ishoalc.sleep(100)

    global finalizing
    finalizing = True

    if g_sio:
        g_sio.disconnect()
    loop.call_soon_threadsafe(loop.stop)


main()
