import ctypes
import ctypes.util
import re
import signal
import threading

import socketio

import ishoalc


# credit: https://bugs.python.org/issue15500#msg230736
def monkey_patch():
    libpthread_path = ctypes.util.find_library('pthread')
    if libpthread_path:
        libpthread = ctypes.CDLL(libpthread_path)

        if hasattr(libpthread, 'pthread_setname_np'):
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
                            name = self.name
                    if name:
                        if isinstance(name, str):
                            name = name.encode('ascii', 'replace')
                        ident = getattr(self, 'ident', None)
                        if ident is not None:
                            pthread_setname_np(ident, name[:15])
                except Exception:
                    pass  # Don't care about failure to set name

            threading.Thread.start = new_start


monkey_patch()


def sig_handler(sig_num, frame):
    ishoalc.thread_all_stop()


signal.signal(signal.SIGINT, sig_handler)

# regex credit: https://stackoverflow.com/a/26445549/13673228
IPV4_REGEXP = re.compile(
    r'^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$')
remote_switches = {}

sio = socketio.Client()


def pulse():
    sio.emit('pulse', (ishoalc.get_switch_ip(), ishoalc.get_vpn_port()))


@sio.on('set_remote_addr')
def on_set_remote_addr(local_ip, remote_ip, remote_port):
    if not isinstance(local_ip, str) or not IPV4_REGEXP.match(local_ip):
        return
    if not isinstance(remote_ip, str) or not IPV4_REGEXP.match(remote_ip):
        return
    if not isinstance(remote_port, int) or not (0 < remote_port < 65536):
        return

    if local_ip in remote_switches:
        if remote_switches[local_ip] == (remote_ip, remote_port):
            return

    remote_switches[local_ip] = remote_ip, remote_port
    ishoalc.set_remote_addr(local_ip, remote_ip, remote_port)


@sio.on('delete_remote_addr')
def on_delete_remote_addr(local_ip):
    if not isinstance(local_ip, str) or not IPV4_REGEXP.match(local_ip):
        return

    if local_ip not in remote_switches:
        return

    del remote_switches[local_ip]
    ishoalc.delete_remote_addr(local_ip)


def main():
    sio.connect('https://ishoal.ink/')

    ishoalc.wait_for_switch()
    if ishoalc.should_stop():
        sio.disconnect()
        return

    pulse()

    def on_switch_change():
        pulse()

    threading.Thread(target=ishoalc.on_switch_chg_threadfn,
                     args=(on_switch_change,), name='py_switch_chg').start()

    def periodic_pulse_threadfn():
        while not ishoalc.should_stop():
            ishoalc.sleep(10 * 1000)
            pulse()

    threading.Thread(target=periodic_pulse_threadfn, name='py_pulse').start()

    # Python is dumb that signal handlers must execute on main thread :(
    # if we ishoalc.sleep(-1) then signal handler will never execute
    # wake up every 100ms to check for signals
    while not ishoalc.should_stop():
        ishoalc.sleep(100)

    sio.disconnect()


main()
