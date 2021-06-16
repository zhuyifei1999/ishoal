import logging
import re
import threading
import traceback

import socketio

import ishoal
import ishoalc

# regex credit: https://stackoverflow.com/a/26445549/13673228
IPV4_REGEXP = re.compile(
    r'^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$')


def new_socketio(g_sio):
    ishoalc.wait_for_switch()
    if ishoalc.should_stop():
        return

    all_connections = set()

    sio = socketio.Client(reconnection=False)
    sio.eio.logger.setLevel(logging.CRITICAL)
    sio.joined_as = ishoalc.get_switch_ip()

    def handshake_cb(typ, args):
        if sio != g_sio.sio:
            return

        if typ == 'port_exchange':
            sio.emit('handshake', args)

        if typ == 'complete':
            switchip,  *_ = args
            all_connections.add(switchip)
            ishoalc.add_connection(*args)

        if typ == 'timeout':
            switchip, = args
            ishoal.log_remote(f'* Remote IP {switchip}, handshake time out')

        if typ == 'error':
            switchip, e = args
            ishoal.log_remote(f'* Remote IP {switchip}, handshake error: '
                              f'{type(e).__qualname__}: {e}')

            try:
                with open('/var/log/ishoal-error.log', 'a') as f:
                    traceback.print_exc(file=f)
            except Exception:
                pass

    @sio.on('disconnect')
    def on_disconnect():
        ishoal.log_remote('Disconnecting')
        for switchip in all_connections:
            ishoalc.delete_connection(switchip)

        g_sio.sio = None

        all_connections.clear()
        ishoal.log_remote('Disconnected')

        ishoalc.sleep(100)

        if not g_sio.finalizing:
            new_socketio(g_sio)

    @sio.on('connected')
    def on_connected():
        sio.emit('protocol', (2, sio.joined_as))

        g_sio.sio = sio

        ishoal.log_remote('Joined iShoal network')

    @sio.on('ip_collision')
    def on_ip_collision():
        if sio != g_sio.sio:
            return

        ishoal.log_remote(f'Cannot join iShoal network, '
                          f'{ishoalc.get_switch_ip()} collision')

    @sio.on('add_remote')
    def on_add_remote(remoteid, remoteip, switchip):
        if sio != g_sio.sio:
            return

        if not isinstance(remoteip, str) or not IPV4_REGEXP.match(remoteip):
            return
        if not isinstance(switchip, str) or not IPV4_REGEXP.match(switchip):
            return

        ishoal.handshaker.do_handshake(remoteid, remoteip,
                                       switchip, handshake_cb)

    @sio.on('handshake')
    def on_handshake(remoteid, exchangeid, port):
        if sio != g_sio.sio:
            return

        if not isinstance(port, int) or not (0 < port < 65536):
            return
        if exchangeid not in (0, 1, 2):
            return

        ishoal.handshaker.on_handshake_msg(remoteid, exchangeid, port)

    @sio.on('del_remote')
    def on_del_remote(remoteid, remoteip, switchip):
        if sio != g_sio.sio:
            return

        if not isinstance(switchip, str) or not IPV4_REGEXP.match(switchip):
            return

        all_connections.discard(switchip)
        ishoalc.delete_connection(switchip)

    try:
        sio.connect('https://ishoal.ink/')
    except Exception as e:
        ishoal.log_remote(f'Failed to join iShoal network, check connection? '
                          f'Error:\n{type(e).__qualname__}: {e}')

        try:
            with open('/var/log/ishoal-error.log', 'a') as f:
                traceback.print_exc(file=f)
        except Exception:
            pass


class Sio:
    def __init__(self):
        self.finalizing = False
        self.sio = None

    def _start(self):
        threading.Thread(target=new_socketio, args=(self,),
                         name='sio_init').start()

    def on_switch_change(self):
        # The race here: in redetect switch, ishoalc.wait_for_switch may return
        # and sets up g_sio before this runs, so the sio from the wait is
        # immediately disconnected.
        if self.sio and self.sio.joined_as != ishoalc.get_switch_ip():
            self.sio.disconnect()

    def stop(self):
        self.finalizing = True

        if self.sio:
            self.sio.disconnect()


def start():
    g_sio = Sio()
    g_sio._start()
    return g_sio
