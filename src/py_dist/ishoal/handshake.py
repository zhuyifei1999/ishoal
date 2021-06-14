# adapted from
# https://gist.github.com/vxgmichel/e47bff34b68adb3cf6bd4845c4bed448

import asyncio
import ipaddress
import os
import socket
import struct
import threading

import ishoalc


class DatagramEndpointProtocol(asyncio.DatagramProtocol):
    def __init__(self, endpoint):
        self._endpoint = endpoint

    def connection_made(self, transport):
        self._endpoint._transport = transport

    def connection_lost(self, exc):
        assert exc is None
        if self._endpoint._write_ready_future is not None:
            self._endpoint._write_ready_future.set_result(None)
        self._endpoint.close()

    def datagram_received(self, data, addr):
        self._endpoint.feed_datagram(data, addr)

    def pause_writing(self):
        assert self._endpoint._write_ready_future is None
        loop = self._endpoint._transport._loop
        self._endpoint._write_ready_future = loop.create_future()

    def resume_writing(self):
        assert self._endpoint._write_ready_future is not None
        self._endpoint._write_ready_future.set_result(None)
        self._endpoint._write_ready_future = None


class Endpoint:
    def __init__(self):
        self._queue = asyncio.Queue()
        self._closed = False
        self._transport = None
        self._write_ready_future = None

    def feed_datagram(self, data, addr):
        self._queue.put_nowait((data, addr))

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._queue.empty():
            self.feed_datagram(None, None)
        if self._transport:
            self._transport.close()

    def send(self, data, addr):
        if self._closed:
            raise IOError('Endpoint is closed')
        self._transport.sendto(data, addr)

    async def receive(self):
        if self._queue.empty() and self._closed:
            raise IOError('Endpoint is closed')
        data, addr = await self._queue.get()
        if data is None:
            raise IOError('Endpoint is closed')
        return data, addr

    def abort(self):
        if self._closed:
            raise IOError('Endpoint is closed')
        self._transport.abort()
        self.close()

    async def drain(self):
        if self._write_ready_future is not None:
            await self._write_ready_future

    @property
    def address(self):
        return self._transport.get_extra_info('socket').getsockname()

    @property
    def closed(self):
        return self._closed


async def open_datagram_endpoint(
        host, port, *, endpoint_factory=Endpoint, remote=False, **kwargs):
    loop = asyncio.get_running_loop()
    endpoint = endpoint_factory()
    kwargs['remote_addr' if remote else 'local_addr'] = host, port
    kwargs['protocol_factory'] = lambda: DatagramEndpointProtocol(endpoint)
    await loop.create_datagram_endpoint(**kwargs)
    return endpoint


async def open_local_endpoint(host, port=0, **kwargs):
    return await open_datagram_endpoint(
        host, port, remote=False,
        **kwargs)


STUNMessageHeader = struct.Struct('>HHI12s')
STUNAttributeHeader = struct.Struct('>HH')
STUNXORMappedIPv4Address = struct.Struct('>BBHI')


async def do_stun(endpoint):
    stunserveraddr = await asyncio.get_running_loop().getaddrinfo(
        'ishoal.ink', 3478, family=socket.AF_INET, type=socket.SOCK_DGRAM)
    stunserveraddr = stunserveraddr[0][4]
    stunid = os.urandom(12)

    request = STUNMessageHeader.pack(0x0001, 0, 0x2112A442, stunid)
    endpoint.send(request, stunserveraddr)

    while True:
        data, addr = await endpoint.receive()

        if addr != stunserveraddr:
            continue

        try:
            msg_type, msg_len, msg_cookie, msg_id = \
                STUNMessageHeader.unpack_from(data)
        except struct.error:
            continue

        if msg_type != 0x0101 or msg_id != stunid:
            continue

        ptr = STUNMessageHeader.size

        while ptr < len(data):
            try:
                attr_type, attr_len = \
                    STUNAttributeHeader.unpack_from(data, ptr)
            except struct.error:
                break

            ptr += STUNAttributeHeader.size
            if attr_type == 0x0020:
                try:
                    addr_res, addr_fam, addr_port, addr_addr = \
                        STUNXORMappedIPv4Address.unpack_from(data, ptr)
                except struct.error:
                    break

                addr = ipaddress.ip_address(addr_addr ^ 0x2112A442)
                return str(addr), addr_port ^ 0x2112

            ptr += attr_len


NUM_HANDSAKE_ADDRS = 2
HANDSHAKE_MSG = b'ISHOAL HANDSHAKE'

endpoints = {}
handshake_struct = struct.Struct(f'>HH{len(HANDSHAKE_MSG)}s')


async def _do_handshake(remoteid, realip, switchip, cb):
    loop = asyncio.get_running_loop()
    relayip = ishoalc.get_relay_ip()

    endpoint = await open_local_endpoint(ishoalc.get_public_host_ip())

    async def _handshake_exchange(myport, exchangeid, use_relay):
        def port_exchange():
            cb('port_exchange', (remoteid, exchangeid, myport, use_relay))
            return endpoints[remoteid][exchangeid]

        if use_relay:
            remoteaddr = (relayip, await port_exchange())
        else:
            remoteaddr = (realip, await port_exchange())

        def send(order):
            data = handshake_struct.pack(order, exchangeid, HANDSHAKE_MSG)
            endpoint.send(data, remoteaddr)

        send(1)

        # After a second, this function may have already returned and
        # closed the endpoint due to super fast handshake. Put a guard before
        # sending to not make spurious IOError('Endpoint is closed')
        def second_exchange():
            if not endpoint._closed:
                send(2)

        loop.call_later(1, second_exchange)

        while True:
            data, addr = await endpoint.receive()

            try:
                order, pkt_exchangeid, msg = handshake_struct.unpack(data)
            except struct.error:
                continue

            if msg != HANDSHAKE_MSG:
                continue

            if pkt_exchangeid != exchangeid:
                continue

            if order == 1:
                # Order 1: NAT traversal
                # The outgoing packet hopefully creates a session in the NAT
                # for incoming packets to get through
                pass
            elif order == 2:
                # Order 2: "SYN"
                # The reveiver updates the sender's port in case the sender's
                # NAT did a port remap.
                if addr[0] != remoteaddr[0]:
                    continue
                remoteaddr = addr
                send(3)
            elif order == 3:
                # Order 3: "SYN ACK"
                # The sender checks if the receiver responded with expected
                # port, connection is good to go, just need to alert receiver
                if addr != remoteaddr:
                    continue
                send(4)
                return addr
            elif order == 4:
                # Order 4: "ACK"
                # The receiver is alerted by sender that the connection is good
                # to go. The assertion should not fail.
                if addr != remoteaddr:
                    continue
                return addr

    try:
        endpoint_fd = endpoint._transport.get_extra_info('socket').fileno()
        _, realport = endpoint.address

        async def attempt(myport, exchangeid, use_relay):
            try:
                remoteaddr, remoteport = await asyncio.wait_for(
                    _handshake_exchange(myport, exchangeid, use_relay),
                    timeout=5)
            except asyncio.TimeoutError:
                return False
            else:
                # We always use realport because only remote concerns stunport
                cb('complete', (switchip, realport, remoteaddr, remoteport,
                                endpoint_fd))
                return True

        if await attempt(realport, 0, False):
            return

        _, stunport = await do_stun(endpoint)

        if await attempt(stunport, 1, False):
            return

        # Always use STUN in relay as it is slightly more reliable;
        # if port is bad "order 1" should fix it in theory.
        if await attempt(stunport, 2, True):
            return

        cb('timeout', (switchip,))
    except Exception as e:
        cb('error', (switchip, e))
    finally:
        del endpoints[remoteid]
        endpoint.close()


def do_handshake(loop, remoteid, remoteip, switchip, cb):
    endpoints[remoteid] = (loop.create_future(),
                           loop.create_future(),
                           loop.create_future())
    asyncio.run_coroutine_threadsafe(
        _do_handshake(remoteid, remoteip, switchip, cb), loop)


def on_handshake_msg(loop, remoteid, exchangeid, port):
    if remoteid not in endpoints:
        return

    loop.call_soon_threadsafe(
        endpoints[remoteid][exchangeid].set_result, port)


def handshake_threadfn(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()


def start_handshaker():
    loop = asyncio.new_event_loop()
    threading.Thread(target=handshake_threadfn,
                     args=(loop,), name='py_handshake').start()
    return loop
