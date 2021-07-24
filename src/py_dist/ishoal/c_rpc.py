import ctypes
import struct
import threading

import requests

import ishoalc

ISHOALC_RPC_CHECK_FOR_UPDATES = 1
ISHOALC_RPC_INIT_UPDATE = 2
ISHOALC_RPC_RAISE_ERR = 3
ISHOALC_RPC_INVOKE_CRASH = 4

# It's a feature: https://bugs.python.org/issue34592
lib = ctypes.cdll.LoadLibrary(None)

malloc = lib.malloc
malloc.restype = ctypes.c_void_p


def check_for_updates(data):
    _, destvar = struct.unpack('IP', data)
    r = requests.get('https://ishoal.ink/dist/ishoal-version')

    if r.status_code != 200:
        return -1

    r.encoding = 'utf-8'  # avoid chardet
    newver = r.text.strip()

    if newver == ishoalc.get_version():
        return 0

    newver = newver.encode()

    # We can't use create_string_buffer because of lifetime :(
    verbuf = ctypes.c_void_p(malloc(len(newver) + 1))
    ctypes.memmove(verbuf, ctypes.create_string_buffer(newver),
                   len(newver) + 1)

    # verbuf is char *
    # destvar is char ***
    # [something].from_address(destvar) refers to the thing behand the address,
    #   a deref, so char **
    ctypes.POINTER(ctypes.c_char_p).from_address(destvar).contents = verbuf

    return 1


def init_update():
    # https://stackoverflow.com/a/16696317
    with requests.get('https://ishoal.ink/dist/ishoal-update.tgz',
                      stream=True) as r:
        r.raise_for_status()
        with open('/tmp/ishoal-update.tgz', 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    return 0


def rpc_handler(data):
    cmd, = struct.unpack_from('I', data)

    if cmd == ISHOALC_RPC_CHECK_FOR_UPDATES:
        return check_for_updates(data)
    elif cmd == ISHOALC_RPC_INIT_UPDATE:
        return init_update()
    elif cmd == ISHOALC_RPC_RAISE_ERR:
        raise RuntimeError('User triggered crash')
    elif cmd == ISHOALC_RPC_INVOKE_CRASH:
        ishoalc.invoke_crash()
        return 0
    else:
        return -1


def start():
    threading.Thread(target=ishoalc.rpc_threadfn,
                     args=(rpc_handler,),
                     name='py_rpc').start()
