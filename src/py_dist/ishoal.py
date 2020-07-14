import sys
import threading

import ishoalc

ishoalc.wait_for_switch()
if ishoalc.should_stop():
    sys.exit()

print(ishoalc.get_switch_ip(), ishoalc.get_vpn_port())


def on_switch_change():
    print('Switch change!')


threading.Thread(target=ishoalc.on_switch_chg_threadfn,
                 args=(on_switch_change,)).start()

while not ishoalc.should_stop():
    ishoalc.sleep(-1)
