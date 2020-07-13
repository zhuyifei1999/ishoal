import ishoalc
print(ishoalc.get_local_addr_port())

while not ishoalc.should_stop():
    ishoalc.sleep(30 * 1000)
