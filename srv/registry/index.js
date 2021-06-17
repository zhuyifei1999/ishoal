// regex credit: https://stackoverflow.com/a/26445549/13673228
const IPV4_REGEXP = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/;

const struct = require('struct');
const io = require('socket.io')(5000, {allowEIO3: true});
const relayctl = require('dgram').createSocket('udp4');
const util = require('util');

const RELAYCTL_CMD_JTC_CLEAR = 1;
const RELAYCTL_CMD_JTC_ADD = 2;
const RELAYCTL_CMD_JTC_DEL = 3;

const RELAYCTL_CMD_CTJ_DUMP = 1;
const RELAYCTL_CMD_CTJ_ADDACK = 2;

relayctl.on('error', (err) => {
  if (util.getSystemErrorName(err.errno) === 'ECONNREFUSED')
    return;
  console.log(`relayctl error:\n${err.stack}`);
});

Promise.all([
  new Promise((resolve, reject) => {
    relayctl.on('connect', () => {
      resolve();
    });
  }),
  new Promise((resolve, reject) => {
    relayctl.on('listening', () => {
      resolve();
    });
  }),
]).then(() => {
  const stru = struct().word8('cmd');

  stru.allocate();
  stru.fields.cmd = RELAYCTL_CMD_JTC_CLEAR;

  relayctl.send(stru.buffer());
});

relayctl.bind(5000);
relayctl.connect(5001);

const relayData = {
  allRelays: new Map(),
  socketIndex: new Map(),
  addRpcId: new Map(),
};

const relayAddRpcIdGen = (function() {
  let curId = 0;
  return function() {
    curId = (curId + 1) % 65536;
    return curId;
  };
}());

const doRelayDelInternal = function(key, obj) {
  relayData.allRelays.delete(key);

  const thisSocketIndex = relayData.socketIndex.get(obj.thisSocketID);
  thisSocketIndex.delete(key);
  if (!thisSocketIndex.size)
    relayData.socketIndex.delete(obj.thisSocketID);

  const thatSocketIndex = relayData.socketIndex.get(obj.thatSocketID);
  thatSocketIndex.delete(key);
  if (!thatSocketIndex.size)
    relayData.socketIndex.delete(obj.thatSocketID);
};

const doRelayDelRPC = function(thisRelayPort, thatRelayPort) {
  const stru = struct()
      .word8('cmd')
      .word16Ube('thisRelayPort')
      .word16Ube('thatRelayPort');

  stru.allocate();
  stru.fields.cmd = RELAYCTL_CMD_JTC_DEL;
  stru.fields.thisRelayPort = thisRelayPort;
  stru.fields.thatRelayPort = thatRelayPort;

  relayctl.send(stru.buffer());
};

const doRelayDelFromSocket = function(socketID) {
  const index = relayData.socketIndex.get(socketID);
  if (!index)
    return;

  for (const key of Array.from(index)) {
    const obj = relayData.allRelays.get(key);
    obj.rpcReject(new Error('Disconnect'));
    doRelayDelInternal(key, obj);

    if (obj.thisRelayPort || obj.thatRelayPort)
      doRelayDelRPC(obj.thisRelayPort, obj.thatRelayPort);
  }
};

const doRelayAdd = function(key, obj) {
  if (obj.thisIP && obj.thatIP && obj.thisPort && obj.thatPort &&
      !obj.rpcSent) {
    let rpcId;
    for (let i = 0; i < 65536; i++) {
      rpcId = relayAddRpcIdGen();

      if (!relayData.addRpcId.has(rpcId))
        break;

      const oldkey = relayData.addRpcId.get(rpcId);
      const oldobj = relayData.allRelays.get(oldkey);
      if (!oldobj)
        throw new Error('Assertion failed');

      if (Date.now() - oldobj.rpcTime > 10000) { // Timeout 10 seconds
        oldobj.rpcReject(new Error('RPC timeout'));
        doRelayDelInternal(oldkey, oldobj);
        relayData.addRpcId.delete(rpcId);
        break;
      }
    }
    if (relayData.addRpcId.has(rpcId))
      throw new Error(`RPC ID exhaustion`);

    relayData.addRpcId.set(rpcId, key);
    obj.rpcTime = Date.now();

    const inetAddr = function(ip) {
      let [, num1, num2, num3, num4] = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
      [num1, num2, num3, num4] =
        [parseInt(num1), parseInt(num2), parseInt(num3), parseInt(num4)];

      // https://stackoverflow.com/a/6798829, `>>> 0` to make unsigned
      return ((num1 << 24) | (num2 << 16) | (num3 << 8) | num4) >>> 0;
    };

    const stru = struct()
        .word8('cmd')
        .word16Ube('rpcId')
        .word32Ube('thisIP')
        .word16Ube('thisPort')
        .word16Ube('thisRelayPort')
        .word32Ube('thatIP')
        .word16Ube('thatPort')
        .word16Ube('thatRelayPort');

    stru.allocate();
    stru.fields.cmd = RELAYCTL_CMD_JTC_ADD;
    stru.fields.rpcId = rpcId;
    stru.fields.thisIP = inetAddr(obj.thisIP);
    stru.fields.thisPort = obj.thisPort;
    stru.fields.thisRelayPort = obj.thisRelayPort;
    stru.fields.thatIP = inetAddr(obj.thatIP);
    stru.fields.thatPort = obj.thatPort;
    stru.fields.thatRelayPort = obj.thatRelayPort;

    relayctl.send(stru.buffer());
    obj.rpcSent = true;
  }
};

relayctl.on('message', (msg, rinfo) => {
  let stru = struct().word8('cmd');

  stru._setBuff(msg);
  switch (stru.fields.cmd) {
    case RELAYCTL_CMD_CTJ_DUMP:
      for (const [key, obj] of relayData.allRelays) {
        obj.rpcSent = false;
        doRelayAdd(key, obj);
      }
      break;
    case RELAYCTL_CMD_CTJ_ADDACK:
      stru = struct()
          .word8('cmd')
          .word16Ube('rpcId')
          .word16Ube('thisRelayPort')
          .word16Ube('thatRelayPort');
      stru._setBuff(msg);

      const key = relayData.addRpcId.get(stru.fields.rpcId);
      relayData.addRpcId.delete(stru.fields.rpcId);
      const obj = relayData.allRelays.get(key);

      // This can happen if it disconnects before RPC is done
      if (!obj) {
        doRelayDelRPC(stru.fields.thisRelayPort, stru.fields.thatRelayPort);
        break;
      }

      obj.thisRelayPort = stru.fields.thisRelayPort;
      obj.thatRelayPort = stru.fields.thatRelayPort;

      obj.rpcResolve();
      break;
  }
});

const doRelay = function(thisSocketID, thatSocketID, thisIP, thisPort) {
  if (thisSocketID === thatSocketID)
    throw new Error('self-relay');

  let thatIP = undefined;
  let thatPort = undefined;
  let isThis = true;
  if (thisSocketID > thatSocketID) {
    [thisSocketID, thatSocketID] = [thatSocketID, thisSocketID];
    [thisIP, thatIP] = [thatIP, thisIP];
    [thisPort, thatPort] = [thatPort, thisPort];
    isThis = false;
  }

  // Oh JS, why is your map identity-keyed?
  const key = JSON.stringify([thisSocketID, thatSocketID]);
  if (!relayData.allRelays.has(key)) {
    const newobj = {
      thisSocketID: thisSocketID,
      thatSocketID: thatSocketID,
      thisIP: thisIP,
      thatIP: thatIP,
      thisPort: thisPort,
      thatPort: thatPort,
    };

    newobj.rpcPromise = new Promise((resolve, reject) => {
      newobj.rpcResolve = resolve;
      newobj.rpcReject = reject;
    });
    relayData.allRelays.set(key, newobj);

    if (!relayData.socketIndex.has(thisSocketID))
      relayData.socketIndex.set(thisSocketID, new Set());
    relayData.socketIndex.get(thisSocketID).add(key);

    if (!relayData.socketIndex.has(thatSocketID))
      relayData.socketIndex.set(thatSocketID, new Set());
    relayData.socketIndex.get(thatSocketID).add(key);
  }

  const obj = relayData.allRelays.get(key);
  if (obj.thisSocketID !== thisSocketID || obj.thatSocketID !== thatSocketID)
    throw new Error('bad key?!');

  const localdata = {
    thisIP: thisIP,
    thatIP: thatIP,
    thisPort: thisPort,
    thatPort: thatPort,
    thisRelayPort: 0,
    thatRelayPort: 0,
  };

  for (const item of Object.keys(localdata)) {
    if (localdata[item]) {
      if (obj[item]) {
        if (localdata[item] !== obj[item])
          throw new Error(`unmatching ${item}`);
      } else
        obj[item] = localdata[item];
    }
  }

  doRelayAdd(key, obj);

  return obj.rpcPromise.then(() => {
    return isThis ? obj.thisRelayPort : obj.thatRelayPort;
  });
};

const P2data = {
  allSwitches: new Map(),
};

const P1data = {
  allSwitches: new Map(),
};

io.on('connection', function(socket) {
  socket.emit('connected');

  console.log('[' + new Date() + '] Connected: ' + socket.id);

  socket.on('disconnect', function() {
    console.log('[' + new Date() + '] Disconnected: ' + socket.id);
  });

  let protocol = undefined;
  let publicIP = socket.request.headers['x-forwarded-for'];

  // for some reason, sigh...
  if (publicIP.startsWith('::ffff:'))
    publicIP = publicIP.substring('::ffff:'.length);

  if (!IPV4_REGEXP.test(publicIP))
    throw new Error(`Unexpected IP ${publicIP}`);

  socket.on('protocol', function(major, ...args) {
    if (protocol !== undefined)
      return;

    protocol = major;

    /* ====== BEGIN PROTOCOL 2 ====== */
    if (protocol === 2) {
      (function() {
        const [switchIP] = args;
        if (typeof switchIP !== 'string')
          return;

        if (!IPV4_REGEXP.test(switchIP))
          return;

        if (!switchIP.startsWith('192.168.1.'))
          return;

        for (const [, [, switchIPOther]] of P2data.allSwitches) {
          if (switchIP === switchIPOther) {
            socket.emit('ip_collision');
            return;
          }
        }

        socket.join('p2');

        socket.on('disconnect', function() {
          socket.in('p2').emit('del_remote', socket.id, publicIP, switchIP);
          P2data.allSwitches.delete(socket.id);

          doRelayDelFromSocket(socket.id);
        });

        socket.on('handshake', function(socketID, exchangeID, port, useRelay) {
          if (useRelay) {
            (async function() {
              let relayPort;
              try {
                relayPort = await doRelay(
                    socket.id, socketID, publicIP, port);
              } catch (e) {
                console.log(`doRelay error:\n${e.stack}`);
              }
              socket.emit('handshake', socketID, exchangeID, relayPort);
            }());
          } else
            io.to(socketID).emit('handshake', socket.id, exchangeID, port);
        });

        socket.in('p2').emit('add_remote', socket.id, publicIP, switchIP);

        for (const [socketID, [publicIP, switchIP]] of P2data.allSwitches)
          socket.emit('add_remote', socketID, publicIP, switchIP);

        P2data.allSwitches.set(socket.id, [publicIP, switchIP]);
      })();
    }
  });

  /* ====== BEGIN PROTOCOL 1 ====== */
  (function() {
    let localIPOld = undefined;

    let initialized = false;
    socket.on('pulse', function(switchIP, vpnPort) {
      if (protocol === undefined) {
        protocol = 1;
        socket.join('p1');
      }
      if (protocol !== 1)
        return;

      if (typeof switchIP !== 'string' || typeof vpnPort !== 'number')
        return;

      if (!IPV4_REGEXP.test(switchIP))
        return;

      // No shenanigans
      if (!switchIP.startsWith('192.168.1.'))
        return;

      if (!Number.isInteger(vpnPort) ||
          vpnPort <= 0 ||
          vpnPort >= 65536)
        return;

      // 20 mins expiry
      const lastPulseAcceptable = Date.now() - 20 * 60 * 1000;

      if (!initialized) {
        initialized = true;

        for (const [localIP, [remoteIP, remotePort, lastPulse]]
          of P1data.allSwitches
        ) {
          if (lastPulse > lastPulseAcceptable)
            socket.emit('set_remote_addr', localIP, remoteIP, remotePort);
          else {
            P1data.allSwitches.delete(localIP);
            socket.to('p1').emit('delete_remote_addr', localIP);
          }
        }
      } else if (localIPOld && localIPOld !== switchIP) {
        if (P1data.allSwitches.has(localIPOld)) {
          P1data.allSwitches.delete(localIPOld);
          socket.to('p1').emit('delete_remote_addr', localIPOld);
        }
      }

      localIPOld = switchIP;

      let shouldBroadcast = true;
      if (P1data.allSwitches.has(switchIP)) {
        const [publicIPOld, vpnPortOld] = P1data.allSwitches.get(switchIP);
        if (publicIPOld === publicIP && vpnPortOld === vpnPort)
          shouldBroadcast = false;
      }

      P1data.allSwitches.set(switchIP, [publicIP, vpnPort, Date.now()]);
      if (shouldBroadcast)
        io.in('p1').emit('set_remote_addr', switchIP, publicIP, vpnPort);
    });
  })();
});
