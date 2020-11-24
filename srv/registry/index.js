const PORT = 5000;
// regex credit: https://stackoverflow.com/a/26445549/13673228
const IPV4_REGEXP = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/;

const io = require('socket.io')(PORT);

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
        socket.join('p2');

        const [switchIP] = args;
        if (typeof switchIP !== 'string')
          return;

        if (!IPV4_REGEXP.test(switchIP))
          return;

        if (!switchIP.startsWith('192.168.1.'))
          return;

        for (const [, [, switchIPOther]] of P2data.allSwitches) {
          if (switchIP == switchIPOther) {
            socket.emit('ip_collision');
            return;
          }
        }

        socket.on('disconnect', function() {
          socket.in('p2').emit('del_remote', socket.id, publicIP, switchIP);
          P2data.allSwitches.delete(socket.id);
        });

        socket.on('handshake', function(socketID, exchangeID, port) {
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
