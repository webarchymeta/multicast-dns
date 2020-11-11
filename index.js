'use strict'

const
    packet = require('dns-packet'),
    dgram = require('dgram'),
    events = require('events'),
    os = require('os');

module.exports = function (opts) {
    opts = opts || {};
    const that = new events.EventEmitter();
    const port = typeof opts.port === 'number' ? opts.port : 5353;
    const use_group_ip = opts.use_group_ip;
    const type = opts.type || 'udp4';
    const group_ip = opts.use_group_ip || opts.group_ip || (type === 'udp4' ? '224.0.0.251' : 'FF02::FB');
    const client_only = !!opts.client_only;
    const subnets = opts.subnets && opts.subnets.length > 0 ? opts.subnets : undefined;
    const sendSockets = [];
    const interfaces = [];

    that.type = type;

    let destroyed = false;

    if (!opts.interface && !opts.interfaces) {
        const ifaces = os.networkInterfaces();
        const ip_family = type === 'udp4' ? 'ipv4' : 'ipv6';
        Object.keys(ifaces).forEach(key => {
            ifaces[key].forEach(ip => {
                if (!ip.internal && ip_family.toLowerCase() === ip.family.toLowerCase()) {
                    if (!subnets || subnets.find(sn => ip.address.indexOf(sn.prefix) === 0)) {
                        interfaces.push(ip.address);
                    }
                }
            });
        });
    } else if (opts.interface) {
        interfaces.push(opts.interface);
    } else {
        opts.interfaces.forEach(iip => {
            interfaces.push(iip);
        });
    }

    const domain_match = (addr1, addr2) => {
        if (type === 'udp4') {
            const an1 = addr1.split('.');
            const an2 = addr2.split('.');
            if (!subnets) {
                let cnt = 0;
                for (let i = 0; i < an1.length; i++) {
                    if (an1[i] === an2[i]) {
                        cnt++;
                    } else {
                        break;
                    }
                }
                return cnt > 0;
            } else {
                const cnts = subnets.map((sn, idx) => {
                    let cnt = 0;
                    const dns = sn.prefix.split('.').filter(n => !!n);
                    for (let i = 0; i < dns.length; i++) {
                        if (dns[i] === an1[i] && an1[i] === an2[i]) {
                            cnt++;
                        } else {
                            break;
                        }
                    }
                    return {
                        match: cnt === dns.length,
                        i: idx,
                        cnt: cnt
                    };
                }).filter(c => !!c.cnt).sort((a, b) => a.cnt > b.cnt ? -1 : a.cnt === b.cnt ? 0 : 1);
                return cnts.length > 0 && cnts[0].match;
            }
        } else {
            const an1 = addr1.split(':');
            const an2 = addr2.split(':');
            if (!subnets) {
                let cnt = 0;
                for (let i = 0; i < an1.length; i++) {
                    if (an1[i] === an2[i]) {
                        cnt++;
                    } else {
                        break;
                    }
                }
                return cnt > 0;
            } else {
                const cnts = subnets.map((sn, idx) => {
                    let cnt = 0;
                    const dns = sn.prefix.split(':').filter(n => !!n);
                    for (let i = 0; i < dns.length; i++) {
                        if (dns[i] === an1[i] && an1[i] === an2[i]) {
                            cnt++;
                        } else {
                            break;
                        }
                    }
                    return {
                        match: cnt === dns.length,
                        i: idx,
                        cnt: cnt
                    };
                }).filter(c => !!c.cnt).sort((a, b) => a.cnt > b.cnt ? -1 : a.cnt === b.cnt ? 0 : 1);
                return cnts.length > 0 && cnts[0].match;
            }
        }
    };

    interfaces.forEach(iip => {
        const s = dgram.createSocket({
            type: type,
            reuseAddr: opts.reuseAddr !== false,
            toString: () => type
        });
        s.on('listening', function () {
            try {
                this.addMembership(group_ip, iip);
            } catch (err) {
                that.emit('error', err);
            }
            this.setMulticastTTL(opts.ttl || 5);
            this.setMulticastLoopback(!!opts.loopback);
            that.emit('ready');
        }.bind(s));
        s.on('message', (message, rinfo) => {
            try {
                message = packet.decode(message);
            } catch (err) {
                that.emit('warning', err);
                return;
            }
            if (message.type === 'response') {
                that.emit('response', message, rinfo);
            }
        });
        s.on('error', err => {
            if (err.code === 'EACCES' || err.code === 'EADDRINUSE') {
                that.emit('error', err);
            } else {
                that.emit('warning', err);
            }
        });
        s.bind(0, iip, () => {
            const adr = s.address();
            s.local_ip = adr.address;
            s.local_port = adr.port;
        });
        sendSockets.push(s);
    });

    const socket = !client_only ? dgram.createSocket({
        type: type,
        reuseAddr: opts.reuseAddr !== false,
        toString: () => type
    }) : undefined;

    if (!client_only) {

        socket.on('error', err => {
            if (err.code === 'EACCES' || err.code === 'EADDRINUSE')
                that.emit('error', err);
            else
                that.emit('warning', err);
        });

        socket.on('message', (message, rinfo) => {
            try {
                message = packet.decode(message);
            } catch (err) {
                that.emit('warning', err);
                return;
            }

            that.emit('packet', message, rinfo);
            if (message.type === 'query') {
                that.emit('query', message, rinfo);
            } else if (message.type === 'response') {
                that.emit('response', message, rinfo);
            }
        });

        socket.on('listening', () => {
            try {
                interfaces.forEach(fi => {
                    socket.addMembership(group_ip, fi);
                });
            } catch (err) {
                that.emit('warning', `add membership: ${fi} to group ${group_ip} failed`);
                that.emit('error', err);
            }
            socket.setMulticastTTL(opts.ttl || 5);
            socket.setMulticastLoopback(!!opts.loopback);
        });

        if (os.platform() === 'win32' || !use_group_ip || !opts.multicast) {
            socket.bind(port || 0, () => {
                that.emit('ready');
            });
        } else {
            socket.bind(port || 0, group_ip, () => {
                that.emit('ready');
            });
        }
    }

    that.send = (value, rinfo, cb) => {
        if (typeof rinfo === 'function') {
            return that.send(value, null, rinfo);
        }
        if (destroyed) {
            return cb && cb(new Error('sockets already closed'));
        }
        const message = packet.encode(value);
        sendSockets.forEach(s => {
            if (!rinfo || domain_match(rinfo.address, s.local_ip)) {
                s.send(message, 0, message.length, rinfo ? rinfo.port : port || 5353, rinfo ? rinfo.address : group_ip, err => {
                    if (err) {
                        that.emit('error', err);
                    }
                    cb && cb(err);
                });
            }
        });
    };

    that.response = that.respond = (res, rinfo, cb) => {
        if (Array.isArray(res)) {
            res = {
                answers: res
            };
        }
        res.type = 'response';
        that.send(res, rinfo, cb);
    };

    that.query = (q, type, rinfo, cb) => {
        if (typeof type === 'function') {
            return that.query(q, null, null, type);
        } else if (typeof type === 'object' && type && type.port) {
            return that.query(q, null, type, cb);
        }
        if (typeof rinfo === 'function') {
            return that.query(q, type, null, rinfo);
        }
        if (typeof q === 'string') {
            q = {
                type: 'query',
                questions: [{
                    name: q,
                    type: type || 'ANY'
                }]
            };
        } else if (Array.isArray(q)) {
            q = {
                type: 'query',
                questions: q
            };
        } else {
            if (q.type !== 'query') {
                q.type = 'query';
            }
        }
        that.send(q, rinfo, cb);
    };

    that.destroy = cb => {
        if (destroyed) {
            return cb && process.nextTick(cb);
        }
        destroyed = true;
        if (!client_only) {
            interfaces.forEach(iip => {
                try {
                    socket.dropMembership(group_ip, iip);
                } catch (ex) {

                }
            });
            if (cb) {
                socket.once('close', cb);
            }
            socket.close();
        }
        sendSockets.forEach(s => {
            interfaces.forEach(iip => {
                try {
                    s.dropMembership(group_ip, iip);
                } catch (ex) {

                }
            });
            if (cb) {
                s.once('close', cb);
            }
            s.close();
        });
        that.emit('shutdown');
    };

    return that;
};