#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# this file is meant to be used along with https://github.com/huangjimmy/PonyDebugger
# so that PonyDebugger supports USB debugging
#
#

__author__ = 'huang, jimmy (jimmy_huang@live.com,  http://huang.sh)'

import SocketServer
from optparse import OptionParser
import os

import socket, struct, select, sys

try:
    import plistlib
    haveplist = True
except:
    haveplist = False

class MuxError(Exception):
    pass

class MuxVersionError(MuxError):
    pass

class SafeStreamSocket:
    def __init__(self, address, family):
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.connect(address)
    def send(self, msg):
        totalsent = 0
        while totalsent < len(msg):
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise MuxError("socket connection broken")
            totalsent = totalsent + sent
    def recv(self, size):
        msg = ''
        while len(msg) < size:
            chunk = self.sock.recv(size-len(msg))
            if chunk == '':
                raise MuxError("socket connection broken")
            msg = msg + chunk
        return msg

class MuxDevice(object):
    def __init__(self, devid, usbprod, serial, location):
        self.devid = devid
        self.usbprod = usbprod
        self.serial = serial
        self.location = location
    def __str__(self):
        return "<MuxDevice: ID %d ProdID 0x%04x Serial '%s' Location 0x%x>"%(self.devid, self.usbprod, self.serial, self.location)

class BinaryProtocol(object):
    TYPE_RESULT = 1
    TYPE_CONNECT = 2
    TYPE_LISTEN = 3
    TYPE_DEVICE_ADD = 4
    TYPE_DEVICE_REMOVE = 5
    VERSION = 0
    def __init__(self, socket):
        self.socket = socket
        self.connected = False

    def _pack(self, req, payload):
        if req == self.TYPE_CONNECT:
            return struct.pack("IH", payload['DeviceID'], payload['PortNumber']) + "\x00\x00"
        elif req == self.TYPE_LISTEN:
            return ""
        else:
            raise ValueError("Invalid outgoing request type %d"%req)

    def _unpack(self, resp, payload):
        if resp == self.TYPE_RESULT:
            return {'Number':struct.unpack("I", payload)[0]}
        elif resp == self.TYPE_DEVICE_ADD:
            devid, usbpid, serial, pad, location = struct.unpack("IH256sHI", payload)
            serial = serial.split("\0")[0]
            return {'DeviceID': devid, 'Properties': {'LocationID': location, 'SerialNumber': serial, 'ProductID': usbpid}}
        elif resp == self.TYPE_DEVICE_REMOVE:
            devid = struct.unpack("I", payload)[0]
            return {'DeviceID': devid}
        else:
            raise MuxError("Invalid incoming request type %d"%req)

    def sendpacket(self, req, tag, payload={}):
        payload = self._pack(req, payload)
        if self.connected:
            raise MuxError("Mux is connected, cannot issue control packets")
        length = 16 + len(payload)
        data = struct.pack("IIII", length, self.VERSION, req, tag) + payload
        self.socket.send(data)
    def getpacket(self):
        if self.connected:
            raise MuxError("Mux is connected, cannot issue control packets")
        dlen = self.socket.recv(4)
        dlen = struct.unpack("I", dlen)[0]
        body = self.socket.recv(dlen - 4)
        version, resp, tag = struct.unpack("III",body[:0xc])
        if version != self.VERSION:
            raise MuxVersionError("Version mismatch: expected %d, got %d"%(self.VERSION,version))
        payload = self._unpack(resp, body[0xc:])
        return (resp, tag, payload)

class PlistProtocol(BinaryProtocol):
    TYPE_RESULT = "Result"
    TYPE_CONNECT = "Connect"
    TYPE_LISTEN = "Listen"
    TYPE_DEVICE_ADD = "Attached"
    TYPE_DEVICE_REMOVE = "Detached" #???
    TYPE_PLIST = 8
    VERSION = 1
    def __init__(self, socket):
        if not haveplist:
            raise Exception("You need the plistlib module")
        BinaryProtocol.__init__(self, socket)

    def _pack(self, req, payload):
        return payload

    def _unpack(self, resp, payload):
        return payload

    def sendpacket(self, req, tag, payload={}):
        payload['ClientVersionString'] = 'usbmux.py by marcan'
        if isinstance(req, int):
            req = [self.TYPE_CONNECT, self.TYPE_LISTEN][req-2]
        payload['MessageType'] = req
        payload['ProgName'] = 'tcprelay'
        BinaryProtocol.sendpacket(self, self.TYPE_PLIST, tag, plistlib.writePlistToString(payload))
    def getpacket(self):
        resp, tag, payload = BinaryProtocol.getpacket(self)
        if resp != self.TYPE_PLIST:
            raise MuxError("Received non-plist type %d"%resp)
        payload = plistlib.readPlistFromString(payload)
        return payload['MessageType'], tag, payload

class MuxConnection(object):
    def __init__(self, socketpath, protoclass):
        self.socketpath = socketpath
        if sys.platform in ['win32', 'cygwin']:
            family = socket.AF_INET
            address = ('127.0.0.1', 27015)
        else:
            family = socket.AF_UNIX
            address = self.socketpath
        self.socket = SafeStreamSocket(address, family)
        self.proto = protoclass(self.socket)
        self.pkttag = 1
        self.devices = []

    def _getreply(self):
        while True:
            resp, tag, data = self.proto.getpacket()
            if resp == self.proto.TYPE_RESULT:
                return tag, data
            else:
                raise MuxError("Invalid packet type received: %d"%resp)
    def _processpacket(self):
        resp, tag, data = self.proto.getpacket()
        if resp == self.proto.TYPE_DEVICE_ADD:
            self.devices.append(MuxDevice(data['DeviceID'], data['Properties']['ProductID'], data['Properties']['SerialNumber'], data['Properties']['LocationID']))
        elif resp == self.proto.TYPE_DEVICE_REMOVE:
            for dev in self.devices:
                if dev.devid == data['DeviceID']:
                    self.devices.remove(dev)
        elif resp == self.proto.TYPE_RESULT:
            raise MuxError("Unexpected result: %d"%resp)
        else:
            raise MuxError("Invalid packet type received: %d"%resp)
    def _exchange(self, req, payload={}):
        mytag = self.pkttag
        self.pkttag += 1
        self.proto.sendpacket(req, mytag, payload)
        recvtag, data = self._getreply()
        if recvtag != mytag:
            raise MuxError("Reply tag mismatch: expected %d, got %d"%(mytag, recvtag))
        return data['Number']

    def listen(self):
        ret = self._exchange(self.proto.TYPE_LISTEN)
        if ret != 0:
            raise MuxError("Listen failed: error %d"%ret)
    def process(self, timeout=None):
        if self.proto.connected:
            raise MuxError("Socket is connected, cannot process listener events")
        rlo, wlo, xlo = select.select([self.socket.sock], [], [self.socket.sock], timeout)
        if xlo:
            self.socket.sock.close()
            raise MuxError("Exception in listener socket")
        if rlo:
            self._processpacket()
    def connect(self, device, port):
        ret = self._exchange(self.proto.TYPE_CONNECT, {'DeviceID':device.devid, 'PortNumber':((port<<8) & 0xFF00) | (port>>8)})
        if ret != 0:
            raise MuxError("Connect failed: error %d"%ret)
        self.proto.connected = True
        return self.socket.sock
    def close(self):
        self.socket.sock.close()

class USBMux(object):
    def __init__(self, socketpath=None):
        if socketpath is None:
            if sys.platform == 'darwin':
                socketpath = "/var/run/usbmuxd"
            else:
                socketpath = "/var/run/usbmuxd"
        self.socketpath = socketpath
        self.listener = MuxConnection(socketpath, BinaryProtocol)
        try:
            self.listener.listen()
            self.version = 0
            self.protoclass = BinaryProtocol
        except MuxVersionError:
            self.listener = MuxConnection(socketpath, PlistProtocol)
            self.listener.listen()
            self.protoclass = PlistProtocol
            self.version = 1
        self.devices = self.listener.devices
    def process(self, timeout=None):
        self.listener.process(timeout)
    def connect(self, device, port):
        connector = MuxConnection(self.socketpath, self.protoclass)
        return connector.connect(device, port)

class SocketRelay(object):
    def __init__(self, a, b, maxbuf=65535):
        self.a = a
        self.b = b
        self.atob = ""
        self.btoa = ""
        self.maxbuf = maxbuf
    def handle(self):
        while True:
            rlist = []
            wlist = []
            xlist = [self.a, self.b]
            if self.atob:
                wlist.append(self.b)
            if self.btoa:
                wlist.append(self.a)
            if len(self.atob) < self.maxbuf:
                rlist.append(self.a)
            if len(self.btoa) < self.maxbuf:
                rlist.append(self.b)
            rlo, wlo, xlo = select.select(rlist, wlist, xlist)
            if xlo:
                return
            if self.a in wlo:
                n = self.a.send(self.btoa)
                self.btoa = self.btoa[n:]
            if self.b in wlo:
                n = self.b.send(self.atob)
                self.atob = self.atob[n:]
            if self.a in rlo:
                s = self.a.recv(self.maxbuf - len(self.atob))
                if not s:
                    return
                self.atob += s
            if self.b in rlo:
                s = self.b.recv(self.maxbuf - len(self.btoa))
                if not s:
                    return
                self.btoa += s
            #print "Relay iter: %8d atob, %8d btoa, lists: %r %r %r"%(len(self.atob), len(self.btoa), rlo, wlo, xlo)

class TCPRelay(SocketServer.BaseRequestHandler):
    def handle(self):
        print "Incoming connection to %d"%self.server.server_address[1]
        mux = USBMux(options.sockpath)
        print "Waiting for devices..."
        if not mux.devices:
            mux.process(1.0)
        if not mux.devices:
            print "No device found"
            self.request.close()
            return
        dev = mux.devices[0]
        print "Connecting to device %s"%str(dev)
        dsock = mux.connect(dev, self.server.rport)
        lsock = self.request
        print "Connection established, relaying data"
        try:
            fwd = SocketRelay(dsock, lsock, self.server.bufsize * 1024)
            fwd.handle()
        finally:
            dsock.close()
            lsock.close()
        print "Connection closed"

class TCPServer(SocketServer.TCPServer):
    allow_reuse_address = True

class ThreadedTCPServer(SocketServer.ThreadingMixIn, TCPServer):
    pass


if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [OPTIONS] RemotePort[:LocalPort] [RemotePort[:LocalPort]]...")
    parser.add_option("-t", "--threaded", dest='threaded', action='store_true', default=False, help="use threading to handle multiple connections at once")
    parser.add_option("-b", "--bufsize", dest='bufsize', action='store', metavar='KILOBYTES', type='int', default=128, help="specify buffer size for socket forwarding")
    parser.add_option("-s", "--socket", dest='sockpath', action='store', metavar='PATH', type='str', default=None, help="specify the path of the usbmuxd socket")

    global options
    opts, args = parser.parse_args()
    options = opts
    HOST = "127.0.0.1"
    serverclass = ThreadedTCPServer

    ports = []

    if len(args) == 0:
        parser.print_help()
        sys.exit(1)

    for arg in args:
        try:
            if ':' in arg:
                rport, lport = arg.split(":")
                rport = int(rport)
                lport = int(lport)
                ports.append((rport, lport))
            else:
                ports.append((int(arg), int(arg)))
        except:
            parser.print_help()
            sys.exit(1)

    servers = []

    for rport, lport in ports:
        print "Forwarding local port %d to remote port %d"%(lport, rport)
        server = serverclass((HOST, lport), TCPRelay)
        server.rport = rport
        server.bufsize = options.bufsize
        servers.append(server)

    alive = True

    if sys.platform == 'darwin':
        command = "open -a Google\\ Chrome http://127.0.0.1:56439/chrome.html"
    else:
        command = "chrome.exe http://127.0.0.1:56439/chrome.html"

    os.system(command)

    while alive:
        try:
            rl, wl, xl = select.select(servers, [], [])
            for server in rl:
                server.handle_request()
        except:
            alive = False
