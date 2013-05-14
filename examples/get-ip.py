# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from __future__ import print_function

from twisted.internet.defer import Deferred
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet.task import react

from txsocksx.client import SOCKS5ClientEndpoint


class TerribleHTTPClient(Protocol):
    def connectionMade(self):
        self.transport.write(
            "GET /ip/ HTTP/1.1\r\nHost: api.externalip.net\r\n\r\n")
        self.data = []
        self.deferred = Deferred()

    def dataReceived(self, data):
        self.data.append(data)

    def connectionLost(self, reason):
        self.deferred.callback(''.join(self.data))

class TerribleHTTPClientFactory(ClientFactory):
    protocol = TerribleHTTPClient


def main(reactor):
    torEndpoint = TCP4ClientEndpoint(reactor, '127.0.0.1', 9050)
    proxiedEndpoint = SOCKS5ClientEndpoint('api.externalip.net', 80, torEndpoint)
    d = proxiedEndpoint.connect(TerribleHTTPClientFactory())
    d.addCallback(lambda proto: proto.deferred)
    d.addCallback(print)
    return d

react(main, [])
