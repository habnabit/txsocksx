# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from twisted.internet import defer
from twisted.test import proto_helpers


class FakeEndpoint(object):
    def __init__(self, failure=None):
        self.failure = failure

    def connect(self, fac):
        if self.failure:
            return defer.fail(self.failure)
        self.proto = fac.buildProtocol(None)
        transport = proto_helpers.StringTransport()
        self.aborted = []
        transport.abortConnection = lambda: self.aborted.append(True)
        self.tlsStarts = []
        transport.startTLS = lambda ctx: self.tlsStarts.append(ctx)
        self.proto.makeConnection(transport)
        self.transport = transport
        return defer.succeed(self.proto)
